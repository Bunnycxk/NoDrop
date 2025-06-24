#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "events.h"
#include "infiniband/verbs.h"
#include "ioctl.h"
#include "pkeys.h"
#include "rdma.h"
#include "tsc.h"

#ifndef PATH_FMT
#define PATH_FMT CONFIG_STORE_PATH "/%u-%ld.buf"
#endif

static nod_rdma_ctrl_block_t rdma_cb;

static const char *__print_format[PT_UINT64 + 1][PF_OCT + 1] = {
    [PT_NONE] = {"", "", "", "", ""}, /*empty*/
    [PT_INT8] = {"", "%" PRId8, "0x%" PRIx8, "%010" PRId8,
                 "0%" PRIo8}, /*PT_INT8*/
    [PT_INT16] = {"", "%" PRId16, "0x%" PRIx16, "%010" PRId16,
                  "0%" PRIo16}, /*PT_INT16*/
    [PT_INT32] = {"", "%" PRId32, "0x%" PRIx32, "%010" PRId32,
                  "0%" PRIo32}, /*PT_INT32*/
    [PT_INT64] = {"", "%" PRId64, "0x%" PRIx64, "%010" PRId64,
                  "0%" PRIo64}, /*PT_INT64*/
    [PT_UINT8] = {"", "%" PRIu8, "0x%" PRIx8, "%010" PRId8,
                  "0%" PRIo8}, /*PT_UINT8*/
    [PT_UINT16] = {"", "%" PRIu16, "0x%" PRIx16, "%010" PRIu16,
                   "0%" PRIo16}, /*PT_UINT16*/
    [PT_UINT32] = {"", "%" PRIu32, "0x%" PRIx32, "%010" PRIu32,
                   "0%" PRIo32}, /*PT_UINT32*/
    [PT_UINT64] = {"", "%" PRIu64, "0x%" PRIx64, "%010" PRIu64,
                   "0%" PRIo64} /*PT_UINT64*/
};

static _unused int _parse(FILE *out, struct nod_event_hdr *hdr, char *buffer,
                          void *__data) {
  size_t i;
  const struct nod_event_info *info;
  const struct nod_param_info *param;
  uint16_t *args;
  char *data;

  if (hdr->type < 0 || hdr->type >= NODE_EVENT_MAX)
    return -1;

  info = &g_event_info[hdr->type];
  args = (uint16_t *)buffer;
  data = (char *)(args + info->nparams);

  fprintf(out, "%lu %u (%u): %s(", hdr->ts, hdr->tid, hdr->cpuid, info->name);

  for (i = 0; i < info->nparams; ++i) {
    param = &info->params[i];
    if (i > 0)
      fprintf(out, ", ");
    fprintf(out, "%s=", param->name);
    switch (param->type) {
    case PT_CHARBUF:
    case PT_FSPATH:
    case PT_FSRELPATH:
    case PT_BYTEBUF:
      fwrite(data, args[i], 1, out);
      break;

    case PT_FLAGS8:
    case PT_UINT8:
    case PT_SIGTYPE:
      fprintf(out, __print_format[PT_UINT8][param->fmt], *(uint8_t *)data);
      break;

    case PT_FLAGS16:
    case PT_UINT16:
    case PT_SYSCALLID:
      fprintf(out, __print_format[PT_UINT16][param->fmt], *(uint16_t *)data);
      break;

    case PT_FLAGS32:
    case PT_UINT32:
    case PT_MODE:
    case PT_UID:
    case PT_GID:
    case PT_SIGSET:
      fprintf(out, __print_format[PT_UINT32][param->fmt], *(uint32_t *)data);
      break;

    case PT_RELTIME:
    case PT_ABSTIME:
    case PT_UINT64:
      fprintf(out, __print_format[PT_UINT64][param->fmt], *(uint64_t *)data);
      break;

    case PT_INT8:
      fprintf(out, __print_format[PT_INT8][param->fmt], *(int8_t *)data);
      break;

    case PT_INT16:
      fprintf(out, __print_format[PT_INT16][param->fmt], *(int16_t *)data);
      break;

    case PT_INT32:
      fprintf(out, __print_format[PT_INT32][param->fmt], *(int32_t *)data);
      break;

    case PT_INT64:
    case PT_ERRNO:
    case PT_FD:
    case PT_PID:
      fprintf(out, __print_format[PT_INT64][param->fmt], *(int64_t *)data);
      break;

    default:
      fprintf(out, "<unknown>");
      break;
    }

    // move to the next argument
    data += args[i];
  }
  fprintf(out, ")\n");
  return 0;
}

static void nod_rdma_protocal_init(nod_rdma_protocal_t *protocal) {
  protocal->psn = 0;
  protocal->exited = 0;
}

static int nod_rdma_send(char *buffer, int buffer_size) {
  int rc;
  rc = nod_rdma_post_send(&rdma_cb, IBV_WR_RDMA_WRITE, buffer, buffer_size);
  if (rc) {
    perror("Failed to post RDMA write");
    return rc;
  }
  rc = nod_rdma_poll(&rdma_cb);
  if (rc) {
    perror("Failed to poll RDMA completion");
    return rc;
  }
  return 0;
}

int nod_monitor_init(int argc, char *argv[], char *env[],
                     struct nod_stack_info *p) {
  int rc;
  int ioctl_fd;
  nod_buffer_info_t *buffer_info;
  uint64_t rdma_buffer_size = sizeof(nod_buffer_info_t) + p->buffer_size;

  ioctl_fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (ioctl_fd < 0) {
    perror("Open " NOD_IOCTL_PATH " failed");
    rc = -EIO;
    goto out;
  }

  buffer_info = mmap(NULL, rdma_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                     ioctl_fd, 0);
  if (buffer_info == MAP_FAILED) {
    perror("mmap buffer info failed");
    rc = -ENOMEM;
    goto out_ioctl;
  }

#ifdef NOD_PKEY_SUPPORT
  if (p->pkey != -1) {
    // Ensure the buffer_info is protected by the pkey
    rc = pkey_mprotect(buffer_info, buffer_size, PROT_READ | PROT_WRITE,
                       p->pkey);
    if (rc) {
      perror("pkey_mprotect for buffer info failed");
      rc = -ENOMEM;
      goto out_unmap;
    }
  }
#endif // NOD_PKEY_SUPPORT

  rc = nod_rdma_ctrl_block_init(&rdma_cb, NOD_RDMA_SERVER_NAME,
                                NOD_RDMA_SERVER_PORT, NOD_RDMA_DEVICE_NAME,
                                (char *)buffer_info, rdma_buffer_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto out_unmap;
  }

  rc = nod_qp_connect(&rdma_cb, NOD_RDMA_IB_PORT, NOD_RDMA_IB_GID_INDEX);
  if (rc) {
    perror("Failed to connect QP");
    goto out_cb;
  }

  p->ioctl_fd = ioctl_fd;
  p->buffer_info = buffer_info;
  nod_rdma_protocal_init(&buffer_info->rdma_protocal);
  return 0;

out_cb:
  nod_rdma_ctrl_block_fini(&rdma_cb);
out_unmap:
  munmap(buffer_info, rdma_buffer_size);
out_ioctl:
  close(ioctl_fd);
out:
  return rc;
}

void nod_monitor_exit(long code, struct nod_stack_info *p) {
  uint64_t rdma_buffer_size = sizeof(nod_buffer_info_t) + p->buffer_size;
  nod_buffer_info_t *buffer_info = p->buffer_info;

  buffer_info->rdma_protocal.exited = 1;
  if (nod_rdma_send((char *)buffer_info, sizeof(nod_buffer_info_t))) {
    perror("Fail to send RDMA write for exit");
  }
  printf("psn: %lu\n", buffer_info->rdma_protocal.psn);

  nod_rdma_ctrl_block_fini(&rdma_cb);
  munmap(p->buffer_info, rdma_buffer_size);
  close(p->ioctl_fd);
}

int nod_monitor_main(int argc, char *argv[], char *env[],
                     struct nod_stack_info *p) {
  int rc;
  // uint64_t ts;
  uint64_t rdma_buffer_size = sizeof(nod_buffer_info_t) + p->buffer_size;
  nod_buffer_info_t *buffer_info = p->buffer_info;

  // ts = -nod_rdtsc();
  buffer_info->rdma_protocal.psn++;
  rc = nod_rdma_send((char *)buffer_info, rdma_buffer_size);
  if (rc) {
    perror("Failed to send RDMA write");
    goto out;
  }
  // ts += nod_rdtsc();
  // printf("RDMA write ts:%lu\n", ts);

  rc = 0;
out:
  buffer_info->nevents = buffer_info->tail = 0;
  return rc;
}
