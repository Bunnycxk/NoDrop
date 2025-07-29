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

#define NOD_RDMA_SUPPORT
// #undef NOD_RDMA_SUPPORT

#define NOD_RDMA_INIT_PSN   0
static nod_rdma_ctrl_block_t rdma_cb;
static uint64_t residence_time_sum, residence_time_cnt;
static uint64_t total_nevents, total_nevents_cnt;

#if 0
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

  fprintf(out, "%lu %u (%u): %s(", hdr->tsc, hdr->tid, hdr->cpuid, info->name);

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
#endif

static void nod_rdma_protocal_init(nod_rdma_protocal_t *protocal) {
  protocal->psn = NOD_RDMA_INIT_PSN;
  protocal->exited = 0;
  protocal->available = 1;
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
      rc = -EACCESS;
      goto out_ioctl;
    }
  }
#endif // NOD_PKEY_SUPPORT

  p->ioctl_fd = ioctl_fd;
  p->buffer_info = buffer_info;
  residence_time_cnt = residence_time_sum = 0;
  total_nevents = total_nevents_cnt = 0;

#if defined(NOD_RDMA_SUPPORT)
  nod_rdma_config_t rdma_config = {
    .ib_gid_index = NOD_RDMA_IB_GID_INDEX,
    .ib_port = NOD_RDMA_IB_PORT,
    .init_psn = NOD_RDMA_INIT_PSN, // Initial PSN can be set to 0
    .buffer_size = p->buffer_size,
    .pid = (unsigned int)syscall(SYS_gettid),
    .flags = 0, // NOD_RDMA_FLAG_REPORT_LOST,
  };
  strncpy(rdma_config.device_name, NOD_RDMA_DEVICE_NAME,
          sizeof(rdma_config.device_name) - 1);

  int sockfd = nod_rdma_sock_connect(NOD_RDMA_SERVER_NAME, NOD_RDMA_SERVER_PORT);
  if (sockfd < 0) {
    perror("Failed to connect to RDMA server");
    rc = sockfd;
    goto err;
  }

  rc = nod_write_to_socket(sockfd, (void *)&rdma_config, sizeof(rdma_config));
  if (rc != sizeof(rdma_config)) {
    perror("Failed to send RDMA config to server");
    rc = rc >= 0 ? rc : -EIO;
    goto err_socket;
  }

  rc = nod_rdma_ctrl_block_init(&rdma_cb, NOD_RDMA_DEVICE_NAME,
                                (char *)buffer_info, rdma_buffer_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto err_socket;
  }

  rc = nod_qp_connect(&rdma_cb, NOD_RDMA_IB_PORT, NOD_RDMA_IB_GID_INDEX, sockfd);
  if (rc) {
    perror("Failed to connect QP");
    goto err_cb;
  }

  close(sockfd);
  nod_rdma_protocal_init(&buffer_info->rdma_protocal);
#endif // NOD_RDMA_SUPPORT
  return 0;

#if defined(NOD_RDMA_SUPPORT)
err_cb:
  nod_rdma_ctrl_block_fini(&rdma_cb);
err_socket:
  close(sockfd);
err:
  buffer_info->rdma_protocal.available = 0; // not available
  return 0;
#endif // NOD_RDMA_SUPPORT

out_ioctl:
  close(ioctl_fd);
out:
  return rc;
}

void nod_monitor_exit(long code, struct nod_stack_info *p) {
  uint64_t rdma_buffer_size = sizeof(nod_buffer_info_t) + p->buffer_size;
  nod_buffer_info_t *buffer_info = p->buffer_info;

#ifdef NOD_RDMA_SUPPORT
  if (likely(buffer_info->rdma_protocal.available)) {
    buffer_info->rdma_protocal.exited = 1;
    if (nod_rdma_send((char *)buffer_info, sizeof(nod_buffer_info_t))) {
      perror("Fail to send RDMA write for exit");
    }
    nod_rdma_ctrl_block_fini(&rdma_cb);
  }
#endif // NOD_RDMA_SUPPORT

  munmap(buffer_info, rdma_buffer_size);
  close(p->ioctl_fd);

  printf("NoTamper: avg nevents %lu (%lu) avg residence time %lu ticks (%lu)\n",
         total_nevents / total_nevents_cnt, total_nevents_cnt,
         residence_time_cnt ? (residence_time_sum / residence_time_cnt) : 0,
         residence_time_cnt);
}

int nod_monitor_main(int argc, char *argv[], char *env[],
                     struct nod_stack_info *p) {
  int rc;
  nod_buffer_info_t *buffer_info = p->buffer_info;
  struct nod_event_hdr *first_evt = (struct nod_event_hdr *)buffer_info->buffer;

#ifdef NOD_RDMA_SUPPORT
  uint64_t rdma_buffer_size = sizeof(nod_buffer_info_t) + buffer_info->tail;
  if (likely(buffer_info->rdma_protocal.available && rdma_buffer_size > sizeof(nod_buffer_info_t))) {
    // uint64_t ts = -nod_rdtsc();
    buffer_info->rdma_protocal.psn++;
    rc = nod_rdma_send((char *)buffer_info, rdma_buffer_size);
    if (rc) {
      perror("Failed to send RDMA write");
      goto out;
    }
    // ts += nod_rdtsc();
    // printf("RDMA write ts:%lu\n", ts);
  }
#endif // NOD_RDMA_SUPPORT

  residence_time_sum += nod_rdtsc() - first_evt->tsc;
  residence_time_cnt++;
  rc = 0;

#ifdef NOD_RDMA_SUPPORT
out:
#endif // NOD_RDMA_SUPPORT
  total_nevents += buffer_info->nevents;
  total_nevents_cnt++;
  buffer_info->nevents = buffer_info->tail = 0;
  return rc;
}
