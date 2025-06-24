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

int nod_monitor_init(int argc, char *argv[], char *env[],
                     struct nod_stack_info *p) {
  int rc;
  rc = nod_rdma_ctrl_block_init(&rdma_cb, NOD_RDMA_SERVER_NAME,
                                NOD_RDMA_SERVER_PORT, NOD_RDMA_DEVICE_NAME,
                                p->buffer, p->buffer_info->buffer_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto out;
  }

  rc = nod_qp_connect(&rdma_cb, NOD_RDMA_IB_PORT, NOD_RDMA_IB_GID_INDEX);
  if (rc) {
    perror("Failed to connect QP");
    goto out_cb;
  }

  return 0;

out_cb:
  nod_rdma_ctrl_block_fini(&rdma_cb);
out:
  return rc;
}

void nod_monitor_exit(long code, struct nod_stack_info *p) {
  nod_rdma_ctrl_block_fini(&rdma_cb);
}

int nod_monitor_main(int argc, char *argv[], char *env[],
                     struct nod_stack_info *p) {
  int rc;
  uint64_t ts;
  struct nod_buffer_info *buffer_info = p->buffer_info;

  ts = -nod_rdtsc();
  rc = nod_rdma_post_send(&rdma_cb, IBV_WR_RDMA_WRITE, p->buffer,
                        buffer_info->buffer_size);
  if (rc) {
    perror("Failed to post RDMA write");
    return rc;
  }
  rc = nod_rdma_poll(&rdma_cb);
  if (rc) {
    perror("Failed to poll RDMA completion");
    return rc;
  }
  ts += nod_rdtsc();
  printf("RDMA write ts:%lu\n", ts);

  buffer_info->nevents = buffer_info->tail = 0;
  return 0;
}
