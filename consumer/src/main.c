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

#define NOD_RDMA_INIT_PSN 0
static nod_rdma_ctrl_block_t rdma_cb;

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

int nod_monitor_init(int argc, char *argv[], char *env[], nod_stack_info_t *p) {
  int rc;
  int ioctl_fd;
  nod_buffer_info_t *buffer_info;

  uint64_t rdma_size = p->buffer_size;
  ioctl_fd = open(NOD_IOCTL_PATH, O_RDWR);
  if (ioctl_fd < 0) {
    perror("Open " NOD_IOCTL_PATH " failed");
    rc = -EIO;
    goto out;
  }

  buffer_info = mmap(NULL, rdma_size, PROT_READ | PROT_WRITE, MAP_SHARED,
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

#if defined(NOD_RDMA_SUPPORT)
  nod_rdma_config_t rdma_config = {
      .ib_gid_index = NOD_RDMA_IB_GID_INDEX,
      .ib_port = NOD_RDMA_IB_PORT,
      .init_psn = NOD_RDMA_INIT_PSN, // Initial PSN can be set to 0
      .buffer_size = rdma_size,
      .pid = (unsigned int)syscall(SYS_gettid),
      .flags = 0, // NOD_RDMA_FLAG_REPORT_LOST,
  };
  strncpy(rdma_config.device_name, NOD_RDMA_DEVICE_NAME,
          sizeof(rdma_config.device_name) - 1);

  int sockfd =
      nod_rdma_sock_connect(NOD_RDMA_SERVER_NAME, NOD_RDMA_SERVER_PORT);
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
                                (char *)buffer_info, rdma_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto err_socket;
  }

  rc =
      nod_qp_connect(&rdma_cb, NOD_RDMA_IB_PORT, NOD_RDMA_IB_GID_INDEX, sockfd);
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

void nod_monitor_exit(struct nod_syscall_args *syscall_args, nod_stack_info_t *p) {
  uint64_t rdma_size = p->buffer_size;
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

  munmap(buffer_info, rdma_size);
  close(p->ioctl_fd);
}

int nod_monitor_main(int argc, char *argv[], char *env[], nod_stack_info_t *p) {
  int rc;
  nod_buffer_info_t *buffer_info = p->buffer_info;
  nod_event_hdr_t *first_evt = (nod_event_hdr_t *)buffer_info->buffer;

#ifdef NOD_RDMA_SUPPORT
  uint64_t rdma_buffer_size = sizeof(nod_buffer_info_t) + buffer_info->tail;
  if (likely(buffer_info->rdma_protocal.available &&
             rdma_buffer_size > sizeof(nod_buffer_info_t))) {
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

  rc = 0;

#ifdef NOD_RDMA_SUPPORT
out:
#endif // NOD_RDMA_SUPPORT

  // statistics
  buffer_info->stat.residence_time_sum += nod_rdtsc() - first_evt->ts;
  buffer_info->stat.total_nevents += buffer_info->nevents;
  buffer_info->stat.total_nevents_bytes += buffer_info->tail;
  buffer_info->stat.enter_cnt++;

  buffer_info->nevents = buffer_info->tail = 0;
  return rc;
}
