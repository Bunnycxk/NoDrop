#include "events.h"
#include "rdma.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int run_server(const char *device_name, uint32_t socket_port, int buffer_size) {
  int rc;
  uint64_t curr_psn;
  nod_buffer_info_t *buffer_info;
  nod_rdma_ctrl_block_t cb;

  buffer_info = (nod_buffer_info_t *)malloc(sizeof(nod_buffer_info_t) + buffer_size);
  if (buffer_info == NULL) {
    perror("Failed to allocate buffer");
    rc = -ENOMEM;
    goto out;
  }

  memset(buffer_info, 0, sizeof(nod_buffer_info_t) + buffer_size);

  rc = nod_rdma_ctrl_block_init(&cb, NULL, NOD_RDMA_SERVER_PORT, device_name,
                                (char *)buffer_info, sizeof(nod_buffer_info_t) + buffer_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto out_free_buffer;
  }

  rc = nod_qp_connect(&cb, NOD_RDMA_IB_PORT, NOD_RDMA_IB_GID_INDEX);
  if (rc) {
    perror("Failed to connect QP");
    goto out_cb;
  }

  curr_psn = 0;
  while (true) {
    if (buffer_info->rdma_protocal.exited) {
      fprintf(stderr, "Server exiting...\n");
      rc = 0;
      break;
    }

    if (buffer_info->rdma_protocal.psn > curr_psn) {
      curr_psn = buffer_info->rdma_protocal.psn;
    }
  }

  printf("Server stopped, PSN: %lu\n", curr_psn);

out_cb:
  nod_rdma_ctrl_block_fini(&cb);
out_free_buffer:
  free(buffer_info);
out:
  return rc;
}

int main(int argc, char *argv[]) { 
  int buffer_size;
  if (argc < 2) {
    buffer_size = 8192;
  } else {
    buffer_size = atoi(argv[1]);
  }

  printf("Starting RDMA server with buffer size: %d\n", buffer_size);
  return run_server(NOD_RDMA_DEVICE_NAME, NOD_RDMA_SERVER_PORT, buffer_size); 
}
