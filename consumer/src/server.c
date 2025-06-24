#include "rdma.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int run_server(const char *device_name, uint32_t socket_port) {
  int rc;
  char *buffer;
  int buffer_size = 8192;
  nod_rdma_ctrl_block_t cb;

  buffer = (char *)malloc(buffer_size);
  if (buffer == NULL) {
    perror("Failed to allocate buffer");
    rc = -ENOMEM;
    goto out;
  }

  rc = nod_rdma_ctrl_block_init(&cb, NULL, NOD_RDMA_SERVER_PORT, device_name,
                                buffer, buffer_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto out_free_buffer;
  }

  rc = nod_qp_connect(&cb, NOD_RDMA_IB_PORT, NOD_RDMA_IB_GID_INDEX);
  if (rc) {
    perror("Failed to connect QP");
    goto out_cb;
  }

  while (true) {
    fwrite(buffer, 1, buffer_size, stdout);
    usleep(1000);
  }

  rc = 0;

out_cb:
  nod_rdma_ctrl_block_fini(&cb);
out_free_buffer:
  free(buffer);
out:
  return rc;
}

int main() { return run_server(NOD_RDMA_DEVICE_NAME, NOD_RDMA_SERVER_PORT); }
