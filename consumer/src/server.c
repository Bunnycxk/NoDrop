#include "events.h"
#include "rdma.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int run_server(int sockfd) {
  int rc;
  uint64_t curr_psn, remote_psn;
  uint64_t buffer_size;
  volatile nod_buffer_info_t *buffer_info;
  nod_rdma_config_t rdma_config;
  nod_rdma_ctrl_block_t cb;

  printf("Server (%d) started, waiting for RDMA config...\n", getpid());

  rc = nod_read_from_socket(sockfd, &rdma_config, sizeof(nod_rdma_config_t));
  if (rc != sizeof(nod_rdma_config_t)) {
    fprintf(stderr, "Failed to read RDMA config from socket: %d\n", rc);
    goto out;
  }

  printf("RDMA config received:\n");
  printf("  Device Name: %s\n", rdma_config.device_name);
  printf("  IB Port: %d\n", rdma_config.ib_port);
  printf("  IB GID Index: %d\n", rdma_config.ib_gid_index);
  printf("  Initial PSN: %d\n", rdma_config.init_psn);
  printf("  Buffer Size: %lu\n", rdma_config.buffer_size);

  buffer_size = rdma_config.buffer_size;
  buffer_info =
      (nod_buffer_info_t *)malloc(sizeof(nod_buffer_info_t) + buffer_size);
  if (buffer_info == NULL) {
    perror("Failed to allocate buffer");
    rc = -ENOMEM;
    goto out;
  }
  memset((void *)buffer_info, 0, sizeof(nod_buffer_info_t));

  rc = nod_rdma_ctrl_block_init(&cb, rdma_config.device_name,
                                (char *)buffer_info,
                                sizeof(nod_buffer_info_t) + buffer_size);
  if (rc) {
    perror("Failed to initialize RDMA control block");
    goto out_free_buffer;
  }

  rc = nod_qp_connect(&cb, rdma_config.ib_port, rdma_config.ib_gid_index,
                      sockfd);
  if (rc) {
    perror("Failed to connect QP");
    goto out_cb;
  }

  printf("RDMA control block initialized and QP connected\n");

  curr_psn = rdma_config.init_psn;
  while (true) {
    if (buffer_info->rdma_protocal.exited) {
      fprintf(stderr, "Server exiting...\n");
      rc = 0;
      break;
    }

    remote_psn = buffer_info->rdma_protocal.psn;
    if (remote_psn > curr_psn) {
      if (remote_psn - curr_psn > 1) {
        fprintf(stderr,
                "Remote PSN jumped from %lu to %lu, possible data loss\n",
                curr_psn, remote_psn);
      }
      curr_psn = remote_psn;
    }
  }

  printf("Server stopped, PSN: %lu\n", curr_psn);

out_cb:
  nod_rdma_ctrl_block_fini(&cb);
out_free_buffer:
  free((void *)buffer_info);
out:
  close(sockfd);
  return rc;
}

int main() {
  int rc, pid, sock_port = NOD_RDMA_SERVER_PORT, sockfd, listenfd;
  struct sockaddr_in server_addr;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(sock_port);

  rc = socket(AF_INET, SOCK_STREAM, 0);
  if (rc < 0) {
    perror("socket");
    goto out;
  }

  sockfd = rc;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  listenfd = sockfd;

  rc = bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (rc < 0) {
    perror("bind");
    goto out_close_socket;
  }

  rc = listen(listenfd, 1);
  if (rc < 0) {
    perror("listen");
    goto out_close_bind;
  }

  while (true) {
    printf("Waiting for connection on port %d...\n", sock_port);
    rc = accept(listenfd, NULL, 0);
    if (rc < 0) {
      perror("accept");
      goto out_close_bind;
    }

    pid = fork();
    if (pid < 0) {
      perror("fork");
      close(rc);
    } else if (pid == 0) {
      close(listenfd); // 子进程关闭监听套接字
      exit(run_server(rc));
    }
  }

  rc = 0;

out_close_bind:
  close(listenfd);
out_close_socket:
  close(sockfd);
out:
  return rc;
}
