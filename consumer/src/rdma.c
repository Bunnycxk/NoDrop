#include "rdma.h"
#include "arpa/inet.h"
#include "infiniband/verbs.h"
#include <stdio.h>
#include <unistd.h>

static int nod_sock_sync_data(int sockfd, size_t len, char *local,
                              char *remote) {
  int rc;
  size_t total, once;

  rc = write(sockfd, local, len);
  if (rc < 0 || rc < len) {
    perror("write local data failed");
    goto out;
  }

  rc = 0;
  for (total = 0; total < len; total += once) {
    once = read(sockfd, remote, len);
    if (once == 0) {
      fprintf(stderr, "read returned 0 bytes, connection closed\n");
      rc = -1;
      break;
    } else if (once < 0) {
      perror("read remote data failed");
      rc = once;
      break;
    }
  }

out:
  return rc;
}

static int nod_sock_connect(const char *server_name, int port) {
  int rc, sockfd, listenfd;
  struct sockaddr_in server_addr;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  rc = socket(AF_INET, SOCK_STREAM, 0);
  if (rc < 0) {
    perror("socket");
    goto out;
  }

  sockfd = rc;
  if (server_name == NULL) {
    /* Server */
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
    printf("Waiting for connection on port %d...\n", port);
    rc = accept(listenfd, NULL, 0);
    if (rc < 0) {
      perror("accept");
      goto out_close_bind;
    }
    sockfd = rc;
  } else {
    server_addr.sin_addr.s_addr = inet_addr(server_name);
    /* Client */
    rc = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (rc < 0) {
      perror("connect");
      goto out_close_socket;
    }
  }

  return sockfd;

out_close_bind:
  close(listenfd);
out_close_socket:
  close(sockfd);
out:
  return rc;
}

static inline int nod_remote_sync(nod_rdma_ctrl_block_t *cb,
                                  const char *prompt) {
  char sync_barrier[sizeof(NOD_RDMA_SYNC_MAGIC)];
  if (prompt) {
    puts(prompt);
  }
  return nod_sock_sync_data(cb->sockfd, sizeof(NOD_RDMA_SYNC_MAGIC),
                            (char *)NOD_RDMA_SYNC_MAGIC, (char *)sync_barrier);
}

int nod_rdma_ctrl_block_init(nod_rdma_ctrl_block_t *cb, const char *server_name,
                             uint32_t server_port, const char *device_name,
                             char *buffer, uint64_t buffer_size) {
  int i, num_dev;
  struct ibv_qp_init_attr qb_init_attr;
  struct ibv_device **dev_list, *ib_dev;

  memset(cb, 0, sizeof(nod_rdma_ctrl_block_t));

  cb->sockfd = nod_sock_connect(server_name, server_port);
  if (cb->sockfd < 0) {
    perror("socket failed");
    goto out;
  }

  printf("TCP connection established to %s:%u\n", server_name, server_port);

  dev_list = ibv_get_device_list(&num_dev);
  if (dev_list == NULL) {
    fprintf(stderr, "Failed to get IB devices list\n");
    goto out_sock;
  }

  printf("found %d device(s)\n", num_dev);
  if (num_dev == 0) {
    fprintf(stderr, "No IB devices found\n");
    goto out_dev_list;
  }

  ib_dev = NULL;
  for (i = 0; i < num_dev; i++) {
    if (!strcmp(ibv_get_device_name(dev_list[i]), device_name)) {
      ib_dev = dev_list[i];
      break;
    }
  }

  if (ib_dev == NULL) {
    fprintf(stderr, "IB device %s not found\n", device_name);
    goto out_dev_list;
  }

  cb->ib_ctx = ibv_open_device(ib_dev);
  if (cb->ib_ctx == NULL) {
    fprintf(stderr, "Failed to open device %s\n", device_name);
    goto out_dev_list;
  }

  cb->ib_pd = ibv_alloc_pd(cb->ib_ctx);
  if (cb->ib_pd == NULL) {
    perror("ibv_alloc_pd failed");
    goto out_device;
  }

  cb->cq_size = 1;
  cb->ib_cq = ibv_create_cq(cb->ib_ctx, cb->cq_size, NULL, NULL, 0);
  if (cb->ib_cq == NULL) {
    perror("ibv_create_cq failed");
    goto out_pd;
  }

  cb->buffer = buffer;
  cb->buffer_size = buffer_size;
  cb->ib_mr = ibv_reg_mr(cb->ib_pd, cb->buffer, cb->buffer_size,
                         IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
                             IBV_ACCESS_REMOTE_WRITE);
  if (cb->ib_mr == NULL) {
    cb->buffer = NULL;
    perror("ibv_reg_mr failed");
    goto out_cq;
  }

  printf("regsitered MR: addr=%p lkey=0x%x rkey=0x%x\n", cb->buffer,
         cb->ib_mr->lkey, cb->ib_mr->rkey);

  memset(&qb_init_attr, 0, sizeof(qb_init_attr));
  qb_init_attr.send_cq = cb->ib_cq;
  qb_init_attr.recv_cq = cb->ib_cq;
  qb_init_attr.cap.max_send_wr = NOD_RDMA_IB_MAX_WR;
  qb_init_attr.cap.max_recv_wr = NOD_RDMA_IB_MAX_WR;
  qb_init_attr.cap.max_send_sge = NOD_RDMA_IB_MAX_SGE;
  qb_init_attr.cap.max_recv_sge = NOD_RDMA_IB_MAX_SGE;
  qb_init_attr.qp_type = IBV_QPT_RC; // Reliable Connection
  cb->ib_qp = ibv_create_qp(cb->ib_pd, &qb_init_attr);
  if (cb->ib_qp == NULL) {
    perror("ibv_create_qp failed");
    goto out_mr;
  }

  printf("QP created with QP number: 0x%x\n", cb->ib_qp->qp_num);

  ibv_free_device_list(dev_list);
  return 0;

out_mr:
  ibv_dereg_mr(cb->ib_mr);
out_cq:
  ibv_destroy_cq(cb->ib_cq);
out_pd:
  ibv_dealloc_pd(cb->ib_pd);
out_device:
  ibv_close_device(cb->ib_ctx);
out_dev_list:
  ibv_free_device_list(dev_list);
out_sock:
  close(cb->sockfd);
out:
  return -1;
}

void nod_rdma_ctrl_block_fini(nod_rdma_ctrl_block_t *cb) {
  if (cb->ib_qp) {
    ibv_destroy_qp(cb->ib_qp);
  }
  if (cb->ib_mr) {
    ibv_dereg_mr(cb->ib_mr);
  }
  if (cb->ib_cq) {
    ibv_destroy_cq(cb->ib_cq);
  }
  if (cb->ib_pd) {
    ibv_dealloc_pd(cb->ib_pd);
  }
  if (cb->ib_ctx) {
    ibv_close_device(cb->ib_ctx);
  }
  if (cb->sockfd >= 0) {
    close(cb->sockfd);
  }
}

static int nod_qp_modify_to_init(nod_rdma_ctrl_block_t *cb, int ib_port) {
  int mask;
  struct ibv_qp_attr attr;
  memset(&attr, 0, sizeof(attr));

  /* Init QP */
  attr.qp_state = IBV_QPS_INIT;
  attr.port_num = ib_port;
  attr.pkey_index = 0; // Default PKEY index
  attr.qp_access_flags =
      IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

  mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
  return ibv_modify_qp(cb->ib_qp, &attr, mask);
}

static int nod_qp_modify_to_rtr(nod_rdma_ctrl_block_t *cb, int ib_port,
                                nod_rdma_prop_t *remote_prop) {
  int mask;
  struct ibv_qp_attr attr;

  /* RTR QP */
  attr.qp_state = IBV_QPS_RTR;
  attr.path_mtu = IBV_MTU_4096;
  attr.dest_qp_num = remote_prop->qpn; // Remote QP number
  attr.rq_psn = remote_prop->psn;      // Remote Packet Sequence Number
  attr.max_dest_rd_atomic = 1;
  attr.min_rnr_timer = 12;

  attr.ah_attr.is_global = 1;
  attr.ah_attr.dlid = remote_prop->lid;
  attr.ah_attr.sl = 0; // Service Level
  attr.ah_attr.src_path_bits = 0;
  attr.ah_attr.port_num = ib_port;

  attr.ah_attr.grh.hop_limit = 1;
  attr.ah_attr.grh.sgid_index = 1;
  memmove(&attr.ah_attr.grh.dgid, remote_prop->gid,
          sizeof(attr.ah_attr.grh.dgid));

  mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
         IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
  return ibv_modify_qp(cb->ib_qp, &attr, mask);
}

static int nod_qp_modify_to_rts(nod_rdma_ctrl_block_t *cb) {
  int mask;
  struct ibv_qp_attr attr;
  memset(&attr, 0, sizeof(attr));

  /* RTS QP */
  attr.qp_state = IBV_QPS_RTS;
  attr.sq_psn = 0;
  attr.timeout = 10;
  attr.retry_cnt = 5;
  attr.rnr_retry = 4; /* infinite */
  attr.max_rd_atomic = 1;

  mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
         IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
  return ibv_modify_qp(cb->ib_qp, &attr, mask);
}

int nod_qp_connect(nod_rdma_ctrl_block_t *cb, int ib_port, int ib_gid_index) {
  int rc;
  union ibv_gid ib_gid;
  struct ibv_port_attr port_attr;
  nod_rdma_prop_t local_prop, remote_prop, tmp_prop;

  /* Get Global Identifier (GID) */
  rc = ibv_query_gid(cb->ib_ctx, ib_port, ib_gid_index, &ib_gid);
  if (rc) {
    perror("ibv_query_gid failed");
    return rc;
  }

  rc = ibv_query_port(cb->ib_ctx, ib_port, &port_attr);
  if (rc) {
    perror("ibv_query_port failed");
    return rc;
  }

  local_prop.addr_hi = htonl((uint32_t)((uintptr_t)cb->buffer >> 32));
  local_prop.addr_lo = htonl((uint32_t)((uintptr_t)cb->buffer & 0xFFFFFFFF));
  local_prop.qpn = htonl(cb->ib_qp->qp_num);
  local_prop.psn = 0; // Packet Sequence Number, can be set to 0
  local_prop.rkey = htonl(cb->ib_mr->rkey);
  local_prop.lid = htons(port_attr.lid);
  memmove(local_prop.gid, &ib_gid, sizeof(ib_gid));

  /* Let the remote side be aware of the properties of this side */
  rc = nod_sock_sync_data(cb->sockfd, sizeof(nod_rdma_prop_t),
                          (char *)&local_prop, (char *)&tmp_prop);
  if (rc < 0) {
    perror("Failed to exchange connection data");
    return rc;
  }

  remote_prop.addr_hi =
      ntohl(tmp_prop.addr_hi); // Remote buffer address: high 32bit
  remote_prop.addr_lo =
      ntohl(tmp_prop.addr_lo);             // Remote buffer address: low 32bit
  remote_prop.qpn = ntohl(tmp_prop.qpn);   // Remote QP number
  remote_prop.psn = ntohl(tmp_prop.psn);   // Remote Packet Sequence Number
  remote_prop.rkey = ntohl(tmp_prop.rkey); // Remote Key
  remote_prop.lid = ntohs(tmp_prop.lid);   // Remote LID
  memmove(remote_prop.gid, tmp_prop.gid, sizeof(remote_prop.gid));

  printf("Remote buffer address = 0x%lx\n",
         NOD_RDMA_TO_ADDRESS(remote_prop.addr_hi, remote_prop.addr_lo));
  printf("Remote QP number = 0x%x\n", remote_prop.qpn);
  printf("Remote Key = 0x%x\n", remote_prop.rkey);
  printf("Remote GID = "
         "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
         "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
         remote_prop.gid[0], remote_prop.gid[1], remote_prop.gid[2],
         remote_prop.gid[3], remote_prop.gid[4], remote_prop.gid[5],
         remote_prop.gid[6], remote_prop.gid[7], remote_prop.gid[8],
         remote_prop.gid[9], remote_prop.gid[10], remote_prop.gid[11],
         remote_prop.gid[12], remote_prop.gid[13], remote_prop.gid[14],
         remote_prop.gid[15]);
  memmove(&cb->remote_prop, &remote_prop,
          sizeof(nod_rdma_prop_t)); // Save remote properties

  /* Init QP */
  rc = nod_qp_modify_to_init(cb, ib_port);
  if (rc) {
    perror("Failed to initialize QP");
    return rc;
  }
  printf("QP state changed to INIT\n");

  /* Modify QP to RTR state */
  rc = nod_qp_modify_to_rtr(cb, ib_port, &remote_prop);
  if (rc) {
    perror("Failed to modify QP to RTR");
    return rc;
  }
  printf("QP state changed to RTR\n");

  /* Modify QP to RTS state */
  rc = nod_qp_modify_to_rts(cb);
  if (rc) {
    perror("Failed to modify QP to RTS");
    return rc;
  }
  printf("QP state changed to RTS\n");

  /* Now, QP is ready to send, wait remote side completion */
  return nod_remote_sync(cb, "Waiting for remote side to complete connection");
}

int nod_rdma_post_send(nod_rdma_ctrl_block_t *cb, enum ibv_wr_opcode opcode,
                       char *buffer, uint32_t length) {
  struct ibv_send_wr wr;
  struct ibv_sge sge = {
      .addr = (uint64_t)buffer,
      .length = length,
      .lkey = cb->ib_mr->lkey,
  };

  /* prepare WR */
  memset(&wr, 0, sizeof(wr));

  wr.num_sge = 1;
  wr.sg_list = &sge;
  wr.opcode = opcode;

  wr.wr_id = 0;                      // Set to 0 or any unique ID
  wr.send_flags = IBV_SEND_SIGNALED; // Signal completion
  wr.wr.rdma.remote_addr = (uint64_t)NOD_RDMA_TO_ADDRESS(
      cb->remote_prop.addr_hi, cb->remote_prop.addr_lo);
  wr.wr.rdma.rkey = cb->remote_prop.rkey;

  return ibv_post_send(cb->ib_qp, &wr, NULL);
}

int nod_rdma_poll(nod_rdma_ctrl_block_t *cb) {
  int rc;
  struct ibv_wc wc;

  do {
    // ts = -nod_rdtsc();
    rc = ibv_poll_cq(cb->ib_cq, 1, &wc);
    // ts += nod_rdtsc();
  } while (rc == 0);

  if (rc < 0) {
    perror("ibv_poll_cq failed");
    return rc;
  }
  if (wc.status != IBV_WC_SUCCESS) {
    fprintf(stderr, "Completion error: %s\n", ibv_wc_status_str(wc.status));
    return -1; // Error in completion
  }
  return 0;
}
