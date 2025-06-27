#ifndef NOD_RDMA_H_
#define NOD_RDMA_H_

#include "infiniband/verbs.h"
#include <stdbool.h>
#include <stdint.h>

#define NOD_RDMA_DEVICE_NAME "mlx5_0"    /* Default RDMA device name */
#define NOD_RDMA_SERVER_NAME "127.0.0.1" /* Default server name */
#define NOD_RDMA_SERVER_PORT 19531       /* Default server port */
#define NOD_RDMA_SYNC_MAGIC "N"
#define NOD_RDMA_IB_MAX_WR 32
#define NOD_RDMA_IB_MAX_SGE 30
#define NOD_RDMA_IB_PORT 1
#define NOD_RDMA_IB_GID_INDEX 0
#define NOD_RDMA_TO_ADDRESS(hi, lo) (((uint64_t)hi << 32) | ((uint64_t)lo))

typedef struct nod_rdma_config_s {
  char device_name[16]; /* RDMA device name */
  int ib_port;
  int ib_gid_index; /* IB port and GID index */
  int init_psn;
  int pid;
  uint64_t buffer_size;
} nod_rdma_config_t;

typedef struct nod_rdma_prop_s {
  uint32_t addr_hi; /* buffer address: high 32bit */
  uint32_t addr_lo; /* buffer address: low 32bit */
  uint32_t rkey;    /* remote key */
  uint32_t qpn;     /* QP number */
  uint32_t psn;     /* packet sequence number */
  uint32_t lid;     /* for ib only, always be 0 in RoCE v2 */
  uint8_t gid[16];  /* gid */
} nod_rdma_prop_t;

typedef struct nod_rdma_ctrl_block_s {
  struct ibv_context *ib_ctx; /* device handle */
  struct ibv_pd *ib_pd;       /* Protection Domain */
  struct ibv_cq *ib_cq;       /* Completion Queue */
  struct ibv_qp *ib_qp;       /* Queue Pair */
  struct ibv_mr *ib_mr;       /* Memory Region */
  int cq_size;
  char *buffer;
  uint64_t buffer_size;
  nod_rdma_prop_t remote_prop; /* Remote properties for connection */
} nod_rdma_ctrl_block_t;

int nod_rdma_ctrl_block_init(nod_rdma_ctrl_block_t *cb, const char *device_name,
                             char *buffer, uint64_t buffer_size);
void nod_rdma_ctrl_block_fini(nod_rdma_ctrl_block_t *cb);
int nod_qp_connect(nod_rdma_ctrl_block_t *cb, int ib_port, int ib_gid_index,
                   int sockfd);
int nod_rdma_post_send(nod_rdma_ctrl_block_t *cb, enum ibv_wr_opcode opcode,
                       char *buffer, uint32_t length);
int nod_rdma_poll(nod_rdma_ctrl_block_t *cb);
int nod_rdma_sock_connect(const char *server_name, int port);
ssize_t nod_read_from_socket(int sockfd, void *buffer, size_t len);
ssize_t nod_write_to_socket(int sockfd, const void *buffer, size_t len);

#endif // NOD_RDMA_H_
