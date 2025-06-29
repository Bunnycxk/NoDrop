#ifndef NOD_IOCTL_H_
#define NOD_IOCTL_H_


#define NOD_IOCTL_NAME "notamper"
#define NOD_IOCTL_PATH "/proc/"NOD_IOCTL_NAME

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/types.h>
#else
#include <sys/ioctl.h>
#include <stdint.h>
#endif //__KERNEL__

#define NOD_IOCTL_MAGIC 'n'
#define NOD_IOCTL_CLEAR_BUFFER                  _IO(NOD_IOCTL_MAGIC, 0)
#define NOD_IOCTL_FETCH_BUFFER                  _IO(NOD_IOCTL_MAGIC, 1)
#define NOD_IOCTL_READ_BUFFER_COUNT_INFO        _IO(NOD_IOCTL_MAGIC, 2)
#define NOD_IOCTL_READ_STATISTICS               _IO(NOD_IOCTL_MAGIC, 3)
#define NOD_IOCTL_CLEAR_STATISTICS              _IO(NOD_IOCTL_MAGIC, 4)
#define NOD_IOCTL_STOP_RECORDING                _IO(NOD_IOCTL_MAGIC, 5)
#define NOD_IOCTL_START_RECORDING               _IO(NOD_IOCTL_MAGIC, 6)
#define NOD_IOCTL_RESTORE_SECURITY              _IO(NOD_IOCTL_MAGIC, 7)
#define NOD_IOCTL_RESTORE_CONTEXT               _IO(NOD_IOCTL_MAGIC, 8)
#define NOD_IOCTL_GET_BUFFER_SIZE               _IO(NOD_IOCTL_MAGIC, 9)
#define NOD_IOCTL_SET_BUFFER_SIZE               _IO(NOD_IOCTL_MAGIC, 10)
#define NOD_IOCTL_GET_TARGET_COMM               _IO(NOD_IOCTL_MAGIC, 11)
#define NOD_IOCTL_SET_TARGET_COMM               _IO(NOD_IOCTL_MAGIC, 12)

#define NOD_TARGET_COMM_MAX_LEN 64

struct buffer_count_info {
	uint64_t event_count;
	uint64_t unflushed_count;
	uint64_t unflushed_len;
};

struct fetch_buffer_struct {
	uint64_t len;
	char *buf;
};

struct nod_event_statistic {
  uint64_t n_evts;
  uint64_t n_drop_evts;
  uint64_t n_drop_evts_unsolved;
};

typedef union nod_ioctl_data_u {
  struct buffer_count_info buffer_count;
  struct fetch_buffer_struct fetch_buffer;
  struct nod_event_statistic event_stat;
  struct {
    unsigned long bufsize;
  } buffer_size;
  struct {
    char comm[NOD_TARGET_COMM_MAX_LEN];
  } target_comm;
} nod_ioctl_data_t;

#endif //NOD_IOCTL_H_
