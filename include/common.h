#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/types.h>

#define weak __attribute__((__weak__))
#define hidden __attribute__((__visibility__("hidden")))
#define weak_alias(old, new)                                                   \
  extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct nod_monitor_info {
  int inited;
};
#endif //__KERNEL__

#define _packed __attribute__((packed))
#define _unused __attribute__((unused))

#define NOD_GET_ARG_LEN(arg_len, arg_nr)                                       \
  (1 << NOD_GET_ARG_LEN_##arg_nr(arg_len))
#define NOD_SET_ARG_LEN(arg_len, arg_nr, bit)                                  \
  NOD_SET_ARG_LEN_##arg_nr(arg_len, bit)

#define NOD_GET_ARG_LEN_1(arg_len) ((arg_len) >> 6)
#define NOD_GET_ARG_LEN_2(arg_len) ((arg_len) >> 4)
#define NOD_GET_ARG_LEN_3(arg_len) ((arg_len) >> 2)
#define NOD_GET_ARG_LEN_4(arg_len) ((arg_len) >> 0)

#define NOD_SET_ARG_LEN_1(arg_len, bit) ((arg_len) |= (bit << 6))
#define NOD_SET_ARG_LEN_2(arg_len, bit) ((arg_len) |= (bit << 4))
#define NOD_SET_ARG_LEN_3(arg_len, bit) ((arg_len) |= (bit << 2))
#define NOD_SET_ARG_LEN_4(arg_len, bit) ((arg_len) |= (bit << 0))

#define B(x) (x)
#define KB(x) (x << 10)
#define MB(x) (KB(x) << 10)
#define NOD_MEM_RND_MASK 0x7ff
#define NOD_SECTION_NAME ".monitor.info"
#define NOD_MONITOR_HEAP_SIZE MB(32)

#define SECOND_IN_NS 1000000000 // 1s = 1e9ns
#define SECOND_IN_US 1000000    // 1s=1e6us
#define NS_TO_SEC(_ns) ((_ns) / SECOND_IN_NS)

typedef struct nod_rdma_protocal_s {
  volatile uint64_t psn;
  volatile int exited;
  volatile int available;
} nod_rdma_protocal_t;

typedef struct nod_buffer_info_s {
  nod_rdma_protocal_t rdma_protocal;
  volatile uint64_t nevents;
  struct {
    volatile uint64_t residence_time_sum;
    volatile uint64_t total_nevents;
    volatile uint64_t total_nevents_bytes;
    volatile int enter_cnt;
  } stat;
  volatile uint32_t tail;
  uint64_t malloc_size;
  uint64_t buffer_size;
  char buffer[0];
} nod_buffer_info_t;

typedef struct nod_event_hdr_s {
  uint64_t ts;
  uint32_t pid;
  uint16_t len;
  uint8_t sc;
  uint8_t arg_len; // arg_len has 8 bits, each 2 bits stands for one argument
                   // length, max 4 arguments
  char args[0];
} _packed nod_event_hdr_t;

struct nod_syscall_args {
  long di;
  long si;
  long dx;
  long r10;
  long r8;
  long r9;
  int syscall_nr;
};

typedef struct nod_stack_info_s {
  int ioctl_fd;
  int pkey;
  struct nod_syscall_args syscall_args;
  uint64_t stack_start;
  uint64_t stack_end;
  uint64_t buffer_size;
  nod_buffer_info_t *buffer_info;
  unsigned long hash;
  unsigned long fsbase;
} nod_stack_info_t;

typedef struct nod_event_data_s {
  uint8_t len;
  char data[0];
} nod_event_data_t;

static unsigned long _unused nod_calc_hash(const nod_stack_info_t *stack) {
  return stack->fsbase ^ (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^
         (unsigned long)stack->buffer_size ^ (unsigned long)stack->buffer_info;
}

typedef struct nod_buffer_s {
  uint64_t event_count;
  uint64_t n_solved_evts;
  nod_buffer_info_t *info;
} nod_buffer_t;

#endif //_COMMON_H_
