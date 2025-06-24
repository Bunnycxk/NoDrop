#ifndef _COMMON_H_
#define _COMMON_H_


#include "events.h"

#ifdef __KERNEL__
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/capability.h>
#include <linux/limits.h>
#else
#include <sys/resource.h>
#include <stdint.h>

#define weak __attribute__((__weak__))
#define hidden __attribute__((__visibility__("hidden")))
#define weak_alias(old, new) \
	extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))

struct nod_monitor_info {
  int inited;
};
#endif
 
#define SYSCALL_EXIT_FAMILY(nr)     	((nr) == __NR_exit || (nr) == __NR_exit_group)

#define likely(x) 	__builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define B(x)  (x)
#define KB(x) (x << 10)
#define MB(x) (KB(x) << 10)
#define NOD_MEM_RND_MASK 0x7ff
#define NOD_SECTION_NAME ".monitor.info"
#define NOD_MONITOR_MEM_SIZE MB(32)

#define SECOND_IN_NS 1000000000 // 1s = 1e9ns
#define SECOND_IN_US 1000000 // 1s=1e6us
#define NS_TO_SEC(_ns) ((_ns) / SECOND_IN_NS)

struct nod_stack_info {
	int ioctl_fd;
	int pkey;
	int syscall_nr;
	long exit_code;
  uint64_t stack_start;
  uint64_t stack_end;
  uint64_t buffer_size;
	nod_buffer_info_t *buffer_info;
	unsigned long hash;
};

static unsigned long _unused
nod_calc_hash(struct nod_stack_info *stack)
{
	return (stack->ioctl_fd + 42) ^ (stack->pkey - 42) ^
		(unsigned long)stack->buffer_size ^ (unsigned long)stack->buffer_info;
}
#endif //_COMMON_H_
