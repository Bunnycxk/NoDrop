#ifndef NODROP_H_
#define NODROP_H_

#include <linux/elf.h>
#include <linux/ptrace.h>

#include "common.h"
#include "fillers.h"
// #include "ioctl.h"
#include "procinfo.h"

/* Forward declarations */
struct nod_proc_info;
enum nod_proc_status;

#define vpr_log(xxx, fmt, ...)                                                 \
  pr_##xxx("(%d)%s[%d][%s:%d]: " fmt, smp_processor_id(), current->comm,       \
           current->pid, __func__, __LINE__, ##__VA_ARGS__)
#define vpr_err(fmt, ...) vpr_log(err, fmt, ##__VA_ARGS__)
#define vpr_info(fmt, ...) vpr_log(info, fmt, ##__VA_ARGS__)
#define vpr_warn(fmt, ...) vpr_log(warn, fmt, ##__VA_ARGS__)
#define vpr_dbg(fmt, ...)
// #define vpr_dbg(fmt, ...) vpr_log(info, fmt, ##__VA_ARGS__)

#define ASSERT(expr) BUG_ON(!(expr))

#define NOD_SUCCESS 0
#define NOD_SUCCESS_LOAD 1
#define NOD_FAILURE_BUG -1
#define NOD_FAILURE_BUFFER_FULL -2
#define NOD_FAILURE_INVALID_EVENT -3
#define NOD_FAILURE_INVALID_USER_MEMORY -4
#define NOD_EVENT_FROM_MONITOR 1
#define NOD_EVENT_FROM_APPLICATION 2

#define NOD_INIT_INFO (1 << 1)
#define NOD_INIT_COUNT (1 << 2)

#ifdef CONFIG_X86_64
#define FSBASE fsbase
#define GSBASE gsbase
#else
#define FSBASE fs
#define GSBASE gs
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

typedef unsigned long syscall_arg_t;
typedef uint64_t nanoseconds;

// exittrace.c
int trace_register_init(void);
void trace_register_destory(void);

// proc.c
int proc_init(void);
void proc_destroy(void);

// privil.c
unsigned int nod_get_seccomp(void);
void nod_prepare_context(struct nod_proc_info *p, struct pt_regs *regs);
void nod_prepare_security(struct nod_proc_info *p);
void nod_restore_context(struct nod_proc_info *p, struct pt_regs *regs);
void nod_restore_security(struct nod_proc_info *p);

// trace.c
int trace_syscall(void);
void untrace_syscall(void);
int tracepoint_init(void);
void tracepoint_destory(void);
void nod_set_target_comm(const char *comm);
void nod_get_target_comm(char *comm);

// procinfo.c
int procinfo_init(void);
void procinfo_destroy(void);
struct nod_proc_info *nod_proc_acquire(enum nod_proc_status status,
                                       enum nod_proc_status *pre,
                                       struct task_struct *task);
enum nod_proc_status nod_proc_release(struct task_struct *task);
void nod_init_procinfo(struct task_struct *task, struct nod_proc_info *p);
int nod_copy_procinfo(struct task_struct *task, struct nod_proc_info *p);
int nod_share_procinfo(struct task_struct *task, struct nod_proc_info *p);
int nod_event_from(struct nod_proc_info **p);
int nod_proc_check_mm(struct nod_proc_info *p, unsigned long addr,
                      unsigned long length);
unsigned long nod_proc_traverse(int (*func)(struct nod_proc_info *,
                                            unsigned long *, va_list),
                                ...);

// loader.c
int loader_init(void);
void loader_destory(void);
int nod_load_monitor(struct nod_proc_info *p, struct pt_regs *regs);
int nod_mmap_check(unsigned long addr, unsigned long length);

// event.c
DECLARE_PER_CPU(struct nod_event_statistic, g_stat);
int record_one_event(struct nod_proc_info *p, struct pt_regs *regs, long id, int force);
int init_buffer(nod_buffer_t *buffer);
void free_buffer(nod_buffer_t *buffer);
void reset_buffer(nod_buffer_t *buffer, int flags);
int nod_event_set_buffer_size(unsigned long size);
int nod_event_get_buffer_size(unsigned long *size);

// elf.c
#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)

int elf_load_phdrs(struct elfhdr *elf_ex, struct file *elf_file,
                   struct elf_phdr **elf_phdrs);
int elf_load_shdrs(struct elfhdr *elf_ex, struct file *elf_file,
                   struct elf_shdr **elf_shdrs);
int elf_load_shstrtab(struct elfhdr *elf_ex, struct elf_shdr *elf_shdrs,
                      struct file *elf_file, char **elf_shstrtab);
unsigned long elf_load_binary(struct elfhdr *elf_ex, struct file *binary,
                              uint64_t *map_addr, unsigned long no_base,
                              struct elf_phdr *elf_phdrs);

// kernel_hacks
#include <linux/version.h>

/*
 * Linux 5.6 kernels no longer include the old 32-bit timeval
 * structures. But the syscalls (might) still use them.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#include <linux/time64.h>
struct compat_timespec {
  int32_t tv_sec;
  int32_t tv_nsec;
};

struct timespec {
  int32_t tv_sec;
  int32_t tv_nsec;
};

struct timeval {
  int32_t tv_sec;
  int32_t tv_usec;
};
#else
#define timeval64 timeval
#endif

#define nod_get_syscall_argument(regs, _start)                                 \
  nod_get_syscall_argument##_start(regs)
#define nod_get_syscall_argument1(regs) ((unsigned long)(regs->di))
#define nod_get_syscall_argument2(regs) ((unsigned long)(regs->si))
#define nod_get_syscall_argument3(regs) ((unsigned long)(regs->dx))
#define nod_get_syscall_argument4(regs) ((unsigned long)(regs->r10))
#define nod_get_syscall_argument5(regs) ((unsigned long)(regs->r8))
#define nod_get_syscall_argument6(regs) ((unsigned long)(regs->r9))
#define nod_get_syscall_nr(regs) ((int)(regs->orig_ax))
#define nod_get_syscall_ret(regs) ((long)(regs->ax))

static inline _unused void memory_dump(char *p, size_t size) {
  unsigned int j;
  pr_info("memory dump at 0x%lx (%ld)\n", (unsigned long)p, size);
  for (j = 0; j < size; j += 8)
    pr_info("%*ph\n", 8, &p[j]);
}

static inline _unused nanoseconds nod_nsecs(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
  return ktime_get_real_ns();
#else
  /* Don't have ktime_get_real functions */
  struct timespec ts;
  getnstimeofday(&ts);
  return SECOND_IN_NS * ts.tv_sec + ts.tv_nsec;
#endif
}

#endif // NODROP_H_
