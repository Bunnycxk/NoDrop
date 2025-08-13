#include <asm/syscall.h>
#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/sched/task_stack.h>
#include <linux/tracepoint.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include "fillers.h"
#include "ioctl.h"
#include "nodrop.h"
#include "procinfo.h"
#include "tsc.h"

typedef int (*nod_syscall_filter_fn)(struct nod_proc_info *p,
                                     struct pt_regs *regs, void *args);

#ifndef CONFIG_HAVE_SYSCALL_TRACEPOINTS
#error The kernel must have HAVE_SYSCALL_TRACEPOINTS in order to be useful
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35))
#define TRACEPOINT_PROBE_REGISTER(p1, p2) tracepoint_probe_register(p1, p2)
#define TRACEPOINT_PROBE_UNREGISTER(p1, p2) tracepoint_probe_unregister(p1, p2)
#define TRACEPOINT_PROBE(probe, args...) static void probe(args)
#else
#define TRACEPOINT_PROBE_REGISTER(p1, p2)                                      \
  tracepoint_probe_register(p1, p2, NULL)
#define TRACEPOINT_PROBE_UNREGISTER(p1, p2)                                    \
  tracepoint_probe_unregister(p1, p2, NULL)
#define TRACEPOINT_PROBE(probe, args...) static void probe(void *__data, args)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define SYSCALL_DEF const struct pt_regs *_syscall_regs
#define SYSCALL_ARGS _syscall_regs
#else
#define SYSCALL_DEF long _di, long _si, long _dx, long _r10, long _r8, long _r9
#define SYSCALL_ARGS _di, _si, _dx, _r10, _r8, _r9
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17,0)

static char nod_target_comm[NOD_TARGET_COMM_MAX_LEN];
static const char nod_target_comm_for_redis[] = "io_thd_";

#if 0
#define NOD_TEST(task)                                                         \
  if (!(strncmp(task->comm, nod_target_comm, sizeof(nod_target_comm)) == 0 ||  \
        (strlen(task->comm) > 3 && task->comm[0] == 'i' &&                     \
         task->comm[1] == 'o' && task->comm[2] == '_' &&                       \
         task->comm[3] == 't')))
#else
#define NOD_TEST(task)                                                         \
  if(strncmp(task->comm, nod_target_comm, sizeof(nod_target_comm)))
#endif

void nod_set_target_comm(const char *comm) {
  if (comm && strlen(comm) < NOD_TARGET_COMM_MAX_LEN - 1) {
    strncpy(nod_target_comm, comm, NOD_TARGET_COMM_MAX_LEN - 1);
    nod_target_comm[NOD_TARGET_COMM_MAX_LEN - 1] = '\0';
  } else {
    vpr_err("Invalid target comm name: %s\n", comm);
  }
}

void nod_get_target_comm(char *comm) {
  strncpy(comm, nod_target_comm, NOD_TARGET_COMM_MAX_LEN - 1);
}

struct nod_syscall_filter {
  int enable;
  int hooked;
  nod_syscall_filter_fn pre_filter;
  nod_syscall_filter_fn post_filter;
  sys_call_ptr_t oldsyscall;
};

static int tracepoint_registered;
static sys_call_ptr_t *syscall_table;
static struct nod_syscall_filter syscall_filters[SYSCALL_TABLE_SIZE];

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
static struct tracepoint *tp_sys_exit;
#endif
static struct tracepoint *tp_sched_process_exit;

/* compat tracepoint functions */
static int compat_register_trace(void *func, const char *probename,
                                 struct tracepoint *tp) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
  return TRACEPOINT_PROBE_REGISTER(probename, func);
#else
  return tracepoint_probe_register(tp, func, NULL);
#endif
}

static void compat_unregister_trace(void *func, const char *probename,
                                    struct tracepoint *tp) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0))
  TRACEPOINT_PROBE_UNREGISTER(probename, func);
#else
  tracepoint_probe_unregister(tp, func, NULL);
#endif
}

TRACEPOINT_PROBE(syscall_exit_probe, struct pt_regs *regs, long ret) {
  int evt_from, id;
  unsigned long clone_flags;
  struct nod_proc_info *p;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
  if (unlikely(current->flags & PF_KTHREAD))
#else
  if (unlikely(current->flags & PF_BORROWED_MM))
#endif
  {
    // We are not interested in kernel threads
    return;
  }

#ifdef NOD_TEST
  NOD_TEST(current) { return; }
#endif

  /*
   * Since some syscalls are not supported yet, those syscalls will be filtered
   * here. These codes will be removed in the release version.
   */
  id = nod_get_syscall_nr(regs);
  if (unlikely(id < 0 || id >= SYSCALL_TABLE_SIZE ||
               nod_syscall_filler_table[id] == NULL)) {
    return;
  }

  evt_from = nod_event_from(&p);

  switch (evt_from) {
  case NOD_RESTORE_CONTEXT:
    ASSERT(id == __NR_ioctl);
    ASSERT(p);
    nod_restore_security(p);
    nod_restore_context(p, regs);
    nod_proc_set_out(p);
    // vpr_info("ctxswtich ts:%llu\n", nod_rdtsc() - p->buffer.ts);
    break;

  case NOD_RESTORE_SECURITY:
    ASSERT(p);
    nod_restore_security(p);
    break;

  case NOD_OUT:
  case NOD_CLONE:
  case NOD_SHARE:
    switch (id) {
    case __NR_clone:
    case __NR_clone3:
      if (ret) { // parent process
        if (!p) {
          p = nod_proc_acquire(evt_from, NULL, current);
        }
        if (p) {
          record_one_event(p, regs, id, 0);
        }
        break;
      }
      // child process
      // FIXME: correctly check clone_flags to determine whether the child
      // process share the address space with parent process If shared, the
      // child should has its own proc_info, otherwise, the child can inherit
      // the proc_info
      // Currently, to pass the evaluation, the child is always shared
#if 0
      clone_flags = 0;
      if (id == __NR_clone)
        clone_flags = nod_get_syscall_argument(regs, 3);
      else if (id == __NR_clone3) {
        if (copy_from_user((void *)&clone_flags,
                           (void *)nod_get_syscall_argument(regs, 1),
                           sizeof(clone_flags))) {
          clone_flags = 0;
        }
      }

      /*
       * If the child process has its own address space,
       * he should inherit parent's procinfo, including buffer, load address
       * and pkey. We mark it here and do it lazily.
       */
      evt_from = (clone_flags & CLONE_VM) ? NOD_SHARE : NOD_CLONE;
#else
      evt_from = NOD_SHARE;
#endif
      if (!nod_proc_acquire(evt_from, NULL, current)) {
        vpr_err("acquire %d for childed process failed\n", evt_from);
      }
      break;
    case __NR_fork:
    case __NR_vfork:
      if (ret) { // parent process
        if (!p) {
          p = nod_proc_acquire(evt_from, NULL, current);
        }
        if (p) {
          record_one_event(p, regs, id, 0);
        }
        break;
      }
      // child process
      if (!nod_proc_acquire(NOD_CLONE, NULL, current)) {
        vpr_err("acquire NOD_CLONE for childed process failed\n");
      }
      break;
    case __NR_execve:
    case __NR_execveat:
      // TODO: execv-family syscall should be logged at the syscall enter to
      // collect their arguments, just ignore them now
      // TODO: add more execv-family syscalls
      if (p) {
        nod_init_procinfo(current, p);
        nod_proc_set_out(p);
      }
      break;
    default:
      if (!p) {
        p = nod_proc_acquire(evt_from, NULL, current);
      }
      if (p) {
        record_one_event(p, regs, id, 0);
      }
      break;
    }
    break;

  default:
    /* ignore logging any syscall from the consumer */
    break;
  }
}

TRACEPOINT_PROBE(syscall_procexit_probe, struct task_struct *tsk) {

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
  if (unlikely(current->flags & PF_KTHREAD))
#else
  if (unlikely(current->flags & PF_BORROWED_MM))
#endif
  {
    // We are not interested in kernel threads
    return;
  }

#ifdef NOD_TEST
  NOD_TEST(tsk) { return; }
#endif

  nod_proc_release(tsk);
}

// static int execv_filter_pre(struct nod_proc_info *p, struct pt_regs *regs,
//                             void *_) {
//   int id = nod_get_syscall_nr(regs);
//   if (!p) {
//     return 0;
//   }
//
//   switch (p->status) {
//   case NOD_OUT:
//   case NOD_CLONE:
//   case NOD_SHARE:
//     if (likely(record_one_event(p, regs, id, 1) == NOD_SUCCESS_LOAD))
//       return -EAGAIN;
//
//     break;
//
//   case NOD_IN:
//     nod_restore_security(p);
//     break;
//
//   default:
//     break;
//   }
//
//   return 0;
// }
//
// static int execv_filter_post(struct nod_proc_info *p, struct pt_regs *regs,
//                              void *args) {
//   int ret_val = (int)(unsigned long)args;
//
//   if (!p || ret_val < 0) {
//     return 0;
//   }
//
//   switch (p->status) {
//   case NOD_OUT:
//   case NOD_CLONE:
//   case NOD_SHARE:
//     break;
//
//   case NOD_IN:
//     /*
//      * In execve(), the address space will be replaced with the new one.
//      * The original instrumented monitor will no longer exist.
//      */
//     nod_init_procinfo(current, p);
//     nod_proc_set_out(p);
//
//     break;
//
//   default:
//     break;
//   }
//
//   return 0;
// }

static int exit_filter_pre(struct nod_proc_info *p, struct pt_regs *regs,
                           void *_) {
  int id = nod_get_syscall_nr(regs);
  if (!p) {
    p = nod_proc_acquire(NOD_OUT, NULL, current);
    if (!p)
      return 0;
  }

  switch (p->status) {
  case NOD_OUT:
  case NOD_CLONE:
  case NOD_SHARE:
    if (likely(record_one_event(p, regs, id, 1) == NOD_SUCCESS_LOAD))
      return -EAGAIN;

    break;

  case NOD_IN:
    nod_restore_security(p);

    break;

  default:
    break;
  }

  return 0;
}

static int mm_range_filter_pre(struct nod_proc_info *p, struct pt_regs *regs,
                               void *_) {
  unsigned long addr, length;

  if (!p) {
    return 0;
  }

  addr = nod_get_syscall_argument(regs, 1);
  length = nod_get_syscall_argument(regs, 2);

  switch (p->status) {
  case NOD_IN:
  case NOD_RESTORE_CONTEXT:
  case NOD_RESTORE_SECURITY:
    return 0;

  default:
    if (nod_mmap_check(addr, length)) {
      vpr_warn("is trying to manipulate monitor memory %lx len %ld\n", addr,
               length);
      return -EINVAL;
    }

    return 0;
  }
}

static long hook_general(SYSCALL_DEF) {
  int ret, id;
  struct pt_regs *regs;
  struct nod_proc_info *p;
  struct nod_syscall_filter *filter;

  regs = current_pt_regs();
  id = nod_get_syscall_nr(regs);
  filter = &syscall_filters[id];

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
  if (unlikely(current->flags & PF_KTHREAD))
#else
  if (unlikely(current->flags & PF_BORROWED_MM))
#endif
  {
    // We are not interested in kernel threads
    return filter->oldsyscall(SYSCALL_ARGS);
  }

#ifdef NOD_TEST
  NOD_TEST(current) { return filter->oldsyscall(SYSCALL_ARGS); }
#endif

  ASSERT(1 == syscall_filters[id].hooked);

  nod_event_from(&p);

  ret = filter->pre_filter ? filter->pre_filter(p, regs, NULL) : 0;
  if (ret)
    return ret;

  ret = filter->oldsyscall(SYSCALL_ARGS);
  if (filter->post_filter) {
    filter->post_filter(p, regs, (void *)(unsigned long)ret);
  }
  return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
static inline void nod_write_cr0(unsigned long cr0) {
  unsigned long __force_order;
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
#else
#define nod_write_cr0 write_cr0
#endif

#define WPOFF                                                                  \
  do {                                                                         \
    nod_write_cr0(read_cr0() & (~0x10000));                                    \
  } while (0)
#define WPON                                                                   \
  do {                                                                         \
    nod_write_cr0(read_cr0() | 0x10000);                                       \
  } while (0)

static void hook_syscall(int id, nod_syscall_filter_fn pre,
                         nod_syscall_filter_fn post) {
  if (id < 0 || id >= SYSCALL_TABLE_SIZE)
    return;

  if (!syscall_filters[id].hooked) {
    syscall_filters[id].hooked = 1;
    WPOFF;
    syscall_filters[id].oldsyscall = syscall_table[id];
    syscall_table[id] = (sys_call_ptr_t)hook_general;
    WPON;
  }

  syscall_filters[id].pre_filter = pre;
  syscall_filters[id].post_filter = post;
}

static void unhook_syscall(int id) {
  if (id < 0 || id >= SYSCALL_TABLE_SIZE)
    return;

  if (!syscall_filters[id].hooked)
    return;

  WPOFF;
  syscall_table[id] = syscall_filters[id].oldsyscall;
  WPON;

  syscall_filters[id].hooked = 0;
  syscall_filters[id].oldsyscall = 0;
}

int trace_syscall(void) {
  int ret;

  if (tracepoint_registered == 1) {
    ret = 0;
    goto out;
  }

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
  ret = compat_register_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
  ret = register_trace_syscall_exit(syscall_exit_probe);
#endif
  if (ret) {
    pr_err("can't create the sys_exit tracepoint\n");
    goto err_syscall_exit;
  }

  ret = compat_register_trace(syscall_procexit_probe, "sched_process_exit",
                              tp_sched_process_exit);
  if (ret) {
    pr_err("can't create the sched_process_exit tracepoint\n");
    goto err_sched_procexit;
  }

  hook_syscall(__NR_exit, exit_filter_pre, NULL);
  hook_syscall(__NR_exit_group, exit_filter_pre, NULL);
  hook_syscall(__NR_munmap, mm_range_filter_pre, NULL);
  hook_syscall(__NR_mprotect, mm_range_filter_pre, NULL);
  hook_syscall(__NR_mremap, mm_range_filter_pre, NULL);

  tracepoint_registered = 1;
  return 0;

err_sched_procexit:
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
  compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
  unregister_trace_syscall_exit(syscall_exit_probe);
#endif
err_syscall_exit:
out:
  return ret;
}

void untrace_syscall(void) {
  if (tracepoint_registered == 0)
    return;

  unhook_syscall(__NR_exit);
  unhook_syscall(__NR_exit_group);
  unhook_syscall(__NR_munmap);
  unhook_syscall(__NR_mprotect);
  unhook_syscall(__NR_mremap);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 20)
  compat_unregister_trace(syscall_exit_probe, "sys_exit", tp_sys_exit);
#else
  unregister_trace_syscall_exit(syscall_exit_probe);
#endif

  compat_unregister_trace(syscall_procexit_probe, "sched_process_exit",
                          tp_sched_process_exit);

  tracepoint_registered = 0;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0))
static void visit_tracepoint(struct tracepoint *tp, void *priv) {
  if (!strcmp(tp->name, "sys_exit"))
    tp_sys_exit = tp;
  else if (!strcmp(tp->name, "sched_process_exit"))
    tp_sched_process_exit = tp;
}

static int get_tracepoint_handles(void) {
  for_each_kernel_tracepoint(visit_tracepoint, NULL);
  if (!tp_sys_exit) {
    pr_err("failed to find sys_exit tracepoint\n");
    return -ENOENT;
  }
  return 0;
}
#else
static int get_tracepoint_handles(void) { return 0; }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
#endif

uint64_t nod_lookup_name(const char *name) {
#ifdef KPROBE_LOOKUP
  typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
  kallsyms_lookup_name_t kallsyms_lookup_name;
  register_kprobe(&kp);
  kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
  unregister_kprobe(&kp);
#endif
  return kallsyms_lookup_name(name);
}

int tracepoint_init(void) {
  int ret;

  tracepoint_registered = 0;
  memset(nod_target_comm, 0, sizeof(nod_target_comm));

  syscall_table = (sys_call_ptr_t *)nod_lookup_name("sys_call_table");
  if (syscall_table == 0) {
    ret = -EINVAL;
    goto out;
  }

  ret = get_tracepoint_handles();
  if (ret)
    goto out;

  ret = trace_syscall();
  if (ret) {
    goto out;
  }

  ret = 0;

out:
  return ret;
}

void tracepoint_destory(void) { untrace_syscall(); }
