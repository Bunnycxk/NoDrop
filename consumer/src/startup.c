#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"
#include "ioctl.h"

#include "dynlink.h"
#include "mmheap.h"
#include "pkeys.h"
#include "tsc.h"

#define START "_start"

#define NOREACH __builtin_unreachable();
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003

extern unsigned long __bdata;
extern unsigned long __edata;

static char nod_mmheap_pool[NOD_MONITOR_MEM_SIZE];
__attribute__((
    section(NOD_SECTION_NAME))) struct nod_monitor_info __nod_monitor_info = {
    .inited = 0,
};

// declarations of processing logic
int nod_monitor_main(int argc, char *argv[], char *env[],
                     struct nod_stack_info *p);
weak void nod_monitor_exit(long code, struct nod_stack_info *p) {};
weak int nod_monitor_init(int argc, char *argv[], char *env[],
                          struct nod_stack_info *p) {
  return 0;
};

// declarations of startup
static void nod_start_main(int argc, char *argv[], char *env[]);

weak void init();
weak void _fini();
int __libc_start_main(int (*)(), int, char **, void (*)(), void (*)(),
                      void (*)());

__asm__(".text \n"
        ".global _start \n"
        "_start: \n"
        "xor %rbp,%rbp \n"
        "mov %rsp,%rdi \n"
        ".weak _DYNAMIC \n"
        ".hidden _DYNAMIC \n"
        "lea _DYNAMIC(%rip),%rsi \n"
        "andq $-16,%rsp \n"
        "call _start_c \n");

static int nod_init(int argc, char *argv[], char *env[],
                    struct nod_stack_info *p) {
  int rc;

  if (likely(__nod_monitor_info.inited)) {
#ifdef NOD_PKEY_SUPPORT
    if (p->pkey != -1) {
      pkey_set(p->pkey, PKEY_WR);
    }
#endif // NOD_PKEY_SUPPORT
    return 0;
  }

  rc = nod_monitor_init(argc, argv, env, p);
  if (rc) {
    perror("NOD_MONITOR_INIT failed");
    goto out;
  }

#ifdef NOD_PKEY_SUPPORT
  if (p->pkey != -1) {
    pkey_set(p->pkey, PKEY_WR);
    rc = pkey_mprotect(&__bdata,
                       (unsigned long)&__edata - (unsigned long)&__bdata,
                       PROT_READ | PROT_WRITE, p->pkey);
    if (rc) {
      perror("pkey_mprotect for data segment failed");
      goto out;
    }

    rc = pkey_mprotect(p->stack_start, p->stack_end - p->stack_start,
                       PROT_READ | PROT_WRITE, p->pkey);
    if (rc) {
      perror("pkey_mprotect for stack failed");
      goto out;
    }
  }
#endif // NOD_PKEY_SUPPORT

  __nod_monitor_info.inited = 1;
  rc = mprotect(&__nod_monitor_info, sizeof(__nod_monitor_info), PROT_READ);
  if (rc) {
    perror("mprotect for nod_monitor_info failed");
    goto out;
  }

  return 0;

out:
  exit(-1);
}

static void nod_fini(int argc, char **argv, char **env,
                     struct nod_stack_info *p) {
  p->hash = nod_calc_hash(p);
  if (unlikely(SYSCALL_EXIT_FAMILY(p->syscall_nr))) {
    nod_monitor_exit(p->syscall_nr, p);
    syscall(p->syscall_nr, p->exit_code);
  } else {
#ifdef NOD_PKEY_SUPPORT
    if (likely(p->pkey != -1)) {
      pkey_set(p->pkey, PKEY_DISABLE_WRITE);
    }
#endif // NOD_PKEY_SUPPORT
    ioctl(p->ioctl_fd, NOD_IOCTL_RESTORE_CONTEXT, p);
  }
  /* NOT REACHABLE */
  NOREACH
  perror("FATAL: not reachable");
  exit(-1);
}

static void nod_start_main(int argc, char *argv[], char *env[]) {
  struct nod_stack_info *p = (struct nod_stack_info *)argv[argc - 1];
  if (likely(nod_init(argc, argv, env, p) == 0)) {
    nod_monitor_main(argc, argv, env, p);
  }
  nod_fini(argc, argv, env, p);
}

hidden void _start_c(size_t *sp, size_t *dynv) {
  size_t i, aux[AUX_CNT], dyn[DYN_CNT];
  size_t *rel, rel_size, base;

  int argc = *sp;
  char **argv = (void *)(sp + 1);
  char **env = argv + argc + 1;

  if (likely(__nod_monitor_info.inited)) {
    nod_start_main(argc, argv, env);
    return;
  }

  for (i = argc + 1; argv[i]; i++)
    ;
  size_t *auxv = (void *)(argv + i + 1);

  for (i = 0; i < AUX_CNT; i++)
    aux[i] = 0;
  for (i = 0; auxv[i]; i += 2)
    if (auxv[i] < AUX_CNT)
      aux[auxv[i]] = auxv[i + 1];

  for (i = 0; i < DYN_CNT; i++)
    dyn[i] = 0;
  for (i = 0; dynv[i]; i += 2)
    if (dynv[i] < DYN_CNT)
      dyn[dynv[i]] = dynv[i + 1];

  /* If the dynamic linker is invoked as a command, its load
   * address is not available in the aux vector. Instead, compute
   * the load address as the difference between &_DYNAMIC and the
   * virtual address in the PT_DYNAMIC program header. */
  base = aux[AT_BASE];
  if (!base) {
    size_t phnum = aux[AT_PHNUM];
    size_t phentsize = aux[AT_PHENT];
    Phdr *ph = (void *)aux[AT_PHDR];
    for (i = phnum; i--; ph = (void *)((char *)ph + phentsize)) {
      if (ph->p_type == PT_DYNAMIC) {
        base = (size_t)dynv - ph->p_vaddr;
        break;
      }
    }
  }

  /* MIPS uses an ugly packed form for GOT relocations. Since we
   * can't make function calls yet and the code is tiny anyway,
   * it's simply inlined here. */

  rel = (void *)(base + dyn[DT_REL]);
  rel_size = dyn[DT_RELSZ];
  for (; rel_size; rel += 2, rel_size -= 2 * sizeof(size_t)) {
    if (!IS_RELATIVE(rel[1], 0))
      continue;
    size_t *rel_addr = (void *)(base + rel[0]);
    *rel_addr += base;
  }

  rel = (void *)(base + dyn[DT_RELA]);
  rel_size = dyn[DT_RELASZ];
  for (; rel_size; rel += 3, rel_size -= 3 * sizeof(size_t)) {
    if (!IS_RELATIVE(rel[1], 0))
      continue;
    size_t *rel_addr = (void *)(base + rel[0]);
    *rel_addr = base + rel[2];
  }

  if (nod_mmheap_init(nod_mmheap_pool, sizeof(nod_mmheap_pool))) {
    perror("mmheap init failed");
    exit(-1);
  }

  __libc_start_main((int (*)())nod_start_main, *sp, (void *)(sp + 1), init,
                    _fini, 0);
}
