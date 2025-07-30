#ifndef NOD_FILLER_H_
#define NOD_FILLER_H_

#include <linux/ptrace.h>
#include "common.h"

#define SYSCALL_TABLE_SIZE 512
#define NOD_SYSCALL_FILLER_MAX_SNAPS 128

#define FILLER_LIST_MAPPER(FN) \
  FN(accept) \
  FN(accept4) \
  FN(bind) \
  FN(chdir) \
  FN(chmod) \
  FN(clone) \
  FN(clone3) \
  FN(close) \
  FN(connect) \
  FN(creat) \
  FN(dup) \
  FN(dup2) \
  FN(dup3) \
  FN(execve) \
  FN(execveat) \
  FN(exit) \
  FN(exit_group) \
  FN(fchdir) \
  FN(fchmod) \
  FN(fchmodat) \
  FN(fcntl) \
  FN(finit_module) \
  FN(fork) \
  FN(ftruncate) \
  FN(getpeername) \
  FN(init_module) \
  FN(kill) \
  FN(link) \
  FN(linkat) \
  FN(mkdir) \
  FN(mkdirat) \
  FN(mknod) \
  FN(mknodat) \
  FN(mmap) \
  FN(mprotect) \
  FN(open) \
  FN(openat) \
  FN(pipe) \
  FN(pipe2) \
  FN(pread64) \
  FN(preadv) \
  FN(preadv2) \
  FN(ptrace) \
  FN(pwrite64) \
  FN(pwritev) \
  FN(pwritev2) \
  FN(read) \
  FN(readv) \
  FN(recvfrom) \
  FN(recvmsg) \
  FN(recvmmsg) \
  FN(rename) \
  FN(renameat) \
  FN(renameat2) \
  FN(rmdir) \
  FN(sendmsg) \
  FN(sendmmsg) \
  FN(sendto) \
  FN(setfsgid) \
  FN(setfsuid) \
  FN(setgid) \
  FN(setregid) \
  FN(setresgid) \
  FN(setresuid) \
  FN(setreuid) \
  FN(setuid) \
  FN(socket) \
  FN(socketpair) \
  FN(splice) \
  FN(symlink) \
  FN(symlinkat) \
  FN(tee) \
  FN(tgkill) \
  FN(tkill) \
  FN(truncate) \
  FN(unlink) \
  FN(unlinkat) \
  FN(vfork) \
  FN(vmsplice) \
  FN(write) \
  FN(writev)

typedef int (*nod_syscall_filler_fn)(struct pt_regs *regs, nod_event_hdr_t *evt);
extern const nod_syscall_filler_fn nod_syscall_filler_table[];

#define FILLER_PROTOTYPE_FN(x)  int f_##x(struct pt_regs *regs, nod_event_hdr_t *evt);
FILLER_LIST_MAPPER(FILLER_PROTOTYPE_FN)
#undef FILLER_PROTOTYPE_FN
int f_ni(struct pt_regs *regs, nod_event_hdr_t *evt); // empty filler for unsupported syscalls

#endif // NOD_FILLER_H_
