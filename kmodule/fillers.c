#include <asm/syscall.h>
#include <asm/unistd.h>
#include <linux/audit.h>
#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/ip.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/quota.h>
#include <linux/tcp.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/af_unix.h>
#include <net/compat.h>
#include <net/sock.h>

#include "common.h"
#include "fillers.h"
#include "nodrop.h"

#define EVENT_TABLE_MAP(x) [__NR_##x] = f_##x,
const nod_syscall_filler_fn nod_syscall_filler_table[SYSCALL_TABLE_SIZE] = {
    [0 ... SYSCALL_TABLE_SIZE - 1] = NULL,
    [__NR_ioctl] = f_ni,
    // TODO: execve and execveat are not supported yet
    [__NR_execve] = f_ni,
    [__NR_execveat] = f_ni,
    FILLER_LIST_MAPPER(EVENT_TABLE_MAP)};
#undef EVENT_TABLE_ITEM

static inline int add_64(nod_event_hdr_t *evt, u64 v, int idx) {
  char len_bit, *buf;
  u8 v0;
  u16 v1;
  u32 v2;

  ASSERT(idx >= 1 && idx <= 4);

  buf = &evt->args[evt->len];
  v0 = v & 0xff;
  if (v0 == v) {
    *(u8 *)buf = v0;
    len_bit = 0;
    goto out;
  }

  v1 = v & 0xffff;
  if (v1 == v) {
    *(u16 *)buf = v1;
    len_bit = 1;
    goto out;
  }

  v2 = v & 0xffffffff;
  if (v2 == v) {
    *(u32 *)buf = v2;
    len_bit = 2;
    goto out;
  }

  *(u64 *)buf = v;
  len_bit = 3;

out:
  evt->arg_len |= (len_bit << ((idx - 1) << 1));
  return (1 << len_bit);
}

static inline int add_data(nod_event_hdr_t *evt, void *data, size_t size) {
  nod_event_data_t *data_evt = (nod_event_data_t *)&evt->args[evt->len];
  memmove(data_evt->data, data, size);
  data_evt->len = (uint8_t)size;
  return sizeof(nod_event_data_t) + size;
}

static inline int add_data_user(nod_event_hdr_t *evt, void __user *data,
                                size_t size) {
  nod_event_data_t *data_evt = (nod_event_data_t *)&evt->args[evt->len];
  copy_from_user(data_evt->data, data, size);
  data_evt->len = (uint8_t)size;
  return sizeof(nod_event_data_t) + size;
}

static inline int add_string_user(nod_event_hdr_t *evt,
                                  const char __user *str) {
  nod_event_data_t *data_evt = (nod_event_data_t *)&evt->args[evt->len];
  long size =
      strncpy_from_user(data_evt->data, str, NOD_SYSCALL_FILLER_MAX_SNAPS);
  if (size <= 0)
    return 0;

  data_evt->len = size + 1; // '\0' is included
  return sizeof(nod_event_data_t) + size + 1;
}

#define NOD_FILLER(x) int f_##x(struct pt_regs *regs, nod_event_hdr_t *evt)

NOD_FILLER(ni) { return 0; }

// File operations
NOD_FILLER(open) {
  const char __user *filename;
  long flags, mode;
  int ret_val;
  u64 md_flags;

  filename = (const char __user *)nod_get_syscall_argument(regs, 1);
  flags = nod_get_syscall_argument(regs, 2);
  mode = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk does)
  // Pack mode and flags like eauditk: ((u64)mode << 32) | flags
  md_flags = ((u64)mode << 32) | flags;
  evt->len += add_64(evt, md_flags, 1); // packed mode+flags
  evt->len += add_64(evt, AT_FDCWD, 2); // dirfd
  evt->len += add_64(evt, ret_val, 3);  // return value
  // Record filename string last
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

NOD_FILLER(openat) {
  const char __user *filename;
  long dirfd, flags, mode;
  int ret_val;
  u64 md_flags;

  dirfd = nod_get_syscall_argument(regs, 1);
  filename = (const char __user *)nod_get_syscall_argument(regs, 2);
  flags = nod_get_syscall_argument(regs, 3);
  mode = nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk does)
  // Pack mode and flags like eauditk: ((u64)mode << 32) | flags
  md_flags = ((u64)mode << 32) | flags;
  evt->len += add_64(evt, md_flags, 1); // packed mode+flags
  evt->len += add_64(evt, dirfd, 2);    // dirfd
  evt->len += add_64(evt, ret_val, 3);  // return value
  // Record filename string last
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

NOD_FILLER(creat) {
  const char __user *pathname;
  long mode;
  int ret_val;
  u64 md_flags;

  pathname = (const char __user *)nod_get_syscall_argument(regs, 1);
  mode = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk does)
  // Pack mode and flags like eauditk: ((u64)mode << 32) | flags
  md_flags = ((u64)mode << 32) | (O_CREAT | O_WRONLY | O_TRUNC);
  evt->len += add_64(evt, md_flags, 1); // packed mode+flags
  evt->len += add_64(evt, AT_FDCWD, 2); // dirfd
  evt->len += add_64(evt, ret_val, 3);  // return value
  // Record pathname string last
  evt->len += add_string_user(evt, pathname);
  return evt->len;
}

NOD_FILLER(close) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(read) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(write) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(readv) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(writev) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(pread64) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(pwrite64) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(preadv) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(pwritev) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(preadv2) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(pwritev2) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

// File descriptor operations
NOD_FILLER(dup) {
  long oldfd, newfd;

  oldfd = nod_get_syscall_argument(regs, 1);
  newfd = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, oldfd, 1);
  evt->len += add_64(evt, newfd, 2);
  return evt->len;
}

NOD_FILLER(dup2) {
  long oldfd, newfd;

  oldfd = nod_get_syscall_argument(regs, 1);
  newfd = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, oldfd, 1);
  evt->len += add_64(evt, newfd, 2);
  return evt->len;
}

NOD_FILLER(dup3) {
  long oldfd, newfd;

  oldfd = nod_get_syscall_argument(regs, 1);
  newfd = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, oldfd, 1);
  evt->len += add_64(evt, newfd, 2);
  return evt->len;
}

NOD_FILLER(fcntl) {
  long fd, cmd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  cmd = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, cmd, 2);
  evt->len += add_64(evt, ret_val, 3);
  return evt->len;
}

// Pipe operations
NOD_FILLER(pipe) {
  int rc;
  int __user *fildes;
  int ret_val;
  long fds_packed = 0;

  fildes = (int __user *)nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  // If successful, read and pack the two file descriptors like eauditk
  if (ret_val == 0 && fildes) {
    int fds[2];
    rc = copy_from_user(fds, fildes, sizeof(fds));
    if (rc < 0) {
      return rc; // failed to read fds, return error
    }
    // Pack two fds into one 64-bit value (like eauditk pipe_exit does)
    fds_packed = ((long)fds[0]) | (((long)fds[1]) << 32);
    evt->len += add_64(evt, fds_packed, 1);
  } else {
    // Failed pipe call, record error return value
    evt->len += add_64(evt, ret_val, 1);
  }
  return evt->len;
}

NOD_FILLER(pipe2) {
  int rc;
  int __user *fildes;
  int ret_val;
  long fds_packed = 0;

  fildes = (int __user *)nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  // If successful, read and pack the two file descriptors like eauditk
  if (ret_val == 0 && fildes) {
    int fds[2];
    rc = copy_from_user(fds, fildes, sizeof(fds));
    if (rc < 0) {
      return rc; // failed to read fds, return error
    }
    // Pack two fds into one 64-bit value (like eauditk pipe_exit does)
    fds_packed = ((long)fds[0]) | (((long)fds[1]) << 32);
    evt->len += add_64(evt, fds_packed, 1);
  } else {
    // Failed pipe call, record error return value
    evt->len += add_64(evt, ret_val, 1);
  }
  return evt->len;
}

// Network operations
NOD_FILLER(socket) {
  long domain, type, protocol;
  int ret_val;

  domain = nod_get_syscall_argument(regs, 1);
  type = nod_get_syscall_argument(regs, 2);
  protocol = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, domain, 1);
  evt->len += add_64(evt, type, 2);
  evt->len += add_64(evt, protocol, 3);
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(socketpair) {
  int rc;
  int __user *usockvec;
  int ret_val;
  long fds_packed = 0;

  usockvec = (int __user *)nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  // If successful, read and pack the two socket fds like eauditk pipe_exit does
  if (ret_val == 0 && usockvec) {
    int fds[2];
    rc = copy_from_user(fds, usockvec, sizeof(fds));
    if (rc < 0) {
      return rc;
    }
    // Pack two fds into one 64-bit value (like eauditk pipe_exit does)
    fds_packed = ((long)fds[0]) | (((long)fds[1]) << 32);
    evt->len += add_64(evt, fds_packed, 1);
  } else {
    // Failed socketpair call, record error return value
    evt->len += add_64(evt, ret_val, 1);
  }
  return evt->len;
}

NOD_FILLER(accept) {
  long sockfd;
  struct sockaddr __user *addr;
  int __user *addrlen_ptr;
  int ret_val, addrlen, rc;

  sockfd = nod_get_syscall_argument(regs, 1);
  addr = (struct sockaddr __user *)nod_get_syscall_argument(regs, 2);
  addrlen_ptr = (int __user *)nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: fd, ret)
  evt->len += add_64(evt, sockfd, 1);  // original socket fd
  evt->len += add_64(evt, ret_val, 2); // return value (new socket fd or error)

  // If successful and address info is available, read and record it
  if (ret_val >= 0 && addr && addrlen) {
    rc = copy_from_user(&addrlen, addrlen_ptr, sizeof(addrlen));
    if (rc < 0) {
      return rc; // failed to read addrlen, return error
    }
    if (addrlen > 0) {
      // Limit address length to reasonable size to avoid excessive data
      evt->len += add_data_user(evt, (void __user *)addr,
                                MIN(addrlen, NOD_SYSCALL_FILLER_MAX_SNAPS));
    }
  }
  return evt->len;
}

NOD_FILLER(accept4) {
  long sockfd;
  struct sockaddr __user *addr;
  int __user *addrlen_ptr;
  int ret_val, addrlen, rc;

  sockfd = nod_get_syscall_argument(regs, 1);
  addr = (struct sockaddr __user *)nod_get_syscall_argument(regs, 2);
  addrlen_ptr = (int __user *)nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: fd, ret)
  evt->len += add_64(evt, sockfd, 1);  // original socket fd
  evt->len += add_64(evt, ret_val, 2); // return value (new socket fd or error)

  // If successful and address info is available, read and record it
  if (ret_val >= 0 && addr && addrlen) {
    rc = copy_from_user(&addrlen, addrlen_ptr, sizeof(addrlen));
    if (rc < 0) {
      return rc; // failed to read addrlen, return error
    }
    if (addrlen > 0) {
      // Limit address length to reasonable size to avoid excessive data
      evt->len += add_data_user(evt, (void __user *)addr,
                                MIN(addrlen, NOD_SYSCALL_FILLER_MAX_SNAPS));
    }
  }
  return evt->len;
}

NOD_FILLER(connect) {
  long sockfd, addrlen;
  struct sockaddr __user *addr;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  addr = (struct sockaddr __user *)nod_get_syscall_argument(regs, 2);
  addrlen = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: fd, ret)
  evt->len += add_64(evt, sockfd, 1);  // socket fd
  evt->len += add_64(evt, ret_val, 2); // return value

  // Record address data if available (like eauditk does)
  if (addr && addrlen > 0) {
    // Limit address length to reasonable size to avoid excessive data
    evt->len += add_data_user(evt, (void __user *)addr,
                              MIN(addrlen, NOD_SYSCALL_FILLER_MAX_SNAPS));
  }
  return evt->len;
}

NOD_FILLER(bind) {
  long sockfd, addrlen;
  struct sockaddr __user *addr;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  addr = (struct sockaddr __user *)nod_get_syscall_argument(regs, 2);
  addrlen = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: fd, ret)
  evt->len += add_64(evt, sockfd, 1);  // socket fd
  evt->len += add_64(evt, ret_val, 2); // return value

  // Record address data if available (like eauditk does)
  if (addr && addrlen > 0) {
    // Limit address length to reasonable size to avoid excessive data
    evt->len += add_data_user(evt, (void __user *)addr,
                              MIN(addrlen, NOD_SYSCALL_FILLER_MAX_SNAPS));
  }
  return evt->len;
}

NOD_FILLER(sendto) {
  long sockfd, buf, len;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  buf = nod_get_syscall_argument(regs, 2);
  len = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record fd and return value first (numeric data)
  evt->len += add_64(evt, sockfd, 1);  // socket fd
  evt->len += add_64(evt, ret_val, 2); // return value

  // Record buffer data last (like eauditk write_entry1)
  if (buf && len > 0 && ret_val > 0) {
    evt->len += add_data_user(evt, (void __user *)buf, len); // send buffer data
  }
  return evt->len;
}

NOD_FILLER(sendmsg) {
  long sockfd;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, sockfd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(recvfrom) {
  long sockfd, buf, len, flags;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  buf = nod_get_syscall_argument(regs, 2);
  len = nod_get_syscall_argument(regs, 3);
  flags = nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: fd, ret)
  evt->len += add_64(evt, sockfd, 1);  // socket fd
  evt->len += add_64(evt, ret_val, 2); // return value

  // Record receive buffer data last (like eauditk read_entry1)
  if (buf && len > 0 && ret_val > 0) {
    evt->len += add_data_user(evt, (void __user *)buf,
                              MIN(ret_val, len)); // received data
  }
  return evt->len;
}

NOD_FILLER(recvmsg) {
  long sockfd;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, sockfd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

// Memory operations
NOD_FILLER(mmap) {
  long addr, length, prot, flags, fd, offset;
  long ret_val;
  long encoded_prot, packed_flags;
  int file_backed, exec_perm, mmap_imp;

  addr = nod_get_syscall_argument(regs, 1);
  length = nod_get_syscall_argument(regs, 2);
  prot = nod_get_syscall_argument(regs, 3);
  flags = nod_get_syscall_argument(regs, 4);
  fd = nod_get_syscall_argument(regs, 5);
  offset = nod_get_syscall_argument(regs, 6);
  ret_val = nod_get_syscall_ret(regs);

  // Security filtering like eauditk: only file-backed or executable mmaps
  file_backed = ((fd >= 0) && !(flags & MAP_ANONYMOUS));
  exec_perm = (prot & PROT_EXEC);
  mmap_imp = file_backed || exec_perm;

  // Skip unimportant mmaps (like eauditk does)
  if (!mmap_imp) {
    return 0;
  }

  // Encode protection bits the same way as file permissions (like eauditk)
  encoded_prot = (((prot & PROT_READ) != 0) << 2) |
                 (((prot & PROT_WRITE) != 0) << 1) | ((prot & PROT_EXEC) != 0);

  // Pack flags and encoded protection like eauditk: (flags << 32) | prot
  packed_flags = (flags << 32) | encoded_prot;

  // Record like eauditk: addr, len, packed_flags, then fd and ret
  evt->len += add_64(evt, addr, 1);         // address
  evt->len += add_64(evt, length, 2);       // length
  evt->len += add_64(evt, packed_flags, 3); // packed flags+prot
  evt->len += add_64(evt, fd, 4);           // file descriptor
  // store return value last as a 64-bit value
  evt->len += add_data(evt, (void *)&ret_val, sizeof(ret_val));
  return evt->len;
}

NOD_FILLER(mprotect) {
  long addr, len, prot;
  int ret_val;
  long encoded_prot;

  addr = nod_get_syscall_argument(regs, 1);
  len = nod_get_syscall_argument(regs, 2);
  prot = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Only record if security-relevant: execute permission (like eauditk does)
  if (!(prot & PROT_EXEC)) {
    return 0;
  }

  // Encode protection bits the same way as file permissions (like eauditk)
  encoded_prot = (((prot & PROT_READ) != 0) << 2) |
                 (((prot & PROT_WRITE) != 0) << 1) | ((prot & PROT_EXEC) != 0);

  // Record like eauditk: start, len, (prot << 32) | ret
  evt->len += add_64(evt, addr, 1); // start address
  evt->len += add_64(evt, len, 2);  // length
  evt->len +=
      add_64(evt, (encoded_prot << 32) | ((u32)ret_val), 3); // packed prot+ret
  return evt->len;
}

// Process control operations
NOD_FILLER(fork) {
  int ret_val;

  ret_val = nod_get_syscall_ret(regs);
  evt->len += add_64(evt, ret_val, 1);
  return evt->len;
}

NOD_FILLER(vfork) {
  int ret_val;

  ret_val = nod_get_syscall_ret(regs);
  evt->len += add_64(evt, ret_val, 1);
  return evt->len;
}

// TODO: execve and execveat cannot be logged at the syscall exit as their arguments does not exists
// after the memory address is replaced.
//
// /* both execve and execveat are collected at the syscall enter, instead of
// the
//  * syscall exit */
// NOD_FILLER(execve) {
//   const char __user *filename;
//   const char __user **argv;
//   const char __user **envp;
//   char __user *argv_ptr;
//   long packed_flags_fd;
//   int rc;
//
//   filename = (const char __user *)nod_get_syscall_argument(regs, 1);
//   argv = (const char __user **)nod_get_syscall_argument(regs, 2);
//   envp = (const char __user **)nod_get_syscall_argument(regs, 3);
//
//   // Pack flags and fd like eauditk: flags=0, fd=AT_FDCWD for execve
//   packed_flags_fd = ((long)0 << 32) | AT_FDCWD;
//
//   // Record numeric arguments first (like eauditk: flags+fd packed)
//   evt->len += add_64(evt, packed_flags_fd, 1); // packed flags+fd
//   // Record filename string last
//   evt->len += add_string_user(evt, filename);
//   // Record argv
//   do {
//     rc = copy_from_user(&argv_ptr, argv, sizeof(argv_ptr));
//     if (rc < 0) {
//       return rc;
//     }
//     if (argv_ptr == NULL) {
//       break; // end of argv
//     }
//     evt->len += add_string_user(evt, argv_ptr);
//   } while (argv++);
//   // envp is ignored
//   return evt->len;
// }
//
// NOD_FILLER(execveat) {
//   const char __user *filename;
//   const char __user **argv;
//   const char __user **envp;
//   char __user *argv_ptr;
//   long dirfd, flags, packed_flags_fd;
//   int rc;
//
//   dirfd = nod_get_syscall_argument(regs, 1);
//   filename = (const char __user *)nod_get_syscall_argument(regs, 2);
//   argv = (const char __user **)nod_get_syscall_argument(regs, 3);
//   envp = (const char __user **)nod_get_syscall_argument(regs, 4);
//   flags = nod_get_syscall_argument(regs, 5);
//
//   // Pack flags and fd like eauditk: (flags << 32) | fd
//   packed_flags_fd = (flags << 32) | dirfd;
//
//   // Record numeric arguments first (like eauditk: flags+fd packed)
//   evt->len += add_64(evt, packed_flags_fd, 1); // packed flags+fd
//   // Record filename string last
//   evt->len += add_string_user(evt, filename);
//   // Record argv
//   do {
//     rc = copy_from_user(&argv_ptr, argv, sizeof(argv_ptr));
//     if (rc < 0) {
//       return rc;
//     }
//     if (argv_ptr == NULL) {
//       break; // end of argv
//     }
//     evt->len += add_string_user(evt, argv_ptr);
//   } while (argv++);
//   // envp is ignored
//   return evt->len;
// }

NOD_FILLER(exit) {
  long status;

  status = nod_get_syscall_argument(regs, 1);
  evt->len += add_64(evt, status, 1);
  return evt->len;
}

NOD_FILLER(exit_group) {
  long status;

  status = nod_get_syscall_argument(regs, 1);
  evt->len += add_64(evt, status, 1);
  return evt->len;
}

NOD_FILLER(kill) {
  long pid, sig;
  int ret_val;
  long packed_pid;

  pid = nod_get_syscall_argument(regs, 1);
  sig = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Pack pid like eauditk: ((pid<<32)|pid)
  packed_pid = ((pid << 32) | pid);

  evt->len += add_64(evt, packed_pid, 1); // packed pid
  evt->len += add_64(evt, sig, 2);        // signal
  evt->len += add_64(evt, ret_val, 3);    // return value
  return evt->len;
}

NOD_FILLER(tkill) {
  long tid, sig;
  int ret_val;

  tid = nod_get_syscall_argument(regs, 1);
  sig = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, tid, 1);
  evt->len += add_64(evt, sig, 2);
  evt->len += add_64(evt, ret_val, 3);
  return evt->len;
}

NOD_FILLER(tgkill) {
  long tgid, tid, sig;
  int ret_val;
  long packed_ids;

  tgid = nod_get_syscall_argument(regs, 1);
  tid = nod_get_syscall_argument(regs, 2);
  sig = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Pack tgid and tid like eauditk: ((tgid<<32)|tid)
  packed_ids = ((tgid << 32) | tid);

  evt->len += add_64(evt, packed_ids, 1); // packed tgid+tid
  evt->len += add_64(evt, sig, 2);        // signal
  evt->len += add_64(evt, ret_val, 3);    // return value
  return evt->len;
}

// Permission operations
NOD_FILLER(setuid) {
  long uid;
  int ret_val;

  uid = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, -1, 1);
  evt->len += add_64(evt, uid, 2);
  evt->len += add_64(evt, -1, 3); // -1 for euid (not used)
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(setgid) {
  long gid;
  int ret_val;

  gid = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, -1, 1);
  evt->len += add_64(evt, gid, 2);
  evt->len += add_64(evt, -1, 3); // -1 for euid (not used)
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(setreuid) {
  long ruid, euid;
  int ret_val;

  ruid = nod_get_syscall_argument(regs, 1);
  euid = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, ruid, 1);
  evt->len += add_64(evt, euid, 2);
  evt->len += add_64(evt, -1, 3); // -1 for suid (not used)
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(setregid) {
  long rgid, egid;
  int ret_val;

  rgid = nod_get_syscall_argument(regs, 1);
  egid = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, rgid, 1);
  evt->len += add_64(evt, egid, 2);
  evt->len += add_64(evt, -1, 3); // -1 for sgid (not used)
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(setresuid) {
  long ruid, euid, suid;
  int ret_val;

  ruid = nod_get_syscall_argument(regs, 1);
  euid = nod_get_syscall_argument(regs, 2);
  suid = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, ruid, 1);
  evt->len += add_64(evt, euid, 2);
  evt->len += add_64(evt, suid, 3);
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(setresgid) {
  long rgid, egid, sgid;
  int ret_val;

  rgid = nod_get_syscall_argument(regs, 1);
  egid = nod_get_syscall_argument(regs, 2);
  sgid = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, rgid, 1);
  evt->len += add_64(evt, egid, 2);
  evt->len += add_64(evt, sgid, 3);
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

// File system operations
NOD_FILLER(unlink) {
  const char __user *pathname;
  int ret_val;

  pathname = (const char __user *)nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: AT_FDCWD)
  evt->len += add_64(evt, AT_FDCWD, 1); // dirfd
  evt->len += add_64(evt, ret_val, 2);  // return value
  // Record pathname string last
  evt->len += add_string_user(evt, pathname);
  return evt->len;
}

NOD_FILLER(unlinkat) {
  const char __user *pathname;
  long dirfd;
  int ret_val;

  dirfd = nod_get_syscall_argument(regs, 1);
  pathname = (const char __user *)nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: dirfd)
  evt->len += add_64(evt, dirfd, 1);   // dirfd
  evt->len += add_64(evt, ret_val, 2); // return value
  // Record pathname string last
  evt->len += add_string_user(evt, pathname);
  return evt->len;
}

NOD_FILLER(mkdir) {
  const char __user *pathname;
  long mode;
  int ret_val;

  pathname = (const char __user *)nod_get_syscall_argument(regs, 1);
  mode = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: AT_FDCWD, mode)
  evt->len += add_64(evt, AT_FDCWD, 1); // dirfd
  evt->len += add_64(evt, mode, 2);     // mode
  evt->len += add_64(evt, ret_val, 3);  // return value
  // Record pathname string last
  evt->len += add_string_user(evt, pathname);
  return evt->len;
}

NOD_FILLER(mkdirat) {
  const char __user *pathname;
  long dirfd, mode;
  int ret_val;

  dirfd = nod_get_syscall_argument(regs, 1);
  pathname = (const char __user *)nod_get_syscall_argument(regs, 2);
  mode = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: dirfd, mode)
  evt->len += add_64(evt, dirfd, 1);   // dirfd
  evt->len += add_64(evt, mode, 2);    // mode
  evt->len += add_64(evt, ret_val, 3); // return value
  // Record pathname string last
  evt->len += add_string_user(evt, pathname);
  return evt->len;
}

NOD_FILLER(rmdir) {
  const char __user *pathname;
  int ret_val;

  pathname = (const char __user *)nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first
  evt->len += add_64(evt, ret_val, 1); // return value
  // Record pathname string last
  evt->len += add_string_user(evt, pathname);
  return evt->len;
}

NOD_FILLER(link) {
  const char __user *oldname, *newname;
  int ret_val;

  oldname = (const char __user *)nod_get_syscall_argument(regs, 1);
  newname = (const char __user *)nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: AT_FDCWD, AT_FDCWD, 0)
  evt->len += add_64(evt, AT_FDCWD, 1); // old_dirfd
  evt->len += add_64(evt, AT_FDCWD, 2); // new_dirfd
  evt->len += add_64(evt, 0, 3);        // flags
  evt->len += add_64(evt, ret_val, 4);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(linkat) {
  const char __user *oldname, *newname;
  long olddirfd, newdirfd, flags;
  int ret_val;

  olddirfd = nod_get_syscall_argument(regs, 1);
  oldname = (const char __user *)nod_get_syscall_argument(regs, 2);
  newdirfd = nod_get_syscall_argument(regs, 3);
  newname = (const char __user *)nod_get_syscall_argument(regs, 4);
  flags = nod_get_syscall_argument(regs, 5);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: olddfd, newdfd, flags)
  evt->len += add_64(evt, olddirfd, 1); // olddfd
  evt->len += add_64(evt, newdirfd, 2); // newdfd
  evt->len += add_64(evt, flags, 3);    // flags
  evt->len += add_64(evt, ret_val, 4);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(symlink) {
  const char __user *oldname, *newname;
  int ret_val;

  oldname = (const char __user *)nod_get_syscall_argument(regs, 1);
  newname = (const char __user *)nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: AT_FDCWD)
  evt->len += add_64(evt, AT_FDCWD, 1); // dirfd
  evt->len += add_64(evt, ret_val, 2);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(symlinkat) {
  const char __user *oldname, *newname;
  long newdirfd;
  int ret_val;

  oldname = (const char __user *)nod_get_syscall_argument(regs, 1);
  newdirfd = nod_get_syscall_argument(regs, 2);
  newname = (const char __user *)nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: newdfd)
  evt->len += add_64(evt, newdirfd, 1); // newdfd
  evt->len += add_64(evt, ret_val, 2);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(rename) {
  const char __user *oldname, *newname;
  int ret_val;

  oldname = (const char __user *)nod_get_syscall_argument(regs, 1);
  newname = (const char __user *)nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: AT_FDCWD, AT_FDCWD, 0)
  evt->len += add_64(evt, AT_FDCWD, 1); // old_dirfd
  evt->len += add_64(evt, AT_FDCWD, 2); // new_dirfd
  evt->len += add_64(evt, 0, 3);        // flags
  evt->len += add_64(evt, ret_val, 4);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(renameat) {
  const char __user *oldname, *newname;
  long olddirfd, newdirfd;
  int ret_val;

  olddirfd = nod_get_syscall_argument(regs, 1);
  oldname = (const char __user *)nod_get_syscall_argument(regs, 2);
  newdirfd = nod_get_syscall_argument(regs, 3);
  newname = (const char __user *)nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: olddfd, newdfd, 0)
  evt->len += add_64(evt, olddirfd, 1); // olddfd
  evt->len += add_64(evt, newdirfd, 2); // newdfd
  evt->len += add_64(evt, 0, 3);        // flags (0 for renameat)
  evt->len += add_64(evt, ret_val, 4);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(renameat2) {
  const char __user *oldname, *newname;
  long olddirfd, newdirfd, flags;
  int ret_val;

  olddirfd = nod_get_syscall_argument(regs, 1);
  oldname = (const char __user *)nod_get_syscall_argument(regs, 2);
  newdirfd = nod_get_syscall_argument(regs, 3);
  newname = (const char __user *)nod_get_syscall_argument(regs, 4);
  flags = nod_get_syscall_argument(regs, 5);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: olddfd, newdfd, flags)
  evt->len += add_64(evt, olddirfd, 1); // olddfd
  evt->len += add_64(evt, newdirfd, 2); // newdfd
  evt->len += add_64(evt, flags, 3);    // flags
  evt->len += add_64(evt, ret_val, 4);  // return value
  // Record strings last (oldname first, then newname)
  evt->len += add_string_user(evt, oldname);
  evt->len += add_string_user(evt, newname);
  return evt->len;
}

NOD_FILLER(mknod) {
  const char __user *filename;
  long mode, dev;
  int ret_val;

  filename = (const char __user *)nod_get_syscall_argument(regs, 1);
  mode = nod_get_syscall_argument(regs, 2);
  dev = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: AT_FDCWD, mode, dev)
  evt->len += add_64(evt, AT_FDCWD, 1); // dirfd
  evt->len += add_64(evt, mode, 2);     // mode
  evt->len += add_64(evt, dev, 3);      // dev
  evt->len += add_64(evt, ret_val, 4);  // return value
  // Record filename string last
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

NOD_FILLER(mknodat) {
  const char __user *filename;
  long dirfd, mode, dev;
  int ret_val;

  dirfd = nod_get_syscall_argument(regs, 1);
  filename = (const char __user *)nod_get_syscall_argument(regs, 2);
  mode = nod_get_syscall_argument(regs, 3);
  dev = nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: dirfd, mode, dev)
  evt->len += add_64(evt, dirfd, 1);   // dirfd
  evt->len += add_64(evt, mode, 2);    // mode
  evt->len += add_64(evt, dev, 3);     // dev
  evt->len += add_64(evt, ret_val, 4); // return value
  // Record filename string last
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

NOD_FILLER(chdir) {
  const char __user *filename;
  int ret_val;

  filename = (const char __user *)nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first
  evt->len += add_64(evt, ret_val, 1); // return value
  // Record filename string last (like eauditk: log_sc_str_long0)
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

NOD_FILLER(fchdir) {
  long fd;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(truncate) {
  const char __user *path;
  long length;
  int ret_val;

  path = (const char __user *)nod_get_syscall_argument(regs, 1);
  length = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: length)
  evt->len += add_64(evt, length, 1);  // length
  evt->len += add_64(evt, ret_val, 2); // return value
  // Record path string last
  evt->len += add_string_user(evt, path);
  return evt->len;
}

NOD_FILLER(ftruncate) {
  long fd, length;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  length = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, length, 2);
  evt->len += add_64(evt, ret_val, 3);
  return evt->len;
}

// Additional network operations
NOD_FILLER(getpeername) {
  long sockfd;
  struct sockaddr __user *addr;
  int __user *addrlen_ptr;
  int ret_val, addrlen, rc;

  sockfd = nod_get_syscall_argument(regs, 1);
  addr = (struct sockaddr __user *)nod_get_syscall_argument(regs, 2);
  addrlen_ptr = (int __user *)nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: fd, ret)
  evt->len += add_64(evt, sockfd, 1);  // socket fd
  evt->len += add_64(evt, ret_val, 2); // return value

  // If successful and address info is available, read and record it (like
  // accept)
  if (ret_val >= 0 && addr && addrlen_ptr) {
    rc = copy_from_user(&addrlen, addrlen_ptr, sizeof(addrlen));
    if (rc < 0) {
      return rc; // failure to read addrlen
    }
    if (addrlen > 0) {
      // Limit address length to reasonable size to avoid excessive data
      evt->len += add_data_user(evt, (void __user *)addr,
                                MIN(addrlen, NOD_SYSCALL_FILLER_MAX_SNAPS));
    }
  }
  return evt->len;
}

NOD_FILLER(recvmmsg) {
  long sockfd;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, sockfd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

NOD_FILLER(sendmmsg) {
  long sockfd;
  int ret_val;

  sockfd = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, sockfd, 1);
  evt->len += add_64(evt, ret_val, 2);
  return evt->len;
}

// Splice operations
NOD_FILLER(tee) {
  long fd_in, fd_out, len, flags;
  int ret_val;

  fd_in = nod_get_syscall_argument(regs, 1);
  fd_out = nod_get_syscall_argument(regs, 2);
  len = nod_get_syscall_argument(regs, 3);
  flags = nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd_in, 1);
  evt->len += add_64(evt, fd_out, 2);
  evt->len += add_64(evt, len, 3);
  evt->len += add_64(evt, flags, 4);
  return evt->len;
}

NOD_FILLER(splice) {
  long fd_in, fd_out, len, flags;
  int ret_val;

  fd_in = nod_get_syscall_argument(regs, 1);
  fd_out = nod_get_syscall_argument(regs, 3);
  len = nod_get_syscall_argument(regs, 5);
  flags = nod_get_syscall_argument(regs, 6);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd_in, 1);
  evt->len += add_64(evt, fd_out, 2);
  evt->len += add_64(evt, len, 3);
  evt->len += add_64(evt, flags, 4);
  return evt->len;
}

NOD_FILLER(vmsplice) {
  long fd, flags;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  flags = nod_get_syscall_argument(regs, 4);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, flags, 2);
  evt->len += add_64(evt, ret_val, 3);
  return evt->len;
}

// Process debugging
NOD_FILLER(ptrace) {
  long request, pid;
  int ret_val;

  request = nod_get_syscall_argument(regs, 1);
  pid = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, request, 1);
  evt->len += add_64(evt, pid, 2);
  evt->len += add_64(evt, ret_val, 3);
  return evt->len;
}

// File permission operations
NOD_FILLER(chmod) {
  const char __user *filename;
  long mode;
  int ret_val;

  filename = (const char __user *)nod_get_syscall_argument(regs, 1);
  mode = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: mode, AT_FDCWD)
  evt->len += add_64(evt, mode, 1);     // mode
  evt->len += add_64(evt, AT_FDCWD, 2); // dirfd
  evt->len += add_64(evt, ret_val, 3);  // return value
  // Record filename string last
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

NOD_FILLER(fchmod) {
  long fd, mode;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  mode = nod_get_syscall_argument(regs, 2);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, fd, 1);
  evt->len += add_64(evt, mode, 2);
  evt->len += add_64(evt, ret_val, 3);
  return evt->len;
}

NOD_FILLER(fchmodat) {
  const char __user *filename;
  long dirfd, mode;
  int ret_val;

  dirfd = nod_get_syscall_argument(regs, 1);
  filename = (const char __user *)nod_get_syscall_argument(regs, 2);
  mode = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record numeric arguments first (like eauditk: mode, dirfd)
  evt->len += add_64(evt, mode, 1);    // mode
  evt->len += add_64(evt, dirfd, 2);   // dirfd
  evt->len += add_64(evt, ret_val, 3); // return value
  // Record filename string last
  evt->len += add_string_user(evt, filename);
  return evt->len;
}

// Filesystem UID/GID operations
NOD_FILLER(setfsgid) {
  long fsgid;
  int ret_val;

  fsgid = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, -1, 1);
  evt->len += add_64(evt, fsgid, 2);
  evt->len += add_64(evt, -1, 3); // -1 for egid (not used)
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

NOD_FILLER(setfsuid) {
  long fsuid;
  int ret_val;

  fsuid = nod_get_syscall_argument(regs, 1);
  ret_val = nod_get_syscall_ret(regs);

  evt->len += add_64(evt, -1, 1);
  evt->len += add_64(evt, fsuid, 2);
  evt->len += add_64(evt, -1, 3); // -1 for egid (not used)
  evt->len += add_64(evt, ret_val, 4);
  return evt->len;
}

// Process creation operations
NOD_FILLER(clone) {
  long flags;
  int ret_val;

  flags = nod_get_syscall_argument(regs, 3); // clone_flags
  ret_val = nod_get_syscall_ret(regs);

  // Record only clone_flags like eauditk does
  evt->len += add_64(evt, flags, 1);   // clone_flags
  evt->len += add_64(evt, ret_val, 2); // return value
  return evt->len;
}

NOD_FILLER(clone3) {
  void __user *uargs;
  long flags = 0; // default value like eauditk
  int ret_val;

  uargs = (void __user *)nod_get_syscall_argument(regs, 1); // struct pointer
  ret_val = nod_get_syscall_ret(regs);

  // The first element of cl_args in clone3 is flags
  if (uargs) {
    copy_from_user(&flags, uargs, sizeof(flags));
  }

  // Record flags like eauditk does
  evt->len += add_64(evt, flags, 1);   // flags from struct
  evt->len += add_64(evt, ret_val, 2); // return value
  return evt->len;
}

// Module operations
NOD_FILLER(init_module) {
  const char __user *umod;
  const char __user *uargs;
  long len;
  int ret_val;

  umod = (const char __user *)nod_get_syscall_argument(regs, 1);
  len = nod_get_syscall_argument(regs, 2);
  uargs = (const char __user *)nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record like eauditk: log_sc_str2_long1(uargs, umod, len)
  evt->len += add_64(evt, len, 1);     // length (long parameter)
  evt->len += add_64(evt, ret_val, 2); // return value
  // Record strings last (uargs first, then umod like eauditk)
  evt->len += add_string_user(evt, uargs); // module arguments string
  evt->len += add_string_user(evt, umod);  // module data string
  return evt->len;
}

NOD_FILLER(finit_module) {
  const char __user *uargs;
  long fd, flags;
  int ret_val;

  fd = nod_get_syscall_argument(regs, 1);
  uargs = (const char __user *)nod_get_syscall_argument(regs, 2);
  flags = nod_get_syscall_argument(regs, 3);
  ret_val = nod_get_syscall_ret(regs);

  // Record like eauditk: log_sc_str_long2(uargs, fd, flags)
  evt->len += add_64(evt, fd, 1);      // file descriptor
  evt->len += add_64(evt, flags, 2);   // flags
  evt->len += add_64(evt, ret_val, 3); // return value
  // Record uargs string last
  evt->len += add_string_user(evt, uargs); // module arguments string
  return evt->len;
}

#undef NOD_FILLER
