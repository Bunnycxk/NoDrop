#include <linux/kernel.h>
#include <linux/semaphore.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "fillers.h"
#include "ioctl.h"
#include "nodrop.h"
#include "tsc.h"

#include "config.h"

DEFINE_PER_CPU(struct nod_event_statistic, g_stat);
EXPORT_PER_CPU_SYMBOL(g_stat);

static volatile unsigned long nod_buffer_size = CONFIG_BUFFER_SIZE;

int nod_event_set_buffer_size(unsigned long size) {
  WRITE_ONCE(nod_buffer_size, size);
  vpr_info("set buffer size: %lu\n", nod_buffer_size);
  return 0;
}

int nod_event_get_buffer_size(unsigned long *size) {
  if (size) {
    *size = nod_buffer_size;
    return 0;
  }
  return -1;
}

int init_buffer(nod_buffer_t *buffer) {
  int ret;
  uint64_t buffer_size = (uint64_t)nod_buffer_size;
  uint64_t malloc_size;

  malloc_size =
      ((sizeof(nod_buffer_info_t) + buffer_size + PAGE_SIZE + PAGE_SIZE - 1) &
       PAGE_MASK);
  buffer->info = vmalloc_user(malloc_size);
  if (!buffer->info) {
    ret = -ENOMEM;
    pr_err("Error allocating buffer memory\n");
    goto init_buffer_err;
  }

  memset(buffer->info, 0, sizeof(nod_buffer_info_t));
  // // clear the entier buffer
  // memset(buffer->info->buffer, 0, buffer_size);

  buffer->info->buffer_size = buffer_size;
  buffer->info->malloc_size = malloc_size;
  reset_buffer(buffer, NOD_INIT_INFO | NOD_INIT_COUNT);

  return 0;

init_buffer_err:
  free_buffer(buffer);
  return ret;
}

void free_buffer(nod_buffer_t *buffer) {
  if (buffer->info) {
    vfree(buffer->info);
    buffer->info = NULL;
  }
}

void reset_buffer(nod_buffer_t *buffer, int flags) {
  if (flags & NOD_INIT_INFO) {
    buffer->info->nevents = 0;
    buffer->info->tail = 0;
  }

  if (flags & NOD_INIT_COUNT)
    buffer->event_count = 0;
}

int record_one_event(struct nod_proc_info *p, struct pt_regs *regs, long id,
                     int force) {
  int rc;
  nod_event_hdr_t *hdr;
  nod_buffer_info_t *info;
  nod_syscall_filler_fn filler;
  struct nod_event_statistic *stat;

  filler = nod_syscall_filler_table[id];
  if (filler == NULL)
    return NOD_SUCCESS;

  stat = &per_cpu(g_stat, smp_processor_id());
  info = p->buffer.info;

  if (unlikely(info->tail >= info->buffer_size)) {
    // Buffer is full, reset it
    vpr_err("Buffer overflow for proc (%d), dropping event, tail: %x, "
            "buffer_size: %llx\n",
            p->pid, info->tail, info->buffer_size);
    stat->n_drop_evts += info->nevents;
    info->nevents = 0;
    info->tail = 0;
    return NOD_FAILURE_BUFFER_FULL;
  }

  hdr = (nod_event_hdr_t *)(info->buffer + info->tail);
  hdr->len = 0;
  hdr->arg_len = 0;

  // SAFTY: info->buffer has ONE PAGE more space than buffer_size,
  // it is enough to store the extra event header and the event data.
  rc = filler(regs, hdr);
  if (likely(rc > 0)) {
    hdr->pid = (uint32_t)p->pid;
    hdr->sc = (uint8_t)id;
    stat->n_evts++;
    info->nevents++;
    info->tail += sizeof(*hdr) + hdr->len;
    // hdr->ts = nod_nsecs();
    hdr->ts = nod_rdtsc(); // Use rdtsc for high precision timestamp
  } else if (unlikely(rc < 0)) {
    stat->n_drop_evts++;
    return NOD_FAILURE_BUFFER_FULL;
  }

  if (force || info->tail >= info->buffer_size) {
    // info->nevents = 0;
    // info->tail = 0;
    return nod_load_monitor(p, regs);
  }

  return NOD_SUCCESS;
}
