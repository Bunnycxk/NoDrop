#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/semaphore.h>
#include <linux/vmalloc.h>


#include "nodrop.h"
#include "events.h"
#include "common.h"
#include "ioctl.h"
#include "tsc.h"

#include "config.h"

DEFINE_PER_CPU(struct nod_event_statistic, g_stat);
EXPORT_PER_CPU_SYMBOL(g_stat);

static volatile unsigned long nod_buffer_size = CONFIG_BUFFER_SIZE;

int nod_event_set_buffer_size(unsigned long size) {
    if (size < PAGE_SIZE) {
        return -1;
    }
    if (size & (PAGE_SIZE - 1)) {
        return -1;
    }
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

static int 
do_record_one_event(struct nod_proc_info *p,
        enum nod_event_type event_type,
        nanoseconds ts,
        struct nod_event_data *event_datap)
{
    int cbret, restart, force;
    size_t event_size;
    uint32_t freespace; 
    char *overflow_page;
    nod_buffer_info_t *info;
    nod_buffer_t *buffer;
    struct event_filler_arguments args;
    struct nod_event_hdr *hdr;
    struct nod_event_statistic *stat;

    buffer = &p->buffer;
    info = buffer->info;
    stat = &per_cpu(g_stat, smp_processor_id());

    if (unlikely(nod_buffer_overflow_check(buffer))) {
        overflow_page = (char *)(buffer->overflow_page & PAGE_MASK);
        info->tail = ((struct nod_event_hdr *)overflow_page)->len;
        info->nevents++;
        stat->n_evts++;

        memmove(info->buffer, overflow_page, info->tail);
        buffer->overflow_page &= PAGE_MASK;
    }

    freespace = info->buffer_size - info->tail;

    args.nargs = g_event_info[event_type].nparams;
    args.arg_data_offset = args.nargs * sizeof(uint16_t);

    if (event_datap->force || p->entry_addr == 0) {
        force = 1;
    } else {
        force = 0;
    }
    restart = 0;

restart:
    if (freespace < args.arg_data_offset + sizeof(struct nod_event_hdr) /* no free space for coming event header */ || 
        restart /* no free space for coming event data */) {
        // When the buffer is full, the next event log will temporarily write to the overflow page
        // The content of this page will be writen to buffer in the next syscall enter.
        hdr = (struct nod_event_hdr *)(buffer->overflow_page & PAGE_MASK);
        args.buf_ptr = (char *)&hdr[1];
        args.buffer_size = PAGE_SIZE - sizeof(struct nod_event_hdr);

        force = 1;
        buffer->overflow_page |= NOD_BUFFER_OVERFLOW_FILL_FLAG;
    } else {
        hdr = (struct nod_event_hdr *)(info->buffer + info->tail);
        args.buf_ptr = info->buffer + info->tail + sizeof(struct nod_event_hdr);
        args.buffer_size = freespace - sizeof(struct nod_event_hdr);
    }

    if (!restart) {
        args.event_type = event_type;
        args.str_storage = buffer->str_storage;
        args.nevents = info->nevents;
        args.snaplen = 80; // temporary MAGIC number
        args.is_socketcall = false;

        if (event_datap->category == NODC_SYSCALL) {
            args.regs = event_datap->event_info.syscall_data.regs;
            args.syscall_nr = event_datap->event_info.syscall_data.id;
        } else {
            args.regs = NULL;
            args.syscall_nr = -1;
        }

    }

    args.curarg = 0;
    args.arg_data_size = args.buffer_size - args.arg_data_offset;

    hdr->ts = ts;
    hdr->tid = current->pid;
    hdr->type = event_type;
    hdr->cpuid = smp_processor_id();
    hdr->nargs = args.nargs;
    hdr->magic = NOD_EVENT_HDR_MAGIC & 0xFFFFFFFF;

    cbret = nod_filler_callback(&args);

    if (cbret == NOD_SUCCESS) {
        if (likely(args.curarg == args.nargs)) {
            event_size = sizeof(struct nod_event_hdr) + args.arg_data_offset;
            hdr->len = event_size;

            if (likely(!nod_buffer_overflow_check(buffer))) {
                info->tail += event_size;
                info->nevents++;
                stat->n_evts++;
            }
        } else {
            pr_err("corrupted filler for event type %d (added %u args, should have added %u args)\n",
                    event_type,
                    args.curarg,
                    args.nargs);
            force = 0;
        }
    } else if (cbret == NOD_FAILURE_BUFFER_FULL) {
        restart = 1;
        goto restart;
    } else {
        stat->n_drop_evts++; 
    }

    if (force) {
        // p->buffer.ts = nod_rdtsc();
        cbret = nod_load_monitor(p);
    }

    return cbret; 
}

int
init_buffer(nod_buffer_t *buffer)
{
    int ret;
    uint64_t buffer_size = (uint64_t)nod_buffer_size;

    if (buffer_size & (PAGE_SIZE - 1)) {
        ret = -EINVAL;
        pr_err("Buffer size is not aligned to the page size\n");
        goto init_buffer_err;
    }

    buffer->str_storage = (char *)__get_free_page(GFP_USER);
    if (!buffer->str_storage) {
        ret = -ENOMEM;
		pr_err("Error allocating the string storage\n");
        goto init_buffer_err;
    }

    buffer->overflow_page = (uint64_t)__get_free_page(GFP_KERNEL);
    if (buffer->overflow_page == 0) {
        ret = -ENOMEM;
        pr_err("Error allocating the overflow page\n");
        goto init_buffer_err;
    }
    if ((buffer->overflow_page & PAGE_MASK) != buffer->overflow_page) {
        pr_err("Overflow page address is not aligned to the page size\n");
        ret = -EINVAL;
        goto init_buffer_err;
    }

    buffer->info = vmalloc_user(sizeof(nod_buffer_info_t) + buffer_size);
    if (!buffer->info) {
        ret = -ENOMEM;
        pr_err("Error allocating buffer memory\n");
        goto init_buffer_err;
    }

    memset(buffer->info, 0, sizeof(nod_buffer_info_t));
    // // clear the buffer
    // memset(buffer->info->buffer, 0, buffer_size);

    buffer->info->buffer_size = buffer_size;
    buffer->info->n_solved_evts = 0;
    reset_buffer(buffer, NOD_INIT_INFO | NOD_INIT_COUNT);

    return 0;

init_buffer_err:
    free_buffer(buffer);
    return ret;
}

void
free_buffer(nod_buffer_t *buffer)
{
    if (buffer->info) {
        vfree(buffer->info);
        buffer->info = NULL;
    }

    if (buffer->overflow_page) {
        free_page((unsigned long)buffer->overflow_page & PAGE_MASK);
        buffer->overflow_page = 0;
    }

    if (buffer->str_storage) {
        free_page((unsigned long)buffer->str_storage);
        buffer->str_storage = NULL;
    }
}

void
reset_buffer(nod_buffer_t *buffer, int flags) 
{
    if (flags & NOD_INIT_INFO) {
        buffer->info->nevents = 0;
        buffer->info->tail = 0;
        buffer->overflow_page &= PAGE_MASK;
    }

    if (flags & NOD_INIT_COUNT)
        buffer->event_count = 0;
}

int 
record_one_event(struct nod_proc_info *p, enum nod_event_type type, struct nod_event_data *event_datap) 
{
    int retval;
    nanoseconds ts = nod_nsecs();

    retval = do_record_one_event(p, type, ts, event_datap);
    if (retval < 0) {
        pr_warn("(%u)record_one_event: event #%llu droopped, type=%u, reason=%d\n",
            smp_processor_id(), p->buffer.info->nevents, type, retval);
    }

    return retval;
}
