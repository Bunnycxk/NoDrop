#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include "nodrop.h"
#include "procinfo.h"

#include "nodrop.h"
#include "ioctl.h"

#define BUFSIZE 30

static struct proc_dir_entry *ent;

static int nod_dev_open(struct inode *inode, struct file *filp)
{
    struct nod_proc_info *p;

    nod_event_from(&p);
    filp->private_data = (void *)p;
    return 0;
}

static int
__proc_buf_reset(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    reset_buffer(&this->buffer, NOD_INIT_INFO | NOD_INIT_COUNT);
    return NOD_PROC_TRAVERSE_CONTINUE;
}

static int
__proc_bufcount_read(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    nod_buffer_t *buf = &this->buffer;
    struct buffer_count_info *info = va_arg(args, struct buffer_count_info *);
    info->event_count += buf->event_count;
    info->unflushed_count += buf->info->nevents;
    info->unflushed_len += buf->info->tail; 
    return NOD_PROC_TRAVERSE_CONTINUE;
}

static ssize_t
nod_dev_read(struct file *filp, char __user *buf, size_t count, loff_t *off) {
    int len = 0;
    struct buffer_count_info buf_info;
    char kbuf[BUFSIZE];

    if (*off > 0 || count < BUFSIZE)
        return 0;

    memset(&buf_info, 0, sizeof(buf_info));
    nod_proc_traverse(__proc_bufcount_read, &buf_info);

    len += sprintf(kbuf, "%llu", buf_info.event_count);
    if (copy_to_user(buf, kbuf, len))
        return -EFAULT;
    
    *off = len;
    return len;
}

static int
__proc_buf_copy(struct nod_proc_info *this, unsigned long *ret, va_list args)
{
    nod_buffer_info_t *info = this->buffer.info;
    char *ptr = va_arg(args, char *);
    uint64_t *count = va_arg(args, uint64_t *);
    uint64_t len = va_arg(args, uint64_t);

    if (*count + info->tail <= len) {
        if (copy_to_user((void *)ptr, (void *)info->buffer, info->tail)) {
            *ret = -EFAULT;
            return NOD_PROC_TRAVERSE_BREAK;
        }
        ptr += info->tail;
        *count += info->tail;
        *ret = 0;
        return NOD_PROC_TRAVERSE_CONTINUE;
    } else {
        *ret = 0;
        return NOD_PROC_TRAVERSE_BREAK;
    }
}

static long 
nod_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret, cpu;
    uint64_t count;
    nod_ioctl_data_t data;
    nod_stack_info_t stack;
    struct nod_event_statistic *stat;
    struct nod_proc_info *p = filp->private_data;

    memset(&data, 0, sizeof(data));
    switch(cmd) {
    case NOD_IOCTL_CLEAR_BUFFER:
        nod_proc_traverse(__proc_buf_reset);

        pr_info("proc: clean buffer");
        break;

    case NOD_IOCTL_FETCH_BUFFER:
        if (copy_from_user((void *)&data, (void *)arg, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }

        count = 0;
        ret = nod_proc_traverse(__proc_buf_copy, data.fetch_buffer.buf, &count, data.fetch_buffer.len);
        if (ret) {
            goto out;
        }

        data.fetch_buffer.len = count;
        if (copy_to_user((void *)arg, (void *)&data, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }

        ret = 0;
        break;

    case NOD_IOCTL_READ_BUFFER_COUNT_INFO:
        nod_proc_traverse(__proc_bufcount_read, &data.buffer_count);

        if (copy_to_user((void *)arg, (void *)&data, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }
        break;

    case NOD_IOCTL_READ_STATISTICS:
        for_each_possible_cpu(cpu) {
          stat = &per_cpu(g_stat, cpu);
          data.event_stat.n_evts += stat->n_evts;
          data.event_stat.n_drop_evts += stat->n_drop_evts;
          data.event_stat.n_drop_evts_unsolved += stat->n_drop_evts_unsolved;
        }

        if (copy_to_user((void *)arg, (void *)&data, sizeof(data))) {
          ret = -EFAULT;
          goto out;
        }
        break;

    case NOD_IOCTL_CLEAR_STATISTICS:
        for_each_possible_cpu(cpu) {
          stat = &per_cpu(g_stat, cpu);
          memset(stat, 0, sizeof(*stat));
        }
        break;

    case NOD_IOCTL_STOP_RECORDING:
        untrace_syscall();

        pr_info("proc: Stop recording");
        break;
    case NOD_IOCTL_START_RECORDING:
        trace_syscall();

        pr_info("proc: Start recording");
        break;

    case NOD_IOCTL_RESTORE_SECURITY:
    case NOD_IOCTL_RESTORE_CONTEXT:
        if (!p || p->status != NOD_IN || p->pid != current->pid) {
            ret = -ENODEV;
            goto out;
        }

        if (copy_from_user(&stack, (void __user *)arg, sizeof(stack))) {
            ret = -EFAULT;
            goto out;
        }

        if (stack.hash != nod_calc_hash(&stack)) {
            vpr_err("inconsistent stack info hash %lx (dumped)\n", stack.hash);
            memory_dump((char *)&stack, sizeof(stack));
            ret = -EINVAL;
            goto out;
        }

        memcpy(&p->stack_info, &stack, sizeof(stack));

        if(cmd == NOD_IOCTL_RESTORE_CONTEXT) 
            nod_proc_set_context(p);
        else
            nod_proc_set_security(p);

        break;

    case NOD_IOCTL_SET_BUFFER_SIZE:
        if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }
        if (nod_event_set_buffer_size(data.buffer_size.bufsize)) {
            ret = -EINVAL;
            goto out;
        }
        break;

    case NOD_IOCTL_GET_BUFFER_SIZE:
        if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }
        if (nod_event_get_buffer_size(&data.buffer_size.bufsize)) {
            ret = -EINVAL;
            goto out;
        }
        if (copy_to_user((void *)arg, (void *)&data, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }
        break;
    
    case NOD_IOCTL_SET_TARGET_COMM:
        if (copy_from_user(&data, (void __user *)arg, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }

        nod_set_target_comm(data.target_comm.comm);
        break;

    case NOD_IOCTL_GET_TARGET_COMM:
        nod_get_target_comm(data.target_comm.comm);
        if (copy_to_user((void *)arg, (void *)&data, sizeof(data))) {
            ret = -EFAULT;
            goto out;
        }
        break;

    default:
        ret = -EINVAL;
        goto out;
    }

    ret = 0;

out:
    return ret;
}

static int nod_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    struct nod_proc_info *p;

    p = filp->private_data;
    if (!p || p->status != NOD_IN) {
        return -ENODEV;
    }

    if (vma->vm_pgoff != 0) {
        vpr_err("invalid pgoff %lu, must be 0\n", vma->vm_pgoff);
        return -EIO;
    }

    ret = remap_vmalloc_range(vma, (void *)p->buffer.info, 0);
    if (ret < 0) {
      vpr_err("remap_vmalloc_range for buffer info failed (%d)\n", ret);
      return ret;
    }

    return 0;
}

static int nod_dev_release(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;
    return 0;
}

static const struct proc_ops g_nod_fops = {
    .proc_open = nod_dev_open,
    .proc_read = nod_dev_read,
    .proc_ioctl = nod_dev_ioctl,
    .proc_release = nod_dev_release,
    .proc_mmap = nod_dev_mmap,
};

int proc_init(void) {
    int ret;

    ent = proc_create(NOD_IOCTL_NAME, 0666, NULL, &g_nod_fops);

    if (!ent) {
        ret = -EFAULT;
        pr_err("proc_init: Cannot create proc file");
    } else {
        ret = 0;
    }

    return ret;
}

void proc_destroy(void) {
    if (ent) {
        proc_remove(ent);
    }
}
