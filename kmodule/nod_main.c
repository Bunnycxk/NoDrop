#include <linux/init.h>
#include <linux/module.h>

#include "nodrop.h"

MODULE_LICENSE("GPL");

static int notamper_init(void)
{
    int err;

    if ((err = loader_init())) {
        pr_err("load monitor failed (%d)\n", err);
        goto out_loader;
    }

    if ((err = procinfo_init())) {
        pr_err("procinfo initialization failed (%d)\n", err);
        goto out_procinfo;
    }

    if((err = tracepoint_init())) {
        pr_err("hook syscall_table failed (%d)\n", err);
        goto out_trace;
    }

    if ((err = proc_init())) {
        pr_err("create proc failed (%d)\n", err);
        goto out_proc;
    }

    err = 0;
out:
    return err;

out_proc:
    proc_destroy();
out_trace:
    tracepoint_destory();
out_procinfo:
    procinfo_destroy();
out_loader:
    loader_destory();
    goto out;
}

static void notamper_exit(void)
{
    proc_destroy();
    tracepoint_destory();
    procinfo_destroy();
    loader_destory();
    pr_info("NoTamper: Uninstalled\n");
}

module_init(notamper_init);
module_exit(notamper_exit);
