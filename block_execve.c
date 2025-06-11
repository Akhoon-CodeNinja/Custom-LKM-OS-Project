#include <linux/version.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Block certain programs from being executed by non-root users");

#define MAX_BLOCKED 20
#define PROC_NAME "block_execve"

// Paths of programs to block
static const char *blocklist[MAX_BLOCKED] = {
    "/usr/bin/nmap", "/usr/bin/netcat", "/usr/bin/nc",
    "/usr/bin/whoami", "/usr/bin/tcpdump", "/usr/bin/vim",
    "/usr/bin/bash", "/usr/bin/sh"
};
static int blocklist_size = 8;

// Proc entry
static struct proc_dir_entry *proc_entry;

// === BLOCKLIST CHECK ===
static int is_blocked(const char *pathname)
{
    int i;
    for (i = 0; i < blocklist_size; i++) {
        if (strcmp(pathname, blocklist[i]) == 0)
            return 1;
    }
    return 0;
}

// === ORIGINAL SYSTEM CALL POINTER ===
static asmlinkage long (*real_execve)(const char __user *filename,
                                      const char __user *const __user *argv,
                                      const char __user *const __user *envp);

// === HOOK FUNCTION ===
static asmlinkage long fh_sys_execve(const char __user *filename,
                                     const char __user *const __user *argv,
                                     const char __user *const __user *envp)
{
    char fname[256];

    if (strncpy_from_user(fname, filename, sizeof(fname)) < 0)
        return -EFAULT;

    if (is_blocked(fname) && !capable(CAP_SYS_ADMIN)) {
        pr_info("Blocked execve attempt: %s by UID=%d\n", fname, current_uid().val);
        return -EPERM;
    }

    return real_execve(filename, argv, envp);
}



#define HOOK(_name, _function, _original) { \
    .name = (_name), \
    .function = (_function), \
    .original = (_original), \
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

static int resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        pr_err("Unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((unsigned long *)hook->original) = hook->address;
    return 0;
}

static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                 struct ftrace_ops *ops, struct pt_regs *regs)
{
#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    regs->ip = (unsigned long)hook->function;
#else
#error Unsupported architecture/version
#endif
}

static int install_hook(struct ftrace_hook *hook)
{
    int err;

    err = resolve_hook_address(hook);
    if (err)
        return err;

    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_err("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

static void remove_hook(struct ftrace_hook *hook)
{
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

// === HOOK INSTANCE ===
static struct ftrace_hook execve_hook = HOOK("do_execveat_common", fh_sys_execve, &real_execve);

// === INSTALL/REMOVE HOOK ===
static int install_execve_hook(void)
{
    return install_hook(&execve_hook);
}

static void remove_execve_hook(void)
{
    remove_hook(&execve_hook);
}

// === PROC FILE FOR BLOCKLIST ===
static ssize_t proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    char *buf;
    int len = 0, i;

    if (*ppos > 0)
        return 0;

    buf = kmalloc(1024, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    for (i = 0; i < blocklist_size; i++)
        len += snprintf(buf + len, 1024 - len, "%s\n", blocklist[i]);

    if (copy_to_user(ubuf, buf, len)) {
        kfree(buf);
        return -EFAULT;
    }

    *ppos = len;
    kfree(buf);
    return len;
}

static const struct proc_ops proc_file_ops = {
    .proc_read = proc_read,
};

// === INIT & EXIT ===
static int __init execve_hook_init(void)
{
    int ret;

    proc_entry = proc_create(PROC_NAME, 0444, NULL, &proc_file_ops);
    if (!proc_entry) {
        pr_err("Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    ret = install_execve_hook();
    if (ret) {
        remove_proc_entry(PROC_NAME, NULL);
        return ret;
    }

    pr_info("BlockExecve Module loaded.\n");
    return 0;
}

static void __exit execve_hook_exit(void)
{
    remove_execve_hook();
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("BlockExecve Module unloaded.\n");
}

module_init(execve_hook_init);
module_exit(execve_hook_exit);
