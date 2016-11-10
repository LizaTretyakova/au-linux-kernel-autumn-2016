#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

#define VSD_DEV_CMD_QUEUE_MAX_LEN 10
// TODO implement write syscall in synchronous non blocking mode.
// TODO implement poll, epoll, select syscalls using .poll file_operations func.

typedef struct vsd_cmd {
    // Command to run.
    uint8_t cmd;
    // To check whether the mode is blocking or not.
    struct file* filp;
    // Buffer of/for user data in case of write/read,
    // set/get_size_arg otherwise.
    char* buf;
    // Number of bytes for read/write. Whence for llseek.
    int count;
    // *fpos for read/write as well. &off for llseek.
    loff_t *fpos;

    // What to return to user if needed.
    ssize_t result;
    // Ready/not ready yet.
    int state;

    // Adding a list structure.
    struct list_head lh;
    wait_queue_head_t wq_ready;
} vsd_cmd_t;

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;

    // Invariant:
    // the current queue consists of commands in range (open segment)
    // [cur_cmd; last_cmd). (cycled)
    vsd_cmd_t vsd_cmd_queue[VSD_DEV_CMD_QUEUE_MAX_LEN + 1];
    int cur_cmd;
    int last_cmd;
    // Lock for the queue.
    spinlock_t vsd_cmd_lock;
    // Wq for the queue.
    wait_queue_head_t cmd_wq;

    // Looking for new commands in the queue.
    struct task_struct *kthread;
    // Waiting for the device.
    wait_queue_head_t wq;
    // Lock for the device.
    struct mutex mtx;
    // Lock for the size operations.
    // struct mutex size_op_mtx;
} vsd_dev_t;
static vsd_dev_t *vsd_dev;

#define LOCAL_DEBUG 0
static void print_vsd_dev_hw_regs(vsd_dev_t *vsd_dev)
{
    if (!LOCAL_DEBUG)
        return;

    pr_notice(LOG_TAG "VSD dev hwregs: \n"
            "CMD: %x \n"
            "RESULT: %x \n"
            "TASKLET_VADDR: %llx \n"
            "dma_paddr: %llx \n"
            "dma_size:  %llx \n"
            "dev_offset: %llx \n"
            "dev_size: %llx \n",
            vsd_dev->hwregs->cmd,
            vsd_dev->hwregs->result,
            vsd_dev->hwregs->tasklet_vaddr,
            vsd_dev->hwregs->dma_paddr,
            vsd_dev->hwregs->dma_size,
            vsd_dev->hwregs->dev_offset,
            vsd_dev->hwregs->dev_size
    );
}

int is_task_queue_full(void) {
    return (vsd_dev->cur_cmd + VSD_DEV_CMD_QUEUE_MAX_LEN + 1 - vsd_dev->last_cmd)
            % (VSD_DEV_CMD_QUEUE_MAX_LEN + 1) >= VSD_DEV_CMD_QUEUE_MAX_LEN;
}

int next_it(int i) {
    return (i + 1) % (VSD_DEV_CMD_QUEUE_MAX_LEN + 1);
}

int prev_it(int i) {
    return (i + (VSD_DEV_CMD_QUEUE_MAX_LEN + 1) - 1)
            % (VSD_DEV_CMD_QUEUE_MAX_LEN + 1);
}

// Carefully: returnes spin-locked!
void wait_for_space(void) {
    while(1) {
        spin_lock(&vsd_dev->vsd_cmd_lock);

        // Check if the queue is full [i.e. the length of the interval is max].
        if(is_task_queue_full()) {
            spin_unlock(&vsd_dev->vsd_cmd_lock);

            // Waiting for better times.
            wait_event(vsd_dev->cmd_wq, !is_task_queue_full());
        } else {
            break;
        }
    }
}

// Carefully: enters spin-locked, returnes spin-unlocked!
void submit_task(int cmd, struct file* filp, char* buf, int count,
                 loff_t* fpos, int* pos) {
    pr_notice(LOG_TAG "submit_task\n");

    *pos = vsd_dev->last_cmd;
    // We've got some space -- write the command there.
    vsd_dev->vsd_cmd_queue[*pos].cmd = cmd;
    vsd_dev->vsd_cmd_queue[*pos].filp = filp;
    vsd_dev->vsd_cmd_queue[*pos].buf = buf;
    vsd_dev->vsd_cmd_queue[*pos].count = count;
    vsd_dev->vsd_cmd_queue[*pos].fpos = fpos;
    // Moving the pointer.
    //[We may not bother about the borders since we've already done this]
    vsd_dev->last_cmd = next_it(vsd_dev->last_cmd);

    pr_notice(LOG_TAG "submit_task: all set\n");

    spin_unlock(&vsd_dev->vsd_cmd_lock);
    pr_notice(LOG_TAG "submit_task: spin unlocked\n");
}

// Carefully: returns spin-locked!
void wait_task_completion(int pos) {
    pr_notice(LOG_TAG "wait_task_completion\n");

    while(1) {
        spin_lock(&vsd_dev->vsd_cmd_lock);
        if(vsd_dev->vsd_cmd_queue[pos].state != READY) {
            spin_unlock(&vsd_dev->vsd_cmd_lock);
            wait_event(vsd_dev->vsd_cmd_queue[pos].wq_ready,
                       vsd_dev->vsd_cmd_queue[pos].state == READY);
        } else {
            break;
        }
    }

    pr_notice(LOG_TAG "wait_task_completion: returns, spin locked\n");
}

static ssize_t vsd_dev_read_internal(struct file *filp,
    char *read_buf, size_t read_size, loff_t *fpos)
{
    // char* read_buf = NULL;

    pr_notice(LOG_TAG "vsd_dev_read_internal\n");

    mutex_lock(&vsd_dev->mtx);

    if (*fpos >= vsd_dev->hwregs->dev_size) {
        return 0;
    }
    if (*fpos + read_size >= vsd_dev->hwregs->dev_size) {
        read_size = vsd_dev->hwregs->dev_size - *fpos;
    }

    // read_buf = (char*)kmalloc(read_size, GFP_KERNEL);
    // if(read_buf == NULL) {
    //     mutex_unlock(&vsd_dev->mtx);
    //     return -ENOMEM;
    // }

    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)&vsd_dev->dma_op_complete_tsk;
    vsd_dev->hwregs->dma_paddr = virt_to_phys(read_buf);
    vsd_dev->hwregs->dma_size = read_size;
    vsd_dev->hwregs->dev_offset = *fpos;
    wmb();
    vsd_dev->hwregs->cmd = VSD_CMD_READ;

    wait_event(vsd_dev->wq, vsd_dev->hwregs->cmd == VSD_CMD_NONE);
    mutex_unlock(&vsd_dev->mtx);

    // if (copy_to_user(read_user_buf, read_buf, read_size))
    //     return -EFAULT;
    *fpos += vsd_dev->hwregs->result;
    // kfree(read_buf);
    return vsd_dev->hwregs->result;
}

static ssize_t vsd_dev_write_internal(struct file *filp,
    char *write_buf, size_t write_size, loff_t *fpos)
{
    // char* write_buf = NULL;

    pr_notice(LOG_TAG "vsd_dev_write_internal\n");

    mutex_lock(&vsd_dev->mtx);

    if (*fpos >= vsd_dev->hwregs->dev_size) {
        mutex_unlock(&vsd_dev->mtx);
        kfree(write_buf);
        return 0;
    }
    if (*fpos + write_size >= vsd_dev->hwregs->dev_size) {
        write_size = vsd_dev->hwregs->dev_size - *fpos;
    }

    // write_buf = (char*)kzalloc(write_size, GFP_KERNEL);
    // if(write_buf == NULL) {
    //     mutex_unlock(&vsd_dev->mtx);
    //     return -ENOMEM;
    // }
    // if (copy_from_user(write_buf, write_user_buf, write_size)) {
    //     mutex_unlock(&vsd_dev->mtx);
    //     return -EFAULT;
    // }

    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)&vsd_dev->dma_op_complete_tsk;
    vsd_dev->hwregs->dma_paddr = virt_to_phys(write_buf);
    vsd_dev->hwregs->dma_size = write_size;
    vsd_dev->hwregs->dev_offset = *fpos;
    wmb();
    vsd_dev->hwregs->cmd = VSD_CMD_WRITE;

    wait_event(vsd_dev->wq, vsd_dev->hwregs->cmd == VSD_CMD_NONE);
    mutex_unlock(& vsd_dev->mtx);

    *fpos += vsd_dev->hwregs->result;
    // Because the ownership of this buf was passed to us.
    kfree(write_buf);
    return vsd_dev->hwregs->result;
}

static loff_t vsd_dev_llseek_internal(struct file* filp, loff_t off, int whence) {
    loff_t newpos = 0;

    pr_notice(LOG_TAG "vsd_dev_llseek\n");

    switch(whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = vsd_dev->hwregs->dev_size - off;
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    if (newpos >= vsd_dev->hwregs->dev_size)
        newpos = vsd_dev->hwregs->dev_size;

    filp->f_pos = newpos;
    return newpos;
}

static long vsd_ioctl_get_size_internal(vsd_ioctl_get_size_arg_t *uarg) {
    pr_notice(LOG_TAG "vsd_ioctl_get_size_internal\n");
    uarg->size = vsd_dev->hwregs->dev_size;
    return 0;
}

static long vsd_ioctl_set_size_internal(vsd_ioctl_set_size_arg_t *uarg)
{
    vsd_ioctl_set_size_arg_t arg;

    pr_notice(LOG_TAG "vsd_ioctl_set_size_internal\n");

    // if (copy_from_user(&arg, uarg, sizeof(arg))) {
    //     return -EFAULT;
    // }

    mutex_lock(&vsd_dev->mtx);

    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)&vsd_dev->dma_op_complete_tsk;
    vsd_dev->hwregs->dev_offset = arg.size;
    wmb();
    vsd_dev->hwregs->cmd = VSD_CMD_SET_SIZE;

    wait_event(vsd_dev->wq, vsd_dev->hwregs->cmd == VSD_CMD_NONE);
    pr_notice(LOG_TAG "vsd_ioctl_set_size woke up\n");
    mutex_unlock(&vsd_dev->mtx);
    pr_notice(LOG_TAG "vsd_ioctl_set_size unlocked\n");

    return vsd_dev->hwregs->result;
}

// void move_queue_iter(int* i) {
//     i = (i + 1) % (VSD_DEV_CMD_QUEUE_MAX_LEN + 1);
// }

static int vsd_dev_cmd_poll_kthread_func(void *data)
{
    pr_notice(LOG_TAG "kthread started");

    while(!kthread_should_stop()) {
        int first = -1;
        int last = -1;
        int i = -1;

        mb();

        spin_lock(&vsd_dev->vsd_cmd_lock);
        first = vsd_dev->cur_cmd;
        last = vsd_dev->last_cmd;
        spin_unlock(&vsd_dev->vsd_cmd_lock);

        // Check if anything yummy appeared in the queue.
        for(i = first; i != last; i = next_it(i)) {
            // Invariant: we as consumer never touch anything
            // under or after `last` while producers never
            // touch anything prior to `last`.

            pr_notice(LOG_TAG "kthread found a task\n");

            switch(vsd_dev->vsd_cmd_queue[i].cmd) {
                case VSD_CMD_READ:
                    pr_notice(LOG_TAG "VSD_CMD_READ\n");
                    vsd_dev->vsd_cmd_queue[i].result = vsd_dev_read_internal(
                                vsd_dev->vsd_cmd_queue[i].filp,
                                vsd_dev->vsd_cmd_queue[i].buf,
                                vsd_dev->vsd_cmd_queue[i].count,
                                vsd_dev->vsd_cmd_queue[i].fpos);
                    vsd_dev->vsd_cmd_queue[i].state = READY;
                    break;
                case VSD_CMD_WRITE:
                    pr_notice(LOG_TAG "VSD_CMD_WRITE\n");
                    vsd_dev->vsd_cmd_queue[i].result = vsd_dev_write_internal(
                                vsd_dev->vsd_cmd_queue[i].filp,
                                vsd_dev->vsd_cmd_queue[i].buf,
                                vsd_dev->vsd_cmd_queue[i].count,
                                vsd_dev->vsd_cmd_queue[i].fpos);
                    vsd_dev->vsd_cmd_queue[i].state = READY;
                    break;
                case VSD_CMD_SET_SIZE:
                    pr_notice(LOG_TAG "VSD_CMD_SET_SIZE\n");
                    vsd_dev->vsd_cmd_queue[i].result = vsd_ioctl_set_size_internal(
                                (vsd_ioctl_set_size_arg_t*)vsd_dev->vsd_cmd_queue[i].buf);
                    vsd_dev->vsd_cmd_queue[i].state = READY;
                    break;
                case VSD_CMD_GET_SIZE:
                    pr_notice(LOG_TAG "VSD_CMD_GET_SIZE\n");
                    vsd_dev->vsd_cmd_queue[i].result = vsd_ioctl_get_size_internal(
                                (vsd_ioctl_get_size_arg_t*)vsd_dev->vsd_cmd_queue[i].buf);
                    vsd_dev->vsd_cmd_queue[i].state = READY;
                    break;
                case VSD_CMD_LLSEEK:
                    pr_notice(LOG_TAG "VSD_CMD_LLSEEK\n");
                    vsd_dev->vsd_cmd_queue[i].result = vsd_dev_llseek_internal(
                                vsd_dev->vsd_cmd_queue[i].filp,
                                *(vsd_dev->vsd_cmd_queue[i].fpos),
                                vsd_dev->vsd_cmd_queue[i].count);
                    vsd_dev->vsd_cmd_queue[i].state = READY;
                    break;
            }

            // Mark this task as done.
            spin_lock(&vsd_dev->vsd_cmd_lock);
            vsd_dev->cur_cmd = next_it(vsd_dev->cur_cmd);
            spin_unlock(&vsd_dev->vsd_cmd_lock);
        }
        ssleep(1);
    }
    pr_notice(LOG_TAG "kthread exited");
    return 0;
}


static int vsd_dev_open(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev opened\n");
    return 0;
}

static int vsd_dev_release(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev closed\n");
    return 0;
}

static void vsd_dev_dma_op_complete_tsk_func(unsigned long unused)
{
    pr_notice(LOG_TAG "vsd_dev_dma_op_complete_tsk_func\n");

    wake_up(&vsd_dev->wq);
}

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    char* read_buf = NULL;
    int pos;
    ssize_t result = 0;
    pr_notice(LOG_TAG "vsd_dev_read\n");

    if(filp->f_flags & O_NONBLOCK) {
        return -EWOULDBLOCK;
    }

    read_buf = (char*)kmalloc(read_size, GFP_KERNEL);
    if(read_buf == NULL) {
        return -ENOMEM;
    }

    // Returns spin-locked!
    wait_for_space();
    // Enters pin-locked, returnes spin-unlocked!
    submit_task(VSD_CMD_READ, filp, read_buf, read_size, fpos, &pos);
    // Waits for completion.
    // Returns spin-locked.
    wait_task_completion(pos);
    // Keep the result.
    result = vsd_dev->vsd_cmd_queue[pos].result;
    // Move the iterator. We are done here.
    vsd_dev->vsd_cmd_queue[pos].state = NOT_READY;
    vsd_dev->vsd_cmd_queue[pos].cmd = VSD_CMD_NONE;
    spin_unlock(&vsd_dev->vsd_cmd_lock);

    if (copy_to_user(read_user_buf, read_buf, read_size)) {
        kfree(read_buf);
        return -EFAULT;
    }

    kfree(read_buf);
    return result;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    char* write_buf = NULL;
    int pos;
    pr_notice(LOG_TAG "vsd_dev_write\n");

    write_buf = (char*)kzalloc(write_size, GFP_ATOMIC);
    if(write_buf == NULL) {
        return -ENOMEM;
    }
    pagefault_disable();
    if (copy_from_user(write_buf, write_user_buf, write_size)) {
        kfree(write_buf);
        return -EFAULT;
    }
    pagefault_enable();

    spin_lock(&vsd_dev->vsd_cmd_lock);
    // Check if the queue is full [i.e. the length of the interval is max].
    if(is_task_queue_full()) {
        spin_unlock(&vsd_dev->vsd_cmd_lock);
        // We can't wait for better times -- return.
        kfree(write_buf);
        return -EWOULDBLOCK;
    }

    // Enters spin-locked, returns spin-unlocked.
    submit_task(VSD_CMD_WRITE, filp, write_buf, write_size, fpos, &pos);
    // Move the iterator.
    spin_lock(&vsd_dev->vsd_cmd_lock);
    vsd_dev->vsd_cmd_queue[pos].state = NOT_READY;
    vsd_dev->vsd_cmd_queue[pos].cmd = VSD_CMD_NONE;
    spin_unlock(&vsd_dev->vsd_cmd_lock);

    // No kfree here -- the internal write will handle it,
    // "I passed the ownership to it".
    return 0;
}

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
    int pos;
    int result;

    if(filp->f_flags & O_NONBLOCK) {
        return -EWOULDBLOCK;
    }

    submit_task(VSD_CMD_LLSEEK, NULL, NULL, whence, &off, &pos);
    // Returns psin-locked.
    wait_task_completion(pos);
    result = vsd_dev->vsd_cmd_queue[pos].result;
    // Move the iterator. We are done here.
    vsd_dev->vsd_cmd_queue[pos].state = NOT_READY;
    vsd_dev->vsd_cmd_queue[pos].cmd = VSD_CMD_NONE;
    spin_unlock(&vsd_dev->vsd_cmd_lock);

    return result;
}

static long vsd_ioctl_get_size(vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;
    int pos;

    pr_notice(LOG_TAG "vsd_ioctl_get_size\n");

    if (copy_from_user(&arg, uarg, sizeof(arg))) {
        return -EFAULT;
    }
    pr_notice(LOG_TAG "vsd_ioctl_get_size: copied from user\n");

    // arg.size = vsd_dev->hwregs->dev_size;

    submit_task(VSD_CMD_GET_SIZE, NULL, (char*)&arg, 0, NULL, &pos);
    wait_task_completion(pos);
    vsd_dev->vsd_cmd_queue[pos].state = NOT_READY;
    vsd_dev->vsd_cmd_queue[pos].cmd = VSD_CMD_NONE;
    spin_unlock(&vsd_dev->vsd_cmd_lock);
    pr_notice(LOG_TAG "vsd_ioctl_get_size: spin unlocked\n");

    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;
    int pos;

    pr_notice(LOG_TAG "vsd_ioctl_set_size\n");

    if (copy_from_user(&arg, uarg, sizeof(arg))) {
        return -EFAULT;
    }

    spin_lock(&vsd_dev->vsd_cmd_lock);
    // Enters spin-locked!
    submit_task(VSD_CMD_SET_SIZE, NULL, (char*)&arg, 0, NULL, &pos);
    wait_task_completion(pos);
    vsd_dev->vsd_cmd_queue[pos].state = NOT_READY;
    vsd_dev->vsd_cmd_queue[pos].cmd = VSD_CMD_NONE;
    spin_unlock(&vsd_dev->vsd_cmd_lock);

    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    pr_notice(LOG_TAG "vsd_dev_ioctl\n");

    if(filp->f_flags & O_NONBLOCK) {
        return -EWOULDBLOCK;
    }

    switch(cmd) {
        case VSD_IOCTL_GET_SIZE:
            return vsd_ioctl_get_size((vsd_ioctl_get_size_arg_t __user*)arg);
            break;
        case VSD_IOCTL_SET_SIZE:
            return vsd_ioctl_set_size((vsd_ioctl_set_size_arg_t __user*)arg);
            break;
        default:
            return -ENOTTY;
    }
}

static unsigned int vsd_dev_poll(struct file *filp, struct poll_table_struct *wait) {
    unsigned int mask = 0;

    pr_notice(LOG_TAG "vsd_dev_poll\n");

    poll_wait(filp, &vsd_dev->cmd_wq, wait);

    spin_lock(&vsd_dev->vsd_cmd_lock);
    if(!is_task_queue_full()) {
        // Readable, writable -- whatever.
        mask |= POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
    }
    spin_unlock(&vsd_dev->vsd_cmd_lock);

    return mask;
}

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .unlocked_ioctl = vsd_dev_ioctl,
    .poll = vsd_dev_poll
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    int i = 0;
    struct resource *vsd_control_regs_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    vsd_dev = (vsd_dev_t*)
        kzalloc(sizeof(*vsd_dev), GFP_KERNEL);
    if (!vsd_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    tasklet_init(&vsd_dev->dma_op_complete_tsk,
            vsd_dev_dma_op_complete_tsk_func, 0);
    vsd_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    vsd_dev->mdev.name = "vsd";
    vsd_dev->mdev.fops = &vsd_dev_fops;
    vsd_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;

    if ((ret = misc_register(&vsd_dev->mdev)))
        goto error_misc_reg;

    vsd_control_regs_res = platform_get_resource_byname(
            pdev, IORESOURCE_REG, "control_regs");
    if (!vsd_control_regs_res) {
        ret = -ENOMEM;
        goto error_get_res;
    }
    vsd_dev->hwregs = (volatile vsd_hw_regs_t*)
        phys_to_virt(vsd_control_regs_res->start);

    vsd_dev->kthread = kthread_create(vsd_dev_cmd_poll_kthread_func,
            NULL, "vsd_driver_poll_kthread");
    if (IS_ERR_OR_NULL(vsd_dev->kthread)) {
        goto error_thread;
    }

    vsd_dev->cur_cmd = 0;
    vsd_dev->last_cmd = 0;
    spin_lock_init(&vsd_dev->vsd_cmd_lock);
    init_waitqueue_head(&vsd_dev->cmd_wq);
    init_waitqueue_head(&vsd_dev->wq);
    for(i = 0; i < VSD_DEV_CMD_QUEUE_MAX_LEN + 1; ++i) {
        init_waitqueue_head(&vsd_dev->vsd_cmd_queue[i].wq_ready);
        vsd_dev->vsd_cmd_queue[i].state = NOT_READY;
        vsd_dev->vsd_cmd_queue[i].cmd = VSD_CMD_NONE;
    }
    mutex_init(&vsd_dev->mtx);

    wake_up_process(vsd_dev->kthread);

    print_vsd_dev_hw_regs(vsd_dev);
    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

error_thread:
error_get_res:
    misc_deregister(&vsd_dev->mdev);
error_misc_reg:
    kfree(vsd_dev);
    vsd_dev = NULL;
error_alloc:
    return ret;
}

static int vsd_driver_remove(struct platform_device *dev)
{
    // module can't be unloaded if its users has even single
    // opened fd
    pr_notice(LOG_TAG "removing device %s\n", dev->name);
    misc_deregister(&vsd_dev->mdev);
    kfree(vsd_dev);
    vsd_dev = NULL;
    return 0;
}

static struct platform_driver vsd_driver = {
    .probe = vsd_driver_probe,
    .remove = vsd_driver_remove,
    .driver = {
        .name = "au-vsd",
        .owner = THIS_MODULE,
    }
};

static int __init vsd_driver_init(void)
{
    return platform_driver_register(&vsd_driver);
}

static void __exit vsd_driver_exit(void)
{
    // This indirectly calls vsd_driver_remove
    platform_driver_unregister(&vsd_driver);
}

module_init(vsd_driver_init);
module_exit(vsd_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device driver module");
MODULE_AUTHOR("Kernel hacker!");
