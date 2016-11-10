#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;

    wait_queue_head_t wq;
    struct mutex mtx;
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

    pr_notice(LOG_TAG "vsd_dev_read\n");

    mutex_lock(&vsd_dev->mtx);

    if (*fpos >= vsd_dev->hwregs->dev_size) {
        return 0;
    }
    if (*fpos + read_size >= vsd_dev->hwregs->dev_size) {
        read_size = vsd_dev->hwregs->dev_size - *fpos;
    }

    read_buf = (char*)kmalloc(read_size, GFP_KERNEL);
    if(read_buf == NULL) {
        return -ENOMEM;
    }

    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)&vsd_dev->dma_op_complete_tsk;
    vsd_dev->hwregs->dma_paddr = virt_to_phys(read_buf);
    vsd_dev->hwregs->dma_size = read_size;
    vsd_dev->hwregs->dev_offset = *fpos;
    wmb();
    vsd_dev->hwregs->cmd = VSD_CMD_READ;

    wait_event(vsd_dev->wq, vsd_dev->hwregs->cmd == VSD_CMD_NONE);
    mutex_unlock(&vsd_dev->mtx);

    if (copy_to_user(read_user_buf, read_buf, read_size))
        return -EFAULT;
    *fpos += vsd_dev->hwregs->result;
    kfree(read_buf);
    return vsd_dev->hwregs->result;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    char* write_buf = NULL;

    pr_notice(LOG_TAG "vsd_dev_write\n");

    mutex_lock(&vsd_dev->mtx);

    if (*fpos >= vsd_dev->hwregs->dev_size) {
        return 0;
    }
    if (*fpos + write_size >= vsd_dev->hwregs->dev_size) {
        write_size = vsd_dev->hwregs->dev_size - *fpos;
    }

    write_buf = (char*)kzalloc(write_size, GFP_KERNEL);
    if(write_buf == NULL) {
        return -ENOMEM;
    }
    if (copy_from_user(write_buf, write_user_buf, write_size)) {
        return -EFAULT;
    }

    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)&vsd_dev->dma_op_complete_tsk;
    vsd_dev->hwregs->dma_paddr = virt_to_phys(write_buf);
    vsd_dev->hwregs->dma_size = write_size;
    vsd_dev->hwregs->dev_offset = *fpos;
    wmb();
    vsd_dev->hwregs->cmd = VSD_CMD_WRITE;

    wait_event(vsd_dev->wq, vsd_dev->hwregs->cmd == VSD_CMD_NONE);
    mutex_unlock(& vsd_dev->mtx);

    *fpos += vsd_dev->hwregs->result;
    kfree(write_buf);
    return vsd_dev->hwregs->result;
}

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
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

static long vsd_ioctl_get_size(vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;

    pr_notice(LOG_TAG "vsd_ioctl_get_size\n");

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    mutex_lock(&vsd_dev->mtx);
    arg.size = vsd_dev->hwregs->dev_size;
    mutex_unlock(&vsd_dev->mtx);

    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    vsd_ioctl_set_size_arg_t arg;

    pr_notice(LOG_TAG "vsd_ioctl_set_size\n");

    if (copy_from_user(&arg, uarg, sizeof(arg))) {
        return -EFAULT;
    }

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

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    pr_notice(LOG_TAG "vsd_dev_ioctl\n");
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

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .unlocked_ioctl = vsd_dev_ioctl
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
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

    init_waitqueue_head(&vsd_dev->wq);
    mutex_init(&vsd_dev->mtx);

    print_vsd_dev_hw_regs(vsd_dev);
    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

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
    pr_notice(LOG_TAG "init driver\n");
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
