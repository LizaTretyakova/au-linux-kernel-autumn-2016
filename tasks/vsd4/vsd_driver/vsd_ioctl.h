#ifndef _VSD_UAPI_H
#define _VSD_UAPI_H

#ifdef __KERNEL__
#include <asm/ioctl.h>
#else
#include <sys/ioctl.h>
#include <stddef.h>
#endif //__KERNEL__

#define VSD_IOCTL_MAGIC 'V'

#define VSD_CMD_NONE 0
#define VSD_CMD_WRITE 1
#define VSD_CMD_READ 2
#define VSD_CMD_SET_SIZE 3
#define VSD_CMD_GET_SIZE 4
#define VSD_CMD_LLSEEK 5

#define READY 1
#define NOT_READY 0

typedef struct vsd_ioctl_get_size_arg {
    unsigned long size;
} vsd_ioctl_get_size_arg_t;

typedef struct vsd_ioctl_set_size_arg {
    unsigned long size;
} vsd_ioctl_set_size_arg_t;

#define VSD_IOCTL_GET_SIZE \
    _IOR(VSD_IOCTL_MAGIC, 1, vsd_ioctl_get_size_arg_t)
#define VSD_IOCTL_SET_SIZE \
    _IOW(VSD_IOCTL_MAGIC, 2, vsd_ioctl_set_size_arg_t)

#endif //_VSD_UAPI_H
