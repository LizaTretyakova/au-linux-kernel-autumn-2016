#include "vsd_device.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../vsd_driver/vsd_ioctl.h"

#define DEVICE_FILE_NAME "/dev/vsd"

static int filp = -1;
static int res = -1;
static int err = -1;

#define CHECK_STATE_CORRECTNESS(ret) \
    if (filp < 0) { \
        return ret; \
    }


int vsd_init()
{
    filp = open(DEVICE_FILE_NAME, O_RDWR);
    err = errno;
    CHECK_STATE_CORRECTNESS(err)
    return 0;
}

int vsd_deinit()
{
    CHECK_STATE_CORRECTNESS(err)
    close(filp);
    return 0;
}

int vsd_get_size(size_t *out_size)
{
    vsd_ioctl_get_size_arg_t arg;
    CHECK_STATE_CORRECTNESS(err)

    res = ioctl(filp, VSD_IOCTL_GET_SIZE, &arg);
    err = errno;
    if (res < 0) {
        return err;
    }

    *out_size = arg.size;

    return 0;
}

int vsd_set_size(size_t size)
{
    vsd_ioctl_set_size_arg_t arg;
    CHECK_STATE_CORRECTNESS(err)

    arg.size = size;

    res = ioctl(filp, VSD_IOCTL_SET_SIZE, &arg);
    err = errno;
    if (res < 0) {
        return err;
    }

    return 0;
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
    CHECK_STATE_CORRECTNESS(err)

    res = read(filp, dst + offset, size);
    err = errno;
    if(res < 0) {
        return -err;
    }

    return res;
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
    CHECK_STATE_CORRECTNESS(err)

    res = write(filp, src + offset, size);
    err = errno;
    if(res < 0) {
        return -err;
    }

    return res;
}

void* vsd_mmap(size_t offset)
{
    size_t size;
    CHECK_STATE_CORRECTNESS(NULL)

    if(vsd_get_size(&size) || offset % sysconf(_SC_PAGE_SIZE)) {
        return NULL;
    }

    return mmap(NULL, size - offset,
                PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANON,
                -1, offset);
}

int vsd_munmap(void* addr, size_t offset)
{
    CHECK_STATE_CORRECTNESS(err)

    return munmap(addr, offset);
}
