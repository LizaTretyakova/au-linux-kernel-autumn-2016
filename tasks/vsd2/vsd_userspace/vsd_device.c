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

    printf("VSD_WRITE: src %p, offt %zu, size %zu\n", src, offset, size);
    res = write(filp, src + offset, size);
    err = errno;
    printf("%d\n", res);
    if(res < 0) {
        return -err;
    }

    return res;
}

void* vsd_mmap(size_t offset)
{
    size_t size;
    void* ret;
    CHECK_STATE_CORRECTNESS(NULL)

    printf("VSD_MMAP: offset %zu\n", offset);

    if(vsd_get_size(&size) || offset % sysconf(_SC_PAGE_SIZE)) {
        return NULL;
    }

    printf("VSD_MMAP: size %zu\n", size);
    printf("VSD_MMAP: filp %d\n", filp);

    ret = mmap(NULL, size - offset,
               PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED,
               filp, offset);
    if(ret == MAP_FAILED) {
        return NULL;
    }
    return ret;
}

int vsd_munmap(void* addr, size_t offset)
{
    size_t size;
    CHECK_STATE_CORRECTNESS(err)

    if(vsd_get_size(&size)) {
        return -1;
    }

    return munmap(addr,  - offset);
}
