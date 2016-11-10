#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <vsd_ioctl.h>
#include <poll.h>
#include "vsd_device.h"

static int vsd_fd = -1;

int vsd_init()
{
    printf("TEST: vsd_init\n");

    vsd_fd = open("/dev/vsd", O_RDWR);
    return vsd_fd < 0 ? -1 : 0;
}

int vsd_deinit()
{
    printf("TEST: vsd_deinit\n");

    return close(vsd_fd);
}

int vsd_set_blocking(void)
{
    printf("TEST: vsd_set_blocking\n");

    int flags = fcntl(vsd_fd, F_GETFL, 0);
    if(flags < 0) {
        return -1;
    }
    flags &= ~O_NONBLOCK;
    return fcntl(vsd_fd, F_SETFL, flags) < 0 ? -1 : 0;
}

int vsd_set_nonblocking(void)
{
    printf("TEST: vsd_set_nonblocking\n");

    int flags = fcntl(vsd_fd, F_GETFL, 0);
    if(flags < 0) {
        return -1;
    }
    flags |=  O_NONBLOCK;
    return fcntl(vsd_fd, F_SETFL, flags) < 0 ? -1 : 0;
}

int vsd_get_size(size_t *out_size)
{
    printf("TEST: vsd_get_size\n");

    vsd_ioctl_get_size_arg_t arg;
    int ret = ioctl(vsd_fd, VSD_IOCTL_GET_SIZE, &arg);

    printf("TEST: ret %d\n", ret);

    if (!ret) {
        *out_size = arg.size;
    }
    return ret;
}

int vsd_set_size(size_t size)
{
    printf("TEST: vsd_set_size\n");

    vsd_ioctl_set_size_arg_t arg;
    arg.size = size;
    int ret = ioctl(vsd_fd, VSD_IOCTL_SET_SIZE, &arg);
    return ret;
}

ssize_t vsd_read(char* dst, size_t size, off_t offset)
{
    printf("TEST: vsd_read\n");

    if (lseek(vsd_fd, offset, SEEK_SET) == (off_t)-1)
        return -1;
    return read(vsd_fd, dst, size);
}

ssize_t vsd_write(const char* src, size_t size, off_t offset)
{
    printf("TEST: vsd_write\n");

    if (lseek(vsd_fd, offset, SEEK_SET) == (off_t)-1)
        return -1;
    return write(vsd_fd, src, size);
}

int vsd_wait_nonblock_write(void)
{
    printf("TEST: vsd_wait_nonblock_write\n");

    struct pollfd requests[1];
    requests[0].fd = vsd_fd;
    requests[0].events = POLLOUT;

    return poll(requests, 1, 0) < 0 ? -1 : 0;
}
