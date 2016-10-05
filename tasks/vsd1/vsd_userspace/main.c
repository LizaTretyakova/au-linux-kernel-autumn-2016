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

#define SIZE_GET "size_get"
#define SIZE_SET "size_set"
#define DEVICE_FILE_NAME "/dev/vsd"

static int read_size_arg(size_t* size, char* startptr) {
    char* endptr;
    long int new_size;

    errno = 0;
    new_size = strtol(startptr, &endptr, 10);
    if ((errno == ERANGE && (new_size == LONG_MAX || new_size == LONG_MIN))
                || (errno != 0 && new_size == 0)) {
        perror("Invalid size argument");
        return -1;
    }
    if (new_size < 0 || new_size > SIZE_MAX || *endptr != 0) {
        printf("Invalid size argument! New size: %ld. *endptr: %d\n", new_size, *endptr);
        return -1;
    }

    *size = new_size;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Not enough arguments!\n");
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        if (strcmp(argv[1], SIZE_GET) == 0) {
            vsd_ioctl_get_size_arg_t arg;
            int filp;
            int res;

            filp = open(DEVICE_FILE_NAME, 0);
            if (filp < 0) {
                perror("Failed to open VSD");
                return EXIT_FAILURE;
            }

            res = ioctl(filp, VSD_IOCTL_GET_SIZE, &arg);
            if (res < 0) {
                perror("Failed to get the VSD size");
                close(filp);
                return EXIT_FAILURE;
            }

            printf("The size of the device is %zd.\n", arg.size);
            close(filp);

            return EXIT_SUCCESS;
        } else {
            if (strcmp(argv[1], SIZE_SET) == 0) {
                printf("Invalid argument: you need to specify the desired size.\n");
            } else {
                printf("Invalid argument. Try again!\n");
            }

            return EXIT_FAILURE;
        }
    }
    if (argc == 3) {
        // The code below is slightly different from the GET-version
        // so I don't think it's worth extracting it into a function.
        if (strcmp(argv[1], SIZE_SET) == 0) {
            vsd_ioctl_set_size_arg_t arg;
            int filp;
            int res;

            if (read_size_arg(&(arg.size), argv[2]) < 0) {
                return EXIT_FAILURE;
            }

            filp = open(DEVICE_FILE_NAME, 0);
            if (filp < 0) {
                perror("Failed to open VSD");
                return EXIT_FAILURE;
            }

            res = ioctl(filp, VSD_IOCTL_SET_SIZE, &arg);
            if (res < 0) {
                perror("Failed to get the VSD size");
                close(filp);
                return EXIT_FAILURE;
            }

            printf("The new size of the device is now %zd.\n", arg.size);
            close(filp);

            return EXIT_SUCCESS;
        } else {
            printf("Invalid argument. Try again!\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_FAILURE;
}
