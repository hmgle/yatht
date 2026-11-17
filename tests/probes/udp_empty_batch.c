#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    alarm(5);
    errno = 0;
    if (sendmmsg(-1, NULL, 0, 0) != -1 || errno != EBADF) return 1;
    int file = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (file < 0) return 2;
    errno = 0;
    if (sendmmsg(file, NULL, 0, 0) != -1 || errno != ENOTSOCK) return 3;
    close(file);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 4;
    if (sendmmsg(fd, NULL, 0, 0) != 0) return 5;
    if (sendmmsg(fd, (void *)1, 0, 0) != 0) return 6;
    errno = 0;
    if (sendmmsg(fd, NULL, 1, 0) != -1 || errno != EFAULT) return 7;
    return close(fd);
}
