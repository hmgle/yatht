#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d errno %d\n", __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv) {
    CHECK(argc == 5);
    alarm(10);
    int family = strchr(argv[1], ':') ? AF_INET6 : AF_INET;
    int fd = socket(family, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_storage addr = {0};
    socklen_t addrlen;
    if (family == AF_INET) {
        struct sockaddr_in *v4 = (void *)&addr;
        v4->sin_family = family;
        v4->sin_port = htons(atoi(argv[2]));
        CHECK(inet_pton(family, argv[1], &v4->sin_addr) == 1);
        addrlen = sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (void *)&addr;
        v6->sin6_family = family;
        v6->sin6_port = htons(atoi(argv[2]));
        CHECK(inet_pton(family, argv[1], &v6->sin6_addr) == 1);
        addrlen = sizeof(*v6);
    }
    size_t limit = strtoul(argv[3], NULL, 10);
    int batch_first = atoi(argv[4]);
    unsigned char buf[65536];
    memset(buf, 0x5a, sizeof(buf));
    struct timeval timeout = { .tv_sec = 3 };
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    struct iovec iov = { buf, limit + 1 };
    struct msghdr msg = { .msg_name = &addr, .msg_namelen = addrlen,
        .msg_iov = &iov, .msg_iovlen = 1 };
    struct iovec first = { buf, 1 };
    struct mmsghdr batch[2] = { { .msg_hdr = msg }, { .msg_hdr = msg } };
    batch[0].msg_hdr.msg_iov = &first;
    if (!batch_first) {
        errno = 0;
        CHECK(sendto(fd, buf, limit + 1, 0, (void *)&addr, addrlen) == -1 && errno == EMSGSIZE);
        errno = 0;
        CHECK(sendmsg(fd, &msg, 0) == -1 && errno == EMSGSIZE);
    }
    CHECK(sendmmsg(fd, batch, 2, 0) == 1);
    CHECK(batch[0].msg_len == 1);
    CHECK(recv(fd, buf, sizeof(buf), 0) == 1);
    CHECK(connect(fd, (void *)&addr, addrlen) == 0);
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    errno = 0;
    CHECK(sendto(fd, buf, limit + 1, 0, NULL, 0) == -1 && errno == EMSGSIZE);
    errno = 0;
    CHECK(sendmsg(fd, &msg, 0) == -1 && errno == EMSGSIZE);
    struct mmsghdr unnamed = { .msg_hdr = msg };
    errno = 0;
    CHECK(sendmmsg(fd, &unnamed, 1, 0) == -1 && errno == EMSGSIZE);
    CHECK(sendto(fd, buf, limit, 0, (void *)&addr, addrlen) == (ssize_t)limit);
    CHECK(recv(fd, buf, sizeof(buf), 0) == (ssize_t)limit);
    for (size_t i = 0; i < limit; ++i) CHECK(buf[i] == 0x5a);
    close(fd);
    return 0;
}
