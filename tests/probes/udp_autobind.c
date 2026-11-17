#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    alarm(10);
    for (int family = 0; family < 2; ++family) {
        int domain = family ? AF_INET6 : AF_INET;
        struct sockaddr_storage dest = {0}, local = {0};
        socklen_t len;
        if (family) {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&dest;
            v6->sin6_family = AF_INET6;
            v6->sin6_addr = in6addr_loopback;
            v6->sin6_port = htons(9);
            ((struct sockaddr_in6 *)&local)->sin6_family = AF_INET6;
            len = sizeof(*v6);
        } else {
            struct sockaddr_in *v4 = (struct sockaddr_in *)&dest;
            v4->sin_family = AF_INET;
            v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            v4->sin_port = htons(9);
            ((struct sockaddr_in *)&local)->sin_family = AF_INET;
            len = sizeof(*v4);
        }
        for (int op = 0; op < 4; ++op) {
            int fd = socket(domain, SOCK_DGRAM, 0);
            if (fd < 0) return 2;
            struct iovec iov = { .iov_base = "x", .iov_len = 1 };
            struct mmsghdr msg = {0};
            msg.msg_hdr.msg_name = &dest;
            msg.msg_hdr.msg_namelen = len;
            msg.msg_hdr.msg_iov = &iov;
            msg.msg_hdr.msg_iovlen = 1;
            if (op == 0 && sendto(fd, "x", 1, 0, (struct sockaddr *)&dest, len) != 1) return 3;
            if (op == 1 && sendmsg(fd, &msg.msg_hdr, 0) != 1) return 4;
            if (op == 2 && sendmmsg(fd, &msg, 1, 0) != 1) return 5;
            if (op == 3 && connect(fd, (struct sockaddr *)&dest, len)) return 6;
            struct sockaddr_storage reported;
            socklen_t reported_len = sizeof(reported);
            if (getsockname(fd, (struct sockaddr *)&reported, &reported_len)) return 7;
            unsigned short port = family ? ((struct sockaddr_in6 *)&reported)->sin6_port
                : ((struct sockaddr_in *)&reported)->sin_port;
            if (!port) return 8;
            errno = 0;
            if (bind(fd, (struct sockaddr *)&local, len) != -1 || errno != EINVAL) return 9;
            if (op == 3) {
                struct sockaddr disconnect = { .sa_family = AF_UNSPEC };
                if (connect(fd, &disconnect, sizeof(disconnect))) return 10;
                if (bind(fd, (struct sockaddr *)&local, len)) return 11;
                if (connect(fd, (struct sockaddr *)&dest, len) ||
                    connect(fd, &disconnect, sizeof(disconnect))) return 12;
                /* bind(0), unlike a nonzero explicit port, is also released
                   by disconnect in Linux. */
                if (bind(fd, (struct sockaddr *)&local, len)) return 13;
            }
            close(fd);
        }
    }
    return 0;
}
