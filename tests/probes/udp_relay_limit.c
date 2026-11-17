#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int expect_enobufs(const char *operation, long result) {
    if (result == -1 && errno == ENOBUFS) return 0;
    fprintf(stderr, "%s: result=%ld errno=%d, expected ENOBUFS\n",
            operation, result, errno);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    alarm(15);
    int stable = strcmp(argv[1], "stable") == 0;
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(9),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int held[128];
    for (int i = 0; i < 128; ++i) {
        held[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (held[i] < 0) { perror("socket within budget"); return 2; }
        // Lazy connect creates a relay without sending or contacting a proxy.
        if (!stable && connect(held[i], (struct sockaddr *)&dest, sizeof(dest))) {
            perror("connect within budget");
            return 3;
        }
    }

    errno = 0;
    int extra = socket(AF_INET, SOCK_DGRAM, 0);
    if (stable) {
        if (expect_enobufs("socket", extra)) return 4;
    } else {
        if (extra < 0) { perror("lazy socket"); return 5; }
        errno = 0;
        if (expect_enobufs("connect", connect(extra, (struct sockaddr *)&dest,
                                              sizeof(dest)))) return 6;
        errno = 0;
        if (expect_enobufs("sendto", sendto(extra, "x", 1, 0,
                                             (struct sockaddr *)&dest,
                                             sizeof(dest)))) return 7;
        struct iovec iov = { .iov_base = (void *)"x", .iov_len = 1 };
        struct mmsghdr msg = { .msg_hdr = {
            .msg_name = &dest,
            .msg_namelen = sizeof(dest),
            .msg_iov = &iov,
            .msg_iovlen = 1,
        } };
        errno = 0;
        if (expect_enobufs("sendmsg", sendmsg(extra, &msg.msg_hdr, 0))) return 8;
        errno = 0;
        if (expect_enobufs("sendmmsg", sendmmsg(extra, &msg, 1, 0))) return 9;
        close(extra);
    }

    // Failed admissions must not consume capacity needed after a target close.
    close(held[0]);
    int recovered = socket(AF_INET, SOCK_DGRAM, 0);
    if (recovered < 0) { perror("socket after close"); return 10; }
    if (!stable && connect(recovered, (struct sockaddr *)&dest, sizeof(dest))) {
        perror("connect after close");
        return 11;
    }
    close(recovered);
    for (int i = 1; i < 128; ++i) close(held[i]);
    return 0;
}
