#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int option(int fd, int name, int expected) {
    int value = -1;
    socklen_t len = sizeof(value);
    return getsockopt(fd, SOL_SOCKET, name, &value, &len) ||
        len != sizeof(value) || value != expected;
}

int main(void) {
    alarm(10);
    for (int bound = 0; bound < 2; ++bound) {
        for (int connected = 0; connected < 2; ++connected) {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return 2;
            struct sockaddr_in local = { .sin_family = AF_INET };
            if (bound && bind(fd, (struct sockaddr *)&local, sizeof(local))) return 3;
            socklen_t len = sizeof(local);
            if (getsockname(fd, (struct sockaddr *)&local, &len)) return 4;
            struct sockaddr_in dest = { .sin_family = AF_INET, .sin_port = htons(53) };
            inet_pton(AF_INET, "198.51.100.12", &dest.sin_addr);
            if (connected && connect(fd, (struct sockaddr *)&dest, sizeof(dest))) return 5;
            if (sendto(fd, "x", 1, 0, (struct sockaddr *)&dest, sizeof(dest)) != 1) return 6;
            int alias = dup(fd);
            close(fd);
            if (option(alias, SO_DOMAIN, AF_INET) || option(alias, SO_TYPE, SOCK_DGRAM) ||
                option(alias, SO_PROTOCOL, IPPROTO_UDP) || option(alias, SO_ERROR, 0)) return 7;
            struct sockaddr_in actual;
            len = sizeof(actual);
            if (getsockname(alias, (struct sockaddr *)&actual, &len) ||
                len != sizeof(actual) || actual.sin_family != AF_INET ||
                actual.sin_port != local.sin_port ||
                actual.sin_addr.s_addr != local.sin_addr.s_addr) return 8;
            errno = 0;
            len = sizeof(actual);
            int rc = getpeername(alias, (struct sockaddr *)&actual, &len);
            if (connected) {
                if (rc || len != sizeof(actual) || actual.sin_family != AF_INET ||
                    actual.sin_port != dest.sin_port ||
                    actual.sin_addr.s_addr != dest.sin_addr.s_addr) return 9;
            } else if (rc != -1 || errno != ENOTCONN) return 10;
            close(alias);
        }
    }
    return 0;
}
