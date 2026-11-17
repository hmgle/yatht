#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d errno %d\n", __LINE__, errno); return 1; } } while (0)
static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    alarm(12);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_in dns = { .sin_family = AF_INET, .sin_port = htons(53) };
    CHECK(inet_pton(AF_INET, "198.51.100.1", &dns.sin_addr) == 1);
    struct timeval timeout = { .tv_sec = 2 };
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    char buf[60000] = {0};
    CHECK(sendto(fd, buf, 2, 0, (void *)&dns, sizeof(dns)) == 2);
    CHECK(recv(fd, buf, sizeof(buf), 0) == 2);
    /* The fake DNS server now stops reading. Require sustained queue pressure
       after transport setup, not a transient full queue while handshaking. */
    double started = now(), blocked = 0;
    int sent = 0;
    while (now() - started < 4) {
        ssize_t rc = sendto(fd, buf, sizeof(buf), MSG_DONTWAIT, (void *)&dns, sizeof(dns));
        if (rc == sizeof(buf)) {
            ++sent;
            blocked = 0;
        } else {
            CHECK(rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
            if (!blocked) blocked = now();
            if (now() - blocked >= 0.15) break;
            usleep(1000);
        }
    }
    CHECK(blocked && now() - blocked >= 0.15 && sent >= 16);
    for (int route = 0; route < 2; ++route) {
        struct sockaddr_in dest = { .sin_family = AF_INET,
            .sin_port = htons(route ? 1234 : atoi(argv[1])) };
        CHECK(inet_pton(AF_INET, route ? "198.51.100.2" : "127.0.0.1", &dest.sin_addr) == 1);
        const char *payload = route ? "socks" : "direct";
        size_t len = strlen(payload);
        started = now();
        CHECK(sendto(fd, payload, len, 0, (void *)&dest, sizeof(dest)) == (ssize_t)len);
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);
        CHECK(recvfrom(fd, buf, sizeof(buf), 0, (void *)&source, &source_len) == (ssize_t)len);
        CHECK(memcmp(buf, payload, len) == 0);
        CHECK(source.sin_addr.s_addr == dest.sin_addr.s_addr && source.sin_port == dest.sin_port);
        CHECK(now() - started < 2);
        printf("%s %.3fs\n", payload, now() - started);
    }
    close(fd);
    return 0;
}
