#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int check_local(int fd, const struct sockaddr_storage *expected, int port_locked) {
    struct sockaddr_storage actual = {0};
    socklen_t len = sizeof(actual);
    if (getsockname(fd, (void *)&actual, &len)) return -1;
    if (actual.ss_family != expected->ss_family) return -1;
    if (actual.ss_family == AF_INET) {
        const struct sockaddr_in *want = (const void *)expected, *got = (const void *)&actual;
        if (got->sin_addr.s_addr != want->sin_addr.s_addr ||
            got->sin_port != (port_locked ? want->sin_port : 0)) return -1;
    } else {
        const struct sockaddr_in6 *want = (const void *)expected, *got = (const void *)&actual;
        if (!IN6_ARE_ADDR_EQUAL(&got->sin6_addr, &want->sin6_addr) ||
            got->sin6_port != (port_locked ? want->sin6_port : 0)) return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 7) return 1;
    alarm(10);
    int domain = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    int binding = atoi(argv[3]); /* 0: autobind, 1: bind(0), 2: explicit port */
    int fd = socket(domain, SOCK_DGRAM, 0);
    if (fd < 0) return 2;
    struct sockaddr_storage local = {0}, dest = {0};
    socklen_t len = domain == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    unsigned short *port;
    if (domain == AF_INET) {
        struct sockaddr_in *addr = (void *)&local;
        addr->sin_family = AF_INET;
        port = &addr->sin_port;
        dest = local;
        ((struct sockaddr_in *)&dest)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ((struct sockaddr_in *)&dest)->sin_port = htons(atoi(argv[2]));
    } else {
        struct sockaddr_in6 *addr = (void *)&local;
        addr->sin6_family = AF_INET6;
        port = &addr->sin6_port;
        dest = local;
        ((struct sockaddr_in6 *)&dest)->sin6_addr = in6addr_loopback;
        ((struct sockaddr_in6 *)&dest)->sin6_port = htons(atoi(argv[2]));
    }
    if (domain == AF_INET) {
        if (inet_pton(domain, argv[6], &((struct sockaddr_in *)&local)->sin_addr) != 1) return 3;
    } else {
        if (inet_pton(domain, argv[6], &((struct sockaddr_in6 *)&local)->sin6_addr) != 1) return 3;
    }
    if (binding == 2) *port = htons(atoi(argv[5]));
    if (binding && bind(fd, (void *)&local, len)) return 4;
    struct timeval timeout = { .tv_sec = 2 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 5;
    if (sendto(fd, "x", 1, 0, (void *)&dest, len) != 1) return 6;
    char response;
    if (recv(fd, &response, 1, 0) != 1 || response != 'x') return 7;
    if (getsockname(fd, (void *)&local, &len) || !*port) return 8;
    if (atoi(argv[4])) {
        struct sockaddr_in dns = { .sin_family = AF_INET, .sin_port = htons(53) };
        if (inet_pton(AF_INET, "198.51.100.1", &dns.sin_addr) != 1 ||
            sendto(fd, "d", 1, 0, (void *)&dns, sizeof(dns)) != 1) return 9;
    }
    printf("ready %u\n", ntohs(*port));
    fflush(stdout);
    if (read(STDIN_FILENO, &response, 1) != 1) return 10;
    struct sockaddr disconnect = { .sa_family = AF_UNSPEC };
    if (connect(fd, &disconnect, sizeof(disconnect))) return 11;
    if (check_local(fd, &local, binding == 2)) {
        fputs("disconnect changed the bound address or port\n", stderr);
        return 12;
    }
    if (connect(fd, &disconnect, sizeof(disconnect)) ||
        check_local(fd, &local, binding == 2)) return 13;
    puts("released");
    fflush(stdout);
    if (read(STDIN_FILENO, &response, 1) != 1) return 15;
    if (binding == 0 && bind(fd, (void *)&local, len)) return 14;
    /* bind(0) must retain its source IP when sending again without a bind. */
    if (sendto(fd, "x", 1, 0, (void *)&dest, len) != 1 ||
        recv(fd, &response, 1, 0) != 1 || response != 'x') return 16;
    if (binding == 1) {
        /* Connecting must also reserve a new port on the retained address. */
        if (connect(fd, &disconnect, sizeof(disconnect)) || check_local(fd, &local, 0) ||
            connect(fd, (void *)&dest, len) || send(fd, "x", 1, 0) != 1 ||
            recv(fd, &response, 1, 0) != 1 || response != 'x') return 17;
        if (connect(fd, &disconnect, sizeof(disconnect)) || check_local(fd, &local, 0)) return 18;
        /* An explicit rebind may replace the retained IP. */
        struct sockaddr_storage rebound = dest;
        if (domain == AF_INET) ((struct sockaddr_in *)&rebound)->sin_port = 0;
        else ((struct sockaddr_in6 *)&rebound)->sin6_port = 0;
        if (bind(fd, (void *)&rebound, len) ||
            sendto(fd, "x", 1, 0, (void *)&dest, len) != 1 ||
            recv(fd, &response, 1, 0) != 1 || response != 'x') return 19;
    }
    return close(fd);
}
