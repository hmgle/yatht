#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 6) return 1;
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
    puts("released");
    fflush(stdout);
    if (read(STDIN_FILENO, &response, 1) != 1) return 15;
    if (binding != 2 && bind(fd, (void *)&local, len)) return 14;
    /* The cache must follow the replacement reservation after rebind. */
    if (sendto(fd, "x", 1, 0, (void *)&dest, len) != 1 ||
        recv(fd, &response, 1, 0) != 1 || response != 'x') return 16;
    return close(fd);
}
