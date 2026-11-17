#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    alarm(10);
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) return 2;
    struct timeval timeout = { .tv_sec = 2 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 3;
    struct sockaddr_in v4 = { .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons(atoi(argv[1])) };
    struct sockaddr_in6 v6 = { .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_LOOPBACK_INIT, .sin6_port = htons(atoi(argv[2])) };
    if (atoi(argv[3])) {
        /* Create a relay before either direct route chooses its transport. */
        struct sockaddr_in dns = { .sin_family = AF_INET, .sin_port = htons(53) };
        if (inet_pton(AF_INET, "198.51.100.1", &dns.sin_addr) != 1) return 4;
        if (sendto(fd, "p", 1, 0, (void *)&dns, sizeof(dns)) != 1) return 5;
        char response;
        if (recv(fd, &response, 1, 0) != 1 || response != 'p') return 6;
    }
    /* Exercise both family transitions while preserving the same socket. */
    for (int i = 0; i < 3; ++i) {
        void *dest = i == 1 ? (void *)&v6 : (void *)&v4;
        socklen_t len = i == 1 ? sizeof(v6) : sizeof(v4);
        char query = '0' + i, response;
        if (sendto(fd, &query, 1, 0, dest, len) != 1) return 7;
        if (recv(fd, &response, 1, 0) != 1 || response != query) return 8;
    }
    return close(fd);
}
