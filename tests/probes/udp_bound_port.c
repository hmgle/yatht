#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    alarm(10);
    int domain = atoi(argv[1]) == 6 ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_DGRAM, 0);
    struct sockaddr_storage addr = {0};
    socklen_t len;
    unsigned short *port;
    if (domain == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&addr;
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        port = &v4->sin_port;
        len = sizeof(*v4);
    } else {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&addr;
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
        port = &v6->sin6_port;
        len = sizeof(*v6);
    }
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, len)) return 3;
    if (getsockname(fd, (struct sockaddr *)&addr, &len) || !*port) return 4;
    unsigned short bound_port = *port;
    int collision = socket(domain, SOCK_DGRAM, 0);
    errno = 0;
    if (bind(collision, (struct sockaddr *)&addr, len) != -1 || errno != EADDRINUSE) return 5;
    close(collision);
    int alias = dup(fd);
    close(fd);
    *port = htons(atoi(argv[2]));
    for (int i = 0; i < 2; ++i) {
        if (sendto(alias, &bound_port, sizeof(bound_port), 0,
                   (struct sockaddr *)&addr, len) != sizeof(bound_port)) return 6;
        unsigned short response = 0;
        if (recv(alias, &response, sizeof(response), 0) != sizeof(response)
            || response != bound_port) return 7;
        struct sockaddr_storage reported;
        socklen_t reported_len = sizeof(reported);
        if (getsockname(alias, (struct sockaddr *)&reported, &reported_len)) return 8;
        unsigned short actual = domain == AF_INET
            ? ((struct sockaddr_in *)&reported)->sin_port
            : ((struct sockaddr_in6 *)&reported)->sin6_port;
        if (actual != bound_port) return 9;
    }
    close(alias);
    return 0;
}
