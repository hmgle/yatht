#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    alarm(15);
    struct sockaddr_in dest = { .sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[2])) };
    if (inet_pton(AF_INET, argv[1], &dest.sin_addr) != 1) return 2;
    if (strcmp(argv[3], "churn") == 0) {
        puts("ready");
        fflush(stdout);
        char start;
        if (read(STDIN_FILENO, &start, 1) != 1) return 12;
        for (int i = 0; i < 2000; ++i) {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) return 3;
            if (sendto(fd, "xx", 2, 0, (void *)&dest, sizeof(dest)) != 2) return 4;
            /* Give the writer a chance to send before closing its target. */
            usleep(1000);
            close(fd);
        }
        puts("closed");
        fflush(stdout);
        char done;
        return read(STDIN_FILENO, &done, 1) == 1 ? 0 : 5;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 6;
    struct timeval timeout = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 7;
    if (strcmp(argv[3], "dns-sources") == 0) {
        for (unsigned char i = 0; i < 4; ++i) {
            struct sockaddr_in to = dest;
            to.sin_addr.s_addr = htonl(ntohl(dest.sin_addr.s_addr) + i % 2);
            /* All queries deliberately share a DNS transaction ID. */
            unsigned char query[3] = { 0x12, 0x34, i };
            if (sendto(fd, query, 3, 0, (void *)&to, sizeof(to)) != 3) return 13;
        }
        unsigned int seen = 0;
        for (int i = 0; i < 4; ++i) {
            unsigned char response[3];
            struct sockaddr_in source;
            socklen_t len = sizeof(source);
            if (recvfrom(fd, response, 3, 0, (void *)&source, &len) != 3) return 14;
            if (response[0] != 0x12 || response[1] != 0x34 || response[2] >= 4) return 15;
            unsigned int index = response[2];
            if (seen & (1u << index)) return 16;
            seen |= 1u << index;
            if (source.sin_addr.s_addr != htonl(ntohl(dest.sin_addr.s_addr) + index % 2) ||
                source.sin_port != dest.sin_port) return 17;
        }
        close(fd);
        return seen == 15 ? 0 : 18;
    }
    for (unsigned char i = 0; i < 6; ++i) {
        unsigned char query[2] = { i, 0 };
        if (sendto(fd, query, sizeof(query), 0, (void *)&dest, sizeof(dest)) != 2) return 8;
    }
    /* The peer waits for the entire burst before sending anything, then
       returns delayed, reordered replies plus one extra datagram. */
    for (int i = 0; i < 7; ++i) {
        unsigned char response[2];
        struct sockaddr_in source;
        socklen_t len = sizeof(source);
        int expected = i < 6 ? 5 - i : 6;
        if (recvfrom(fd, response, sizeof(response), 0, (void *)&source, &len) != 2) return 9;
        if (response[0] != expected || response[1] != 1) return 10;
        if (len != sizeof(source) || source.sin_family != AF_INET ||
            source.sin_addr.s_addr != dest.sin_addr.s_addr || source.sin_port != dest.sin_port) return 11;
    }
    close(fd);
    puts("independent-io-ok");
    return 0;
}
