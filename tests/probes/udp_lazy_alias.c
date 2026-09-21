#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int exchange(int fd, struct sockaddr_in *dest) {
    if (sendto(fd, "alias", 5, 0, (struct sockaddr *)dest, sizeof(*dest)) != 5) return 1;
    char buf[16];
    if (recv(fd, buf, sizeof(buf), 0) != 5 || memcmp(buf, "alias", 5)) return 2;
    errno = 0;
    if (sendto(fd, "x", 1, 0, NULL, 0) != -1 || errno != EDESTADDRREQ) return 3;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    alarm(10);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local = { .sin_family = AF_INET };
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local))) return 3;
    struct sockaddr_in dest = { .sin_family = AF_INET };
    char *colon = strrchr(argv[1], ':');
    if (!colon) return 4;
    *colon = 0;
    dest.sin_port = htons(atoi(colon + 1));
    if (inet_pton(AF_INET, argv[1], &dest.sin_addr) != 1) return 5;
    if (exchange(fd, &dest)) return 6; /* Replace before creating aliases. */
    int alias = dup(fd);
    if (alias < 0 || exchange(alias, &dest)) return 7;
    if (dup2(alias, 100) != 100 || exchange(100, &dest)) return 8;
    if (dup3(alias, 101, O_CLOEXEC) != 101 || exchange(101, &dest)) return 9;
    close(fd);
    close(alias);
    close(100);
    int pipefd[2];
    if (pipe(pipefd)) return 10;
    pid_t child = fork();
    if (child < 0) return 11;
    if (child == 0) {
        close(pipefd[1]);
        char token;
        if (read(pipefd[0], &token, 1) != 1) _exit(12);
        _exit(exchange(101, &dest));
    }
    close(101); /* Child's previously unseen alias is now the only owner. */
    close(pipefd[0]);
    if (write(pipefd[1], "x", 1) != 1) return 13;
    close(pipefd[1]);
    int status;
    if (waitpid(child, &status, 0) != child) return 14;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 15;
}
