#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct endpoint {
    struct sockaddr_storage address;
    socklen_t length;
    int family;
    int socktype;
    int protocol;
};

static uint64_t monotonic_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t timeval_ns(struct timeval value) {
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
           (uint64_t)value.tv_usec * UINT64_C(1000);
}

static size_t parse_size(const char *raw, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0' || value > SIZE_MAX) {
        fprintf(stderr, "invalid %s: %s\n", name, raw);
        exit(2);
    }
    return (size_t)value;
}

static struct endpoint resolve_endpoint(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *results = NULL;
    int rc = getaddrinfo(host, port, &hints, &results);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        exit(2);
    }
    if (results == NULL || results->ai_addrlen > sizeof(struct sockaddr_storage)) {
        fprintf(stderr, "no usable endpoint\n");
        freeaddrinfo(results);
        exit(2);
    }

    struct endpoint endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    memcpy(&endpoint.address, results->ai_addr, results->ai_addrlen);
    endpoint.length = (socklen_t)results->ai_addrlen;
    endpoint.family = results->ai_family;
    endpoint.socktype = results->ai_socktype;
    endpoint.protocol = results->ai_protocol;
    freeaddrinfo(results);
    return endpoint;
}

static int connect_endpoint(const struct endpoint *endpoint, uint64_t *elapsed_ns) {
    int fd = socket(endpoint->family, endpoint->socktype | SOCK_CLOEXEC, endpoint->protocol);
    if (fd < 0) {
        return -1;
    }
    uint64_t started = monotonic_ns();
    int rc = connect(fd, (const struct sockaddr *)&endpoint->address, endpoint->length);
    int saved_errno = errno;
    *elapsed_ns = monotonic_ns() - started;
    if (rc != 0) {
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int write_all(int fd, const uint8_t *buffer, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = send(fd, buffer + offset, length - offset, MSG_NOSIGNAL);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}

static int run_request(const struct endpoint *endpoint, size_t flows, size_t payload_size) {
    uint8_t *payload = malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL) {
        perror("malloc");
        return 2;
    }
    memset(payload, 0x5a, payload_size);
    size_t successful = 0;
    uint64_t total_bytes = 0;

    for (size_t flow = 0; flow < flows; ++flow) {
        uint64_t flow_started = monotonic_ns();
        uint64_t connect_ns = 0;
        int fd = connect_endpoint(endpoint, &connect_ns);
        if (fd < 0) {
            int error = errno;
            printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":false,"
                   "\"errno\":%d,\"connect_ns\":%" PRIu64 "}\n",
                   flow, error, connect_ns);
            continue;
        }

        int error = 0;
        if (write_all(fd, payload, payload_size) != 0 || shutdown(fd, SHUT_WR) != 0) {
            error = errno;
        }
        size_t received = 0;
        uint64_t first_response_ns = 0;
        uint8_t buffer[16384];
        while (error == 0) {
            ssize_t count = recv(fd, buffer, sizeof(buffer), 0);
            if (first_response_ns == 0) {
                first_response_ns = monotonic_ns() - flow_started;
            }
            if (count > 0) {
                for (ssize_t index = 0; index < count; ++index) {
                    if (buffer[index] != 0x5a) {
                        error = EPROTO;
                        break;
                    }
                }
                received += (size_t)count;
                continue;
            }
            if (count == 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            error = errno;
        }
        close(fd);
        if (error == 0 && received != payload_size) {
            error = EIO;
        }
        uint64_t total_ns = monotonic_ns() - flow_started;
        if (error == 0) {
            ++successful;
            total_bytes += payload_size * 2;
            printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":true,"
                   "\"connect_ns\":%" PRIu64 ",\"first_response_ns\":%" PRIu64
                   ",\"total_ns\":%" PRIu64 ",\"bytes\":%zu}\n",
                   flow, connect_ns, first_response_ns, total_ns, payload_size * 2);
        } else {
            printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":false,"
                   "\"errno\":%d,\"connect_ns\":%" PRIu64
                   ",\"total_ns\":%" PRIu64 "}\n",
                   flow, error, connect_ns, total_ns);
        }
    }
    free(payload);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        return 2;
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"request\","
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":%" PRIu64
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           flows, successful, total_bytes, timeval_ns(usage.ru_utime),
           timeval_ns(usage.ru_stime));
    return successful == flows ? 0 : 1;
}

static int run_idle(const struct endpoint *endpoint, size_t flows, size_t hold_ms) {
    int *fds = malloc(flows * sizeof(*fds));
    if (fds == NULL) {
        perror("malloc");
        return 2;
    }
    for (size_t index = 0; index < flows; ++index) {
        fds[index] = -1;
    }
    size_t successful = 0;
    for (size_t flow = 0; flow < flows; ++flow) {
        uint64_t connect_ns = 0;
        fds[flow] = connect_endpoint(endpoint, &connect_ns);
        int error = fds[flow] < 0 ? errno : 0;
        if (error == 0) {
            ++successful;
        }
        printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":%s,"
               "\"errno\":%d,\"connect_ns\":%" PRIu64 "}\n",
               flow, error == 0 ? "true" : "false", error, connect_ns);
    }
    struct timespec hold = {
        .tv_sec = (time_t)(hold_ms / 1000),
        .tv_nsec = (long)((hold_ms % 1000) * 1000000),
    };
    while (nanosleep(&hold, &hold) != 0 && errno == EINTR) {
    }
    for (size_t flow = 0; flow < flows; ++flow) {
        if (fds[flow] >= 0) {
            close(fds[flow]);
        }
    }
    free(fds);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        return 2;
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"idle\","
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":0,"
           "\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           flows, successful, timeval_ns(usage.ru_utime), timeval_ns(usage.ru_stime));
    return successful == flows ? 0 : 1;
}

static int run_stalled(const struct endpoint *endpoint, size_t flows,
                       size_t bytes_per_flow, size_t hold_ms) {
    int *fds = malloc(flows * sizeof(*fds));
    uint8_t *payload = malloc(65536);
    if (fds == NULL || payload == NULL) {
        perror("malloc");
        free(fds);
        free(payload);
        return 2;
    }
    memset(payload, 0x5a, 65536);
    for (size_t index = 0; index < flows; ++index) {
        fds[index] = -1;
    }

    size_t successful = 0;
    uint64_t total_bytes = 0;
    for (size_t flow = 0; flow < flows; ++flow) {
        uint64_t connect_ns = 0;
        fds[flow] = connect_endpoint(endpoint, &connect_ns);
        int error = fds[flow] < 0 ? errno : 0;
        size_t sent = 0;
        while (error == 0 && sent < bytes_per_flow) {
            size_t chunk = (bytes_per_flow - sent) < 65536 ?
                           (bytes_per_flow - sent) : 65536;
            if (write_all(fds[flow], payload, chunk) != 0) {
                error = errno;
                break;
            }
            sent += chunk;
        }
        if (error == 0) {
            ++successful;
            total_bytes += sent;
        }
        printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":%s,"
               "\"errno\":%d,\"connect_ns\":%" PRIu64
               ",\"bytes\":%zu}\n",
               flow, error == 0 ? "true" : "false", error, connect_ns, sent);
    }

    struct timespec hold = {
        .tv_sec = (time_t)(hold_ms / 1000),
        .tv_nsec = (long)((hold_ms % 1000) * 1000000),
    };
    while (nanosleep(&hold, &hold) != 0 && errno == EINTR) {
    }
    for (size_t flow = 0; flow < flows; ++flow) {
        if (fds[flow] >= 0) {
            close(fds[flow]);
        }
    }
    free(fds);
    free(payload);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        return 2;
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"stalled\","
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":%" PRIu64
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           flows, successful, total_bytes, timeval_ns(usage.ru_utime),
           timeval_ns(usage.ru_stime));
    return successful == flows ? 0 : 1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc != 6 && argc != 7) {
        fprintf(stderr,
                "usage: %s request HOST PORT FLOWS PAYLOAD_BYTES\n"
                "       %s idle HOST PORT FLOWS HOLD_MS\n"
                "       %s stalled HOST PORT FLOWS BYTES_PER_FLOW HOLD_MS\n",
                argv[0], argv[0], argv[0]);
        return 2;
    }
    struct endpoint endpoint = resolve_endpoint(argv[2], argv[3]);
    size_t flows = parse_size(argv[4], "flows");
    size_t value = parse_size(argv[5], "payload bytes or hold milliseconds");
    if (strcmp(argv[1], "request") == 0 && argc == 6) {
        return run_request(&endpoint, flows, value);
    }
    if (strcmp(argv[1], "idle") == 0 && argc == 6) {
        return run_idle(&endpoint, flows, value);
    }
    if (strcmp(argv[1], "stalled") == 0 && argc == 7) {
        return run_stalled(&endpoint, flows, value,
                           parse_size(argv[6], "hold milliseconds"));
    }
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
