#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <poll.h>
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
                       size_t bytes_per_flow, size_t hold_ms,
                       const char *ready_path) {
    struct stalled_flow {
        int fd;
        int error;
        int blocked;
        uint64_t started_ns;
        uint64_t connect_ns;
        uint64_t first_eagain_ns;
        size_t attempted;
        size_t accepted;
    };
    struct stalled_flow *states = calloc(flows, sizeof(*states));
    uint8_t *payload = malloc(65536);
    if (states == NULL || payload == NULL) {
        perror("malloc");
        free(states);
        free(payload);
        return 2;
    }
    memset(payload, 0x5a, 65536);
    for (size_t index = 0; index < flows; ++index) {
        states[index].fd = -1;
    }

    for (size_t flow = 0; flow < flows; ++flow) {
        struct stalled_flow *state = &states[flow];
        state->started_ns = monotonic_ns();
        state->fd = connect_endpoint(endpoint, &state->connect_ns);
        if (state->fd < 0) {
            state->error = errno;
            continue;
        }
        int send_buffer = 4096;
        if (setsockopt(state->fd, SOL_SOCKET, SO_SNDBUF, &send_buffer,
                       sizeof(send_buffer)) != 0) {
            state->error = errno;
            continue;
        }
        int flags = fcntl(state->fd, F_GETFL);
        if (flags < 0 || fcntl(state->fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            state->error = errno;
        }
    }

    size_t settled = 0;
    while (settled < flows) {
        settled = 0;
        for (size_t flow = 0; flow < flows; ++flow) {
            struct stalled_flow *state = &states[flow];
            if (state->error != 0 || state->blocked ||
                state->accepted == bytes_per_flow) {
                ++settled;
                continue;
            }
            size_t chunk = bytes_per_flow - state->accepted;
            if (chunk > 65536) {
                chunk = 65536;
            }
            state->attempted += chunk;
            ssize_t written = send(state->fd, payload, chunk, MSG_NOSIGNAL);
            if (written > 0) {
                state->accepted += (size_t)written;
            } else if (written == 0) {
                state->error = EIO;
            } else if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                state->blocked = 1;
                state->first_eagain_ns = monotonic_ns() - state->started_ns;
            } else {
                state->error = errno;
            }
        }
    }

    size_t blocked_flows = 0;
    for (size_t flow = 0; flow < flows; ++flow) {
        blocked_flows += states[flow].blocked != 0;
    }
    FILE *ready = fopen(ready_path, "w");
    if (ready == NULL) {
        perror("fopen stalled ready path");
        for (size_t flow = 0; flow < flows; ++flow) {
            if (states[flow].fd >= 0) {
                close(states[flow].fd);
            }
        }
        free(states);
        free(payload);
        return 2;
    }
    fprintf(ready, "%zu\n", blocked_flows);
    if (fclose(ready) != 0) {
        perror("close stalled ready path");
        free(states);
        free(payload);
        return 2;
    }

    size_t successful = 0;
    uint64_t total_bytes = 0;
    for (size_t flow = 0; flow < flows; ++flow) {
        struct stalled_flow *state = &states[flow];
        if (state->fd >= 0 && state->error == 0) {
            int flags = fcntl(state->fd, F_GETFL);
            if (flags < 0 || fcntl(state->fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
                state->error = errno;
            }
        }
        while (state->error == 0 && state->accepted < bytes_per_flow) {
            size_t chunk = bytes_per_flow - state->accepted;
            if (chunk > 65536) {
                chunk = 65536;
            }
            state->attempted += chunk;
            ssize_t written = send(state->fd, payload, chunk, MSG_NOSIGNAL);
            if (written > 0) {
                state->accepted += (size_t)written;
            } else if (written < 0 && errno == EINTR) {
                continue;
            } else {
                state->error = written == 0 ? EIO : errno;
            }
        }
        if (state->error == 0 && shutdown(state->fd, SHUT_WR) != 0) {
            state->error = errno;
        }
        uint8_t drain[1];
        while (state->error == 0) {
            ssize_t count = recv(state->fd, drain, sizeof(drain), 0);
            if (count > 0) {
                state->error = EPROTO;
            } else if (count == 0) {
                break;
            } else if (errno != EINTR) {
                state->error = errno;
            }
        }
        if (state->fd >= 0) {
            close(state->fd);
        }
        int ok = state->error == 0 && state->blocked &&
                 state->accepted == bytes_per_flow;
        if (ok) {
            ++successful;
            total_bytes += state->accepted;
        }
        printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":%s,"
               "\"errno\":%d,\"connect_ns\":%" PRIu64
               ",\"attempted_bytes\":%zu,\"accepted_bytes\":%zu,"
               "\"blocked\":%s,\"first_eagain_ns\":%" PRIu64 "}\n",
               flow, ok ? "true" : "false", state->error,
               state->connect_ns, state->attempted, state->accepted,
               state->blocked ? "true" : "false", state->first_eagain_ns);
    }
    free(states);
    free(payload);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        return 2;
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"stalled\","
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":%" PRIu64
           ",\"blocked_flows\":%zu,\"hold_ms\":%zu"
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           flows, successful, total_bytes, blocked_flows, hold_ms,
           timeval_ns(usage.ru_utime), timeval_ns(usage.ru_stime));
    return successful == flows ? 0 : 1;
}

/*
 * Stream workload: FLOWS concurrent long-lived connections against the
 * harness stream server. A 32-byte header selects the server behavior:
 *   bytes 0..3   magic "YBW1"
 *   byte  4      direction: 'U' upload, 'D' download, 'B' bidirectional
 *   bytes 5..7   zero
 *   bytes 8..15  payload bytes per flow (u64 LE)
 *   bytes 16..23 server-side read rate limit in bytes/s, 0 unlimited (u64 LE)
 *   bytes 24..31 reserved (u64 LE)
 * Payload bytes are 0x5a in both directions; uploads are acknowledged with a
 * single 0xa5 byte so silent server-side truncation cannot look successful.
 */
#define STREAM_HEADER_SIZE 32
#define STREAM_CHUNK_SIZE 65536

struct stream_flow {
    int fd;
    int error;
    int connected;
    int wr_shutdown;
    int saw_eof;
    int done;
    size_t header_sent;
    size_t to_send;
    uint64_t expected_recv;
    uint64_t received;
    uint64_t sent_bytes;
    uint64_t started_ns;
    uint64_t connect_ns;
    uint64_t first_response_ns;
};

static void stream_flow_fail(struct stream_flow *flow, int error) {
    if (flow->error == 0) {
        flow->error = error;
    }
}

static void encode_u64le(uint8_t *out, uint64_t value) {
    for (size_t index = 0; index < 8; ++index) {
        out[index] = (uint8_t)(value >> (8 * index));
    }
}

static int stream_flow_wants_write(const struct stream_flow *flow) {
    return !flow->connected || flow->header_sent < STREAM_HEADER_SIZE ||
           flow->to_send > 0 || !flow->wr_shutdown;
}

static int stream_flow_finished(const struct stream_flow *flow) {
    return flow->error != 0 ||
           (flow->wr_shutdown && flow->saw_eof &&
            flow->received == flow->expected_recv);
}

static void stream_flow_on_writable(struct stream_flow *flow,
                                    const uint8_t *header,
                                    const uint8_t *payload) {
    if (!flow->connected) {
        int pending = 0;
        socklen_t length = sizeof(pending);
        if (getsockopt(flow->fd, SOL_SOCKET, SO_ERROR, &pending, &length) != 0) {
            stream_flow_fail(flow, errno);
            return;
        }
        if (pending != 0) {
            stream_flow_fail(flow, pending);
            return;
        }
        flow->connected = 1;
        flow->connect_ns = monotonic_ns() - flow->started_ns;
    }
    while (flow->error == 0 && flow->header_sent < STREAM_HEADER_SIZE) {
        ssize_t written = send(flow->fd, header + flow->header_sent,
                               STREAM_HEADER_SIZE - flow->header_sent, MSG_NOSIGNAL);
        if (written > 0) {
            flow->header_sent += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        stream_flow_fail(flow, written == 0 ? EIO : errno);
        return;
    }
    while (flow->error == 0 && flow->to_send > 0) {
        size_t chunk = flow->to_send > STREAM_CHUNK_SIZE ? STREAM_CHUNK_SIZE : flow->to_send;
        ssize_t written = send(flow->fd, payload, chunk, MSG_NOSIGNAL);
        if (written > 0) {
            flow->to_send -= (size_t)written;
            flow->sent_bytes += (uint64_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
        }
        stream_flow_fail(flow, written == 0 ? EIO : errno);
        return;
    }
    if (flow->error == 0 && flow->to_send == 0 && !flow->wr_shutdown) {
        if (shutdown(flow->fd, SHUT_WR) != 0) {
            stream_flow_fail(flow, errno);
            return;
        }
        flow->wr_shutdown = 1;
    }
}

static void stream_flow_on_readable(struct stream_flow *flow, uint8_t expected_byte) {
    uint8_t buffer[STREAM_CHUNK_SIZE];
    while (flow->error == 0 && !flow->saw_eof) {
        ssize_t count = recv(flow->fd, buffer, sizeof(buffer), 0);
        if (count > 0) {
            if (flow->first_response_ns == 0) {
                flow->first_response_ns = monotonic_ns() - flow->started_ns;
            }
            for (ssize_t index = 0; index < count; ++index) {
                if (buffer[index] != expected_byte) {
                    stream_flow_fail(flow, EPROTO);
                    break;
                }
            }
            flow->received += (uint64_t)count;
            if (flow->received > flow->expected_recv) {
                stream_flow_fail(flow, EPROTO);
            }
            continue;
        }
        if (count == 0) {
            flow->saw_eof = 1;
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        stream_flow_fail(flow, errno);
        return;
    }
}

static void stream_flow_finalize(struct stream_flow *flow, size_t index) {
    if (flow->error == 0 && flow->received != flow->expected_recv) {
        flow->error = EIO;
    }
    if (flow->fd >= 0) {
        close(flow->fd);
        flow->fd = -1;
    }
    flow->done = 1;
    uint64_t total_ns = monotonic_ns() - flow->started_ns;
    if (flow->error == 0) {
        printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":true,"
               "\"connect_ns\":%" PRIu64 ",\"first_response_ns\":%" PRIu64
               ",\"total_ns\":%" PRIu64 ",\"sent_bytes\":%" PRIu64
               ",\"received_bytes\":%" PRIu64 "}\n",
               index, flow->connect_ns, flow->first_response_ns, total_ns,
               flow->sent_bytes, flow->received);
    } else {
        printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":false,"
               "\"errno\":%d,\"connect_ns\":%" PRIu64 ",\"total_ns\":%" PRIu64
               ",\"sent_bytes\":%" PRIu64 ",\"received_bytes\":%" PRIu64 "}\n",
               index, flow->error, flow->connect_ns, total_ns,
               flow->sent_bytes, flow->received);
    }
}

static int run_stream(const struct endpoint *endpoint, size_t flows,
                      size_t bytes_per_flow, const char *direction_name,
                      size_t rate_bytes_per_second) {
    unsigned char direction;
    if (strcmp(direction_name, "up") == 0) {
        direction = 'U';
    } else if (strcmp(direction_name, "down") == 0) {
        direction = 'D';
    } else if (strcmp(direction_name, "bidi") == 0) {
        direction = 'B';
    } else {
        fprintf(stderr, "unknown stream direction: %s\n", direction_name);
        return 2;
    }

    uint8_t header[STREAM_HEADER_SIZE];
    memset(header, 0, sizeof(header));
    memcpy(header, "YBW1", 4);
    header[4] = direction;
    encode_u64le(header + 8, (uint64_t)bytes_per_flow);
    encode_u64le(header + 16, (uint64_t)rate_bytes_per_second);

    uint8_t *payload = malloc(STREAM_CHUNK_SIZE);
    struct stream_flow *states = calloc(flows, sizeof(*states));
    struct pollfd *poll_set = calloc(flows, sizeof(*poll_set));
    size_t *poll_flows = calloc(flows, sizeof(*poll_flows));
    if (payload == NULL || states == NULL || poll_set == NULL || poll_flows == NULL) {
        perror("malloc");
        free(payload);
        free(states);
        free(poll_set);
        free(poll_flows);
        return 2;
    }
    memset(payload, 0x5a, STREAM_CHUNK_SIZE);

    for (size_t flow = 0; flow < flows; ++flow) {
        struct stream_flow *state = &states[flow];
        state->fd = -1;
        state->started_ns = monotonic_ns();
        state->to_send = direction == 'D' ? 0 : bytes_per_flow;
        state->expected_recv = direction == 'U' ? 1 : (uint64_t)bytes_per_flow;
        int fd = socket(endpoint->family,
                        endpoint->socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                        endpoint->protocol);
        if (fd < 0) {
            state->error = errno;
            continue;
        }
        state->fd = fd;
        if (connect(fd, (const struct sockaddr *)&endpoint->address,
                    endpoint->length) == 0) {
            state->connected = 1;
            state->connect_ns = monotonic_ns() - state->started_ns;
        } else if (errno != EINPROGRESS) {
            state->error = errno;
        }
    }

    uint8_t expected_byte = direction == 'U' ? 0xa5 : 0x5a;
    for (;;) {
        size_t active = 0;
        for (size_t flow = 0; flow < flows; ++flow) {
            struct stream_flow *state = &states[flow];
            if (state->done) {
                continue;
            }
            if (stream_flow_finished(state)) {
                stream_flow_finalize(state, flow);
                continue;
            }
            short events = 0;
            if (stream_flow_wants_write(state)) {
                events |= POLLOUT;
            }
            if (state->connected && state->header_sent == STREAM_HEADER_SIZE &&
                !state->saw_eof) {
                events |= POLLIN;
            }
            poll_set[active].fd = state->fd;
            poll_set[active].events = events;
            poll_set[active].revents = 0;
            poll_flows[active] = flow;
            ++active;
        }
        if (active == 0) {
            break;
        }
        int ready = poll(poll_set, (nfds_t)active, -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            free(payload);
            free(states);
            free(poll_set);
            free(poll_flows);
            return 2;
        }
        for (size_t entry = 0; entry < active; ++entry) {
            short revents = poll_set[entry].revents;
            if (revents == 0) {
                continue;
            }
            struct stream_flow *state = &states[poll_flows[entry]];
            if (revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
                if (stream_flow_wants_write(state)) {
                    stream_flow_on_writable(state, header, payload);
                }
            }
            if (state->error == 0 && state->connected &&
                state->header_sent == STREAM_HEADER_SIZE &&
                (revents & (POLLIN | POLLERR | POLLHUP))) {
                stream_flow_on_readable(state, expected_byte);
            }
        }
    }

    size_t successful = 0;
    uint64_t total_bytes = 0;
    for (size_t flow = 0; flow < flows; ++flow) {
        struct stream_flow *state = &states[flow];
        if (state->error != 0) {
            continue;
        }
        ++successful;
        if (direction == 'U') {
            total_bytes += state->sent_bytes;
        } else if (direction == 'D') {
            total_bytes += state->received;
        } else {
            total_bytes += state->sent_bytes + state->received;
        }
    }
    free(payload);
    free(states);
    free(poll_set);
    free(poll_flows);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        return 2;
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"stream\","
           "\"direction\":\"%s\",\"rate_bytes_per_second\":%zu,"
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":%" PRIu64
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           direction_name, rate_bytes_per_second, flows, successful, total_bytes,
           timeval_ns(usage.ru_utime), timeval_ns(usage.ru_stime));
    return successful == flows ? 0 : 1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 6) {
        fprintf(stderr,
                "usage: %s request HOST PORT FLOWS PAYLOAD_BYTES\n"
                "       %s idle HOST PORT FLOWS HOLD_MS\n"
                "       %s stalled HOST PORT FLOWS BYTES_PER_FLOW HOLD_MS READY_PATH\n"
                "       %s stream HOST PORT FLOWS BYTES_PER_FLOW DIRECTION RATE_BYTES_PER_SECOND\n",
                argv[0], argv[0], argv[0], argv[0]);
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
    if (strcmp(argv[1], "stalled") == 0 && argc == 8) {
        return run_stalled(&endpoint, flows, value,
                           parse_size(argv[6], "hold milliseconds"), argv[7]);
    }
    if (strcmp(argv[1], "stream") == 0 && argc == 8) {
        return run_stream(&endpoint, flows, value, argv[6],
                          parse_size(argv[7], "rate bytes per second"));
    }
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
