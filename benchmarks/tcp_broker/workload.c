#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

static int run_idle(const struct endpoint *endpoint, size_t flows, size_t hold_ms,
                    const char *ready_path) {
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
    if (ready_path != NULL) {
        // Marks the registration/steady-state boundary so the harness can
        // attribute supervisor CPU to each phase separately.
        FILE *ready = fopen(ready_path, "w");
        if (ready == NULL || fprintf(ready, "%zu\n", successful) < 0 ||
            fclose(ready) != 0) {
            perror("idle ready path");
            for (size_t flow = 0; flow < flows; ++flow) {
                if (fds[flow] >= 0) {
                    close(fds[flow]);
                }
            }
            free(fds);
            return 2;
        }
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

/*
 * Fairness workload: one hot flow uploads hot_bytes through the stream server
 * while quiet_flows connections run small echo round trips against the echo
 * destination, each iteration timed individually. The quiet latency samples
 * are the measurement; the hot flow exists to contend for the relay.
 */
struct fairness_config {
    const struct endpoint *echo_endpoint;
    const struct endpoint *stream_endpoint;
    size_t quiet_payload;
    size_t hot_bytes;
    size_t iterations;
};

struct fairness_flow {
    pthread_t thread;
    const struct fairness_config *config;
    size_t flow;
    int created;
    int error;
    uint64_t connect_ns;
    uint64_t total_ns;
    uint64_t sent_bytes;
    uint64_t *latencies;
    size_t completed_iterations;
};

static void *fairness_hot_main(void *raw) {
    struct fairness_flow *state = raw;
    const struct fairness_config *config = state->config;
    uint64_t started = monotonic_ns();
    int fd = connect_endpoint(config->stream_endpoint, &state->connect_ns);
    if (fd < 0) {
        state->error = errno;
        state->total_ns = monotonic_ns() - started;
        return NULL;
    }
    uint8_t header[STREAM_HEADER_SIZE];
    memset(header, 0, sizeof(header));
    memcpy(header, "YBW1", 4);
    header[4] = 'U';
    encode_u64le(header + 8, (uint64_t)config->hot_bytes);
    uint8_t chunk[STREAM_CHUNK_SIZE];
    memset(chunk, 0x5a, sizeof(chunk));
    if (write_all(fd, header, sizeof(header)) != 0) {
        state->error = errno;
    }
    size_t remaining = config->hot_bytes;
    while (state->error == 0 && remaining > 0) {
        size_t step = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        if (write_all(fd, chunk, step) != 0) {
            state->error = errno;
            break;
        }
        state->sent_bytes += step;
        remaining -= step;
    }
    if (state->error == 0 && shutdown(fd, SHUT_WR) != 0) {
        state->error = errno;
    }
    size_t acked = 0;
    while (state->error == 0) {
        uint8_t ack = 0;
        ssize_t count = recv(fd, &ack, 1, 0);
        if (count > 0) {
            if (ack != 0xa5 || acked != 0) {
                state->error = EPROTO;
                break;
            }
            acked = 1;
            continue;
        }
        if (count == 0) {
            if (acked != 1) {
                state->error = EIO;
            }
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        state->error = errno;
        break;
    }
    close(fd);
    state->total_ns = monotonic_ns() - started;
    return NULL;
}

static void *fairness_quiet_main(void *raw) {
    struct fairness_flow *state = raw;
    const struct fairness_config *config = state->config;
    uint64_t started = monotonic_ns();
    uint8_t *payload = malloc(config->quiet_payload);
    uint8_t *scratch = malloc(config->quiet_payload);
    int fd = -1;
    if (payload == NULL || scratch == NULL) {
        state->error = ENOMEM;
        goto out;
    }
    memset(payload, 0x5a, config->quiet_payload);
    fd = connect_endpoint(config->echo_endpoint, &state->connect_ns);
    if (fd < 0) {
        state->error = errno;
        goto out;
    }
    for (size_t iteration = 0; iteration < config->iterations; ++iteration) {
        uint64_t iteration_started = monotonic_ns();
        if (write_all(fd, payload, config->quiet_payload) != 0) {
            state->error = errno;
            goto out;
        }
        size_t received = 0;
        while (received < config->quiet_payload) {
            ssize_t count = recv(fd, scratch, config->quiet_payload - received, 0);
            if (count > 0) {
                for (ssize_t index = 0; index < count; ++index) {
                    if (scratch[index] != 0x5a) {
                        state->error = EPROTO;
                        goto out;
                    }
                }
                received += (size_t)count;
                continue;
            }
            if (count == 0) {
                state->error = EIO;
                goto out;
            }
            if (errno == EINTR) {
                continue;
            }
            state->error = errno;
            goto out;
        }
        state->latencies[iteration] = monotonic_ns() - iteration_started;
        ++state->completed_iterations;
    }
    if (shutdown(fd, SHUT_WR) != 0) {
        state->error = errno;
        goto out;
    }
    for (;;) {
        ssize_t count = recv(fd, scratch, config->quiet_payload, 0);
        if (count > 0) {
            state->error = EPROTO;
            break;
        }
        if (count == 0) {
            break;
        }
        if (errno != EINTR) {
            state->error = errno;
            break;
        }
    }
out:
    free(payload);
    free(scratch);
    if (fd >= 0) {
        close(fd);
    }
    state->total_ns = monotonic_ns() - started;
    return NULL;
}

static int run_fairness(const struct endpoint *echo_endpoint,
                        const struct endpoint *stream_endpoint,
                        size_t quiet_flows, size_t iterations,
                        size_t quiet_payload, size_t hot_bytes) {
    struct fairness_config config = {
        .echo_endpoint = echo_endpoint,
        .stream_endpoint = stream_endpoint,
        .quiet_payload = quiet_payload,
        .hot_bytes = hot_bytes,
        .iterations = iterations,
    };
    size_t total_flows = quiet_flows + 1;
    struct fairness_flow *states = calloc(total_flows, sizeof(*states));
    uint64_t *latency_storage = calloc(quiet_flows * iterations, sizeof(uint64_t));
    if (states == NULL || latency_storage == NULL) {
        perror("calloc");
        free(states);
        free(latency_storage);
        return 2;
    }
    for (size_t flow = 0; flow < total_flows; ++flow) {
        struct fairness_flow *state = &states[flow];
        state->config = &config;
        state->flow = flow;
        if (flow > 0) {
            state->latencies = latency_storage + (flow - 1) * iterations;
        }
        void *(*entry)(void *) = flow == 0 ? fairness_hot_main : fairness_quiet_main;
        int rc = pthread_create(&state->thread, NULL, entry, state);
        if (rc != 0) {
            state->error = rc;
        } else {
            state->created = 1;
        }
    }
    for (size_t flow = 0; flow < total_flows; ++flow) {
        if (states[flow].created) {
            pthread_join(states[flow].thread, NULL);
        }
    }

    size_t successful = 0;
    uint64_t total_bytes = 0;
    for (size_t flow = 0; flow < total_flows; ++flow) {
        struct fairness_flow *state = &states[flow];
        int ok = state->error == 0 &&
                 (flow == 0 ? state->sent_bytes == hot_bytes
                            : state->completed_iterations == iterations);
        if (ok) {
            ++successful;
            if (flow == 0) {
                total_bytes += state->sent_bytes;
            } else {
                total_bytes += (uint64_t)quiet_payload * iterations * 2;
            }
        }
        if (flow == 0) {
            printf("{\"event\":\"flow\",\"flow\":0,\"kind\":\"hot\",\"ok\":%s,"
                   "\"errno\":%d,\"connect_ns\":%" PRIu64 ",\"total_ns\":%" PRIu64
                   ",\"sent_bytes\":%" PRIu64 "}\n",
                   ok ? "true" : "false", state->error, state->connect_ns,
                   state->total_ns, state->sent_bytes);
        } else {
            printf("{\"event\":\"flow\",\"flow\":%zu,\"kind\":\"quiet\",\"ok\":%s,"
                   "\"errno\":%d,\"connect_ns\":%" PRIu64 ",\"total_ns\":%" PRIu64
                   ",\"iterations\":%zu}\n",
                   flow, ok ? "true" : "false", state->error, state->connect_ns,
                   state->total_ns, state->completed_iterations);
            if (ok) {
                for (size_t iteration = 0; iteration < iterations; ++iteration) {
                    printf("{\"event\":\"sample\",\"kind\":\"quiet_echo\","
                           "\"flow\":%zu,\"iteration\":%zu,\"latency_ns\":%" PRIu64
                           "}\n",
                           flow, iteration, state->latencies[iteration]);
                }
            }
        }
    }
    free(states);
    free(latency_storage);

    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        perror("getrusage");
        return 2;
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"fairness\","
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":%" PRIu64
           ",\"quiet_flows\":%zu,\"quiet_iterations\":%zu"
           ",\"quiet_payload_bytes\":%zu,\"hot_bytes\":%zu"
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           total_flows, successful, total_bytes, quiet_flows, iterations,
           quiet_payload, hot_bytes, timeval_ns(usage.ru_utime),
           timeval_ns(usage.ru_stime));
    return successful == total_flows ? 0 : 1;
}

/*
 * Reset workload: FLOWS concurrent connections send request bytes to the
 * stream server with direction 'R'. The server consumes CONSUME bytes
 * (0 = the whole request), optionally answers with PREFIX payload bytes, and
 * then aborts the connection so a hard RST propagates back. Clients classify
 * the observable terminal state instead of asserting one: Linux and the relay
 * chain may legitimately surface either ECONNRESET or a clean EOF, and the
 * per-variant distribution is part of the dataset.
 */
struct reset_flow {
    int fd;
    int error;
    int send_errno;
    int recv_errno;
    int connected;
    int done;
    size_t header_sent;
    size_t to_send;
    uint64_t received;
    uint64_t sent_bytes;
    int saw_eof;
    uint64_t started_ns;
    uint64_t connect_ns;
};

static void reset_flow_fail(struct reset_flow *flow, int error) {
    if (flow->error == 0) {
        flow->error = error;
    }
}

static int reset_flow_finished(const struct reset_flow *flow) {
    return flow->error != 0 || flow->saw_eof || flow->recv_errno != 0;
}

static void reset_flow_on_writable(struct reset_flow *flow, const uint8_t *header,
                                   const uint8_t *payload) {
    if (!flow->connected) {
        int pending = 0;
        socklen_t length = sizeof(pending);
        if (getsockopt(flow->fd, SOL_SOCKET, SO_ERROR, &pending, &length) != 0) {
            reset_flow_fail(flow, errno);
            return;
        }
        if (pending != 0) {
            reset_flow_fail(flow, pending);
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
        reset_flow_fail(flow, written == 0 ? EIO : errno);
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
        if (written < 0 && (errno == EPIPE || errno == ECONNRESET)) {
            // Expected when the abort races the request: the reset arrived
            // while data was still queued. Keep reading for the terminal
            // state instead of treating this as a workload failure.
            flow->send_errno = errno;
            flow->to_send = 0;
            return;
        }
        reset_flow_fail(flow, written == 0 ? EIO : errno);
        return;
    }
}

static void reset_flow_on_readable(struct reset_flow *flow, uint64_t prefix_limit) {
    uint8_t buffer[STREAM_CHUNK_SIZE];
    while (flow->error == 0 && !flow->saw_eof && flow->recv_errno == 0) {
        ssize_t count = recv(flow->fd, buffer, sizeof(buffer), 0);
        if (count > 0) {
            for (ssize_t index = 0; index < count; ++index) {
                if (buffer[index] != 0x5a) {
                    reset_flow_fail(flow, EPROTO);
                    break;
                }
            }
            flow->received += (uint64_t)count;
            if (flow->received > prefix_limit) {
                reset_flow_fail(flow, EPROTO);
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
        if (errno == ECONNRESET) {
            flow->recv_errno = errno;
            return;
        }
        reset_flow_fail(flow, errno);
        return;
    }
}

static int run_reset(const struct endpoint *endpoint, size_t flows,
                     size_t request_bytes, size_t prefix_bytes,
                     size_t consume_bytes) {
    uint8_t header[STREAM_HEADER_SIZE];
    memset(header, 0, sizeof(header));
    memcpy(header, "YBW1", 4);
    header[4] = 'R';
    encode_u64le(header + 8, (uint64_t)request_bytes);
    encode_u64le(header + 16, (uint64_t)prefix_bytes);
    encode_u64le(header + 24, (uint64_t)consume_bytes);

    uint8_t *payload = malloc(STREAM_CHUNK_SIZE);
    struct reset_flow *states = calloc(flows, sizeof(*states));
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
        struct reset_flow *state = &states[flow];
        state->fd = -1;
        state->started_ns = monotonic_ns();
        state->to_send = request_bytes;
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

    size_t successful = 0;
    uint64_t total_bytes = 0;
    size_t reset_outcomes = 0;
    size_t eof_outcomes = 0;
    for (;;) {
        size_t active = 0;
        for (size_t flow = 0; flow < flows; ++flow) {
            struct reset_flow *state = &states[flow];
            if (state->done) {
                continue;
            }
            if (reset_flow_finished(state)) {
                if (state->fd >= 0) {
                    close(state->fd);
                    state->fd = -1;
                }
                state->done = 1;
                uint64_t total_ns = monotonic_ns() - state->started_ns;
                const char *outcome = "error";
                if (state->error == 0 && state->recv_errno == ECONNRESET) {
                    outcome = "reset";
                } else if (state->error == 0 && state->saw_eof) {
                    outcome = "eof";
                }
                int ok = state->error == 0 && strcmp(outcome, "error") != 0;
                if (ok) {
                    ++successful;
                    total_bytes += state->sent_bytes + state->received;
                    if (strcmp(outcome, "reset") == 0) {
                        ++reset_outcomes;
                    } else {
                        ++eof_outcomes;
                    }
                }
                printf("{\"event\":\"flow\",\"flow\":%zu,\"ok\":%s,"
                       "\"errno\":%d,\"outcome\":\"%s\",\"send_errno\":%d,"
                       "\"recv_errno\":%d,\"connect_ns\":%" PRIu64
                       ",\"total_ns\":%" PRIu64 ",\"sent_bytes\":%" PRIu64
                       ",\"received_bytes\":%" PRIu64 "}\n",
                       flow, ok ? "true" : "false", state->error, outcome,
                       state->send_errno, state->recv_errno, state->connect_ns,
                       total_ns, state->sent_bytes, state->received);
                continue;
            }
            short events = POLLIN;
            if (!state->connected || state->header_sent < STREAM_HEADER_SIZE ||
                state->to_send > 0) {
                events |= POLLOUT;
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
            struct reset_flow *state = &states[poll_flows[entry]];
            if (revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
                reset_flow_on_writable(state, header, payload);
            }
            if (state->error == 0 && state->connected &&
                state->header_sent == STREAM_HEADER_SIZE &&
                (revents & (POLLIN | POLLERR | POLLHUP))) {
                reset_flow_on_readable(state, (uint64_t)prefix_bytes);
            }
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
    printf("{\"event\":\"workload_summary\",\"mode\":\"reset\","
           "\"flows\":%zu,\"successful\":%zu,\"bytes\":%" PRIu64
           ",\"request_bytes\":%zu,\"prefix_bytes\":%zu,\"consume_bytes\":%zu"
           ",\"reset_outcomes\":%zu,\"eof_outcomes\":%zu"
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           flows, successful, total_bytes, request_bytes, prefix_bytes,
           consume_bytes, reset_outcomes, eof_outcomes,
           timeval_ns(usage.ru_utime), timeval_ns(usage.ru_stime));
    return successful == flows ? 0 : 1;
}

struct soak_profile {
    size_t request_flows;
    size_t request_small_bytes;
    size_t request_large_bytes;
    size_t idle_flows;
    size_t idle_hold_ms;
    size_t ramp_flows;
    size_t ramp_bytes;
    size_t steady_flows;
    size_t steady_bytes;
    size_t slow_flows;
    size_t slow_bytes;
    size_t slow_rate;
    size_t fairness_quiet_flows;
    size_t fairness_iterations;
    size_t fairness_payload;
    size_t fairness_hot_bytes;
    size_t reset_flows;
    size_t reset_request_bytes;
    size_t reset_prefix_bytes;
};

static const struct soak_profile SOAK_STANDARD = {
    .request_flows = 128,
    .request_small_bytes = 1024,
    .request_large_bytes = 65536,
    .idle_flows = 512,
    .idle_hold_ms = 100,
    .ramp_flows = 32,
    .ramp_bytes = 4 * 1024 * 1024,
    .steady_flows = 32,
    .steady_bytes = 32 * 1024 * 1024,
    .slow_flows = 16,
    .slow_bytes = 256 * 1024,
    .slow_rate = 128 * 1024,
    .fairness_quiet_flows = 32,
    .fairness_iterations = 40,
    .fairness_payload = 1024,
    .fairness_hot_bytes = 64 * 1024 * 1024,
    .reset_flows = 128,
    .reset_request_bytes = 65536,
    .reset_prefix_bytes = 1024,
};

static const struct soak_profile SOAK_SMOKE = {
    .request_flows = 2,
    .request_small_bytes = 64,
    .request_large_bytes = 1024,
    .idle_flows = 2,
    .idle_hold_ms = 1,
    .ramp_flows = 2,
    .ramp_bytes = 64 * 1024,
    .steady_flows = 2,
    .steady_bytes = 128 * 1024,
    .slow_flows = 2,
    .slow_bytes = 64 * 1024,
    .slow_rate = 1024 * 1024,
    .fairness_quiet_flows = 2,
    .fairness_iterations = 2,
    .fairness_payload = 64,
    .fairness_hot_bytes = 64 * 1024,
    .reset_flows = 2,
    .reset_request_bytes = 4096,
    .reset_prefix_bytes = 64,
};

static void format_size(char *buffer, size_t length, size_t value) {
    int written = snprintf(buffer, length, "%zu", value);
    if (written < 0 || (size_t)written >= length) {
        fprintf(stderr, "cannot format soak argument\n");
        exit(2);
    }
}

static int run_soak_child(const char *self, const char *const *arguments,
                          size_t argument_count) {
    char *child_argv[12];
    if (argument_count + 2 > sizeof(child_argv) / sizeof(child_argv[0])) {
        fprintf(stderr, "too many soak phase arguments\n");
        return 2;
    }
    child_argv[0] = (char *)self;
    for (size_t index = 0; index < argument_count; ++index) {
        child_argv[index + 1] = (char *)arguments[index];
    }
    child_argv[argument_count + 1] = NULL;

    fflush(NULL);
    pid_t child = fork();
    if (child < 0) {
        perror("fork soak phase");
        return 2;
    }
    if (child == 0) {
        int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0) {
            perror("redirect soak phase output");
            _exit(127);
        }
        close(null_fd);
        execvp(self, child_argv);
        perror("exec soak phase");
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        perror("waitpid soak phase");
        return 2;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 2;
}

static int run_soak_basic_phase(const char *self, const char *mode,
                                const char *host, const char *port,
                                size_t flows, size_t value,
                                const char *extra_one, size_t extra_two,
                                int has_extras) {
    char flows_text[32];
    char value_text[32];
    char extra_two_text[32];
    format_size(flows_text, sizeof(flows_text), flows);
    format_size(value_text, sizeof(value_text), value);
    format_size(extra_two_text, sizeof(extra_two_text), extra_two);
    const char *arguments[] = {
        mode, host, port, flows_text, value_text, extra_one, extra_two_text,
    };
    return run_soak_child(self, arguments, has_extras ? 7 : 5);
}

static int run_soak_fairness_phase(const char *self, const char *host,
                                   const char *echo_port,
                                   const char *stream_port,
                                   const struct soak_profile *profile) {
    char quiet_flows[32];
    char iterations[32];
    char payload[32];
    char hot_bytes[32];
    format_size(quiet_flows, sizeof(quiet_flows), profile->fairness_quiet_flows);
    format_size(iterations, sizeof(iterations), profile->fairness_iterations);
    format_size(payload, sizeof(payload), profile->fairness_payload);
    format_size(hot_bytes, sizeof(hot_bytes), profile->fairness_hot_bytes);
    const char *arguments[] = {
        "fairness", host, echo_port, stream_port, quiet_flows,
        iterations, payload, hot_bytes,
    };
    return run_soak_child(self, arguments, 8);
}

static int run_soak_reset_phase(const char *self, const char *host,
                                const char *stream_port,
                                const struct soak_profile *profile,
                                size_t prefix_bytes, size_t consume_bytes) {
    char flows[32];
    char request_bytes[32];
    char prefix[32];
    char consume[32];
    format_size(flows, sizeof(flows), profile->reset_flows);
    format_size(request_bytes, sizeof(request_bytes), profile->reset_request_bytes);
    format_size(prefix, sizeof(prefix), prefix_bytes);
    format_size(consume, sizeof(consume), consume_bytes);
    const char *arguments[] = {
        "reset", host, stream_port, flows, request_bytes, prefix, consume,
    };
    return run_soak_child(self, arguments, 7);
}

static int publish_soak_cycle(size_t cycle, const char *progress_path,
                              const char *ack_path) {
    FILE *progress = fopen(progress_path, "w");
    if (progress == NULL) {
        perror("publish soak cycle");
        return -1;
    }
    int write_failed = fprintf(progress, "%zu\n", cycle) < 0;
    int close_failed = fclose(progress) != 0;
    if (write_failed || close_failed) {
        perror("publish soak cycle");
        return -1;
    }
    for (;;) {
        FILE *ack = fopen(ack_path, "r");
        if (ack != NULL) {
            size_t acknowledged = 0;
            int matched = fscanf(ack, "%zu", &acknowledged) == 1;
            fclose(ack);
            if (matched && acknowledged >= cycle) {
                return 0;
            }
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
    }
}

static int run_soak(const char *self, const char *host, const char *echo_port,
                    const char *stream_port, size_t duration_seconds,
                    const char *profile_name, const char *progress_path,
                    const char *ack_path) {
    const struct soak_profile *profile = NULL;
    if (strcmp(profile_name, "standard") == 0) {
        profile = &SOAK_STANDARD;
    } else if (strcmp(profile_name, "smoke") == 0) {
        profile = &SOAK_SMOKE;
    } else {
        fprintf(stderr, "unknown soak profile: %s\n", profile_name);
        return 2;
    }
    if (duration_seconds == 0) {
        fprintf(stderr, "soak duration must be positive\n");
        return 2;
    }

    const uint64_t started_ns = monotonic_ns();
    const uint64_t duration_ns = (uint64_t)duration_seconds * UINT64_C(1000000000);
    size_t completed_cycles = 0;
    size_t completed_phases = 0;
    uint64_t total_flows = 0;
    uint64_t total_stream_connections = 0;
    uint64_t total_bytes = 0;
    int failure = 0;
    const char *failed_phase = NULL;
    const char *steady_directions[] = {"up", "down", "bidi"};

#define RUN_SOAK_PHASE(name, expression)                                           \
    do {                                                                            \
        int phase_rc = (expression);                                                 \
        if (phase_rc != 0) {                                                         \
            failure = phase_rc;                                                      \
            failed_phase = (name);                                                   \
            goto finished;                                                          \
        }                                                                            \
        ++completed_phases;                                                          \
    } while (0)

    do {
        const char *steady_direction =
            steady_directions[completed_cycles % 3];
        RUN_SOAK_PHASE(
            "request-0",
            run_soak_basic_phase(self, "request", host, echo_port,
                                 profile->request_flows, 0, NULL, 0, 0));
        RUN_SOAK_PHASE(
            "request-small",
            run_soak_basic_phase(self, "request", host, echo_port,
                                 profile->request_flows,
                                 profile->request_small_bytes, NULL, 0, 0));
        RUN_SOAK_PHASE(
            "request-large",
            run_soak_basic_phase(self, "request", host, echo_port,
                                 profile->request_flows,
                                 profile->request_large_bytes, NULL, 0, 0));
        RUN_SOAK_PHASE(
            "idle",
            run_soak_basic_phase(self, "idle", host, echo_port,
                                 profile->idle_flows, profile->idle_hold_ms,
                                 NULL, 0, 0));
        for (size_t direction = 0; direction < 3; ++direction) {
            RUN_SOAK_PHASE(
                "ramp-stream",
                run_soak_basic_phase(self, "stream", host, stream_port,
                                     profile->ramp_flows, profile->ramp_bytes,
                                     steady_directions[direction], 0, 1));
        }
        RUN_SOAK_PHASE(
            "steady-stream",
            run_soak_basic_phase(self, "stream", host, stream_port,
                                 profile->steady_flows, profile->steady_bytes,
                                 steady_direction, 0, 1));
        RUN_SOAK_PHASE(
            "slow-stream",
            run_soak_basic_phase(self, "stream", host, stream_port,
                                 profile->slow_flows, profile->slow_bytes,
                                 "up", profile->slow_rate, 1));
        RUN_SOAK_PHASE(
            "fairness",
            run_soak_fairness_phase(self, host, echo_port, stream_port, profile));
        RUN_SOAK_PHASE(
            "reset-response",
            run_soak_reset_phase(self, host, stream_port, profile,
                                 profile->reset_prefix_bytes, 0));
        RUN_SOAK_PHASE(
            "reset-early",
            run_soak_reset_phase(self, host, stream_port, profile, 0,
                                 profile->reset_request_bytes / 2));

        ++completed_cycles;
        uint64_t flows_this_cycle =
            3 * profile->request_flows + profile->idle_flows +
            3 * profile->ramp_flows + profile->steady_flows +
            profile->slow_flows + profile->fairness_quiet_flows + 1 +
            2 * profile->reset_flows;
        uint64_t stream_connections_this_cycle =
            3 * profile->ramp_flows + profile->steady_flows +
            profile->slow_flows + 1 + 2 * profile->reset_flows;
        uint64_t steady_multiplier =
            strcmp(steady_direction, "bidi") == 0 ? 2 : 1;
        uint64_t bytes_this_cycle =
            2 * profile->request_flows *
                (profile->request_small_bytes + profile->request_large_bytes) +
            4 * profile->ramp_flows * profile->ramp_bytes +
            steady_multiplier * profile->steady_flows * profile->steady_bytes +
            profile->slow_flows * profile->slow_bytes +
            profile->fairness_hot_bytes +
            2 * profile->fairness_quiet_flows * profile->fairness_iterations *
                profile->fairness_payload;
        total_flows += flows_this_cycle;
        total_stream_connections += stream_connections_this_cycle;
        total_bytes += bytes_this_cycle;
        printf("{\"event\":\"soak_cycle\",\"cycle\":%zu,"
               "\"flows\":%" PRIu64 ",\"stream_connections\":%" PRIu64
               ",\"bytes\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 "}\n",
               completed_cycles, total_flows, total_stream_connections,
               total_bytes, monotonic_ns() - started_ns);
        fflush(stdout);
        struct timespec quiescence = {.tv_sec = 0, .tv_nsec = 50000000};
        while (nanosleep(&quiescence, &quiescence) != 0 && errno == EINTR) {
        }
        if (publish_soak_cycle(completed_cycles, progress_path, ack_path) != 0) {
            failure = 2;
            failed_phase = "cycle-publish";
            goto finished;
        }
    } while (monotonic_ns() - started_ns < duration_ns);

finished:
#undef RUN_SOAK_PHASE
    struct rusage self_usage;
    struct rusage child_usage;
    if (getrusage(RUSAGE_SELF, &self_usage) != 0 ||
        getrusage(RUSAGE_CHILDREN, &child_usage) != 0) {
        perror("getrusage soak");
        return 2;
    }
    uint64_t user_cpu_ns = timeval_ns(self_usage.ru_utime) +
                           timeval_ns(child_usage.ru_utime);
    uint64_t system_cpu_ns = timeval_ns(self_usage.ru_stime) +
                             timeval_ns(child_usage.ru_stime);
    char failed_phase_json[64];
    if (failed_phase == NULL) {
        memcpy(failed_phase_json, "null", 5);
    } else {
        int written = snprintf(failed_phase_json, sizeof(failed_phase_json),
                               "\"%s\"", failed_phase);
        if (written < 0 || (size_t)written >= sizeof(failed_phase_json)) {
            memcpy(failed_phase_json, "\"unknown\"", 10);
        }
    }
    printf("{\"event\":\"workload_summary\",\"mode\":\"soak\","
           "\"profile\":\"%s\",\"duration_seconds\":%zu,"
           "\"cycles\":%zu,\"completed_phases\":%zu,"
           "\"flows\":%" PRIu64 ",\"successful\":%" PRIu64
           ",\"stream_connections\":%" PRIu64 ",\"bytes\":%" PRIu64
           ",\"failed_phase\":%s,\"phase_returncode\":%d,"
           "\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           profile_name, duration_seconds, completed_cycles, completed_phases,
           total_flows, total_flows, total_stream_connections, total_bytes,
           failed_phase_json, failure,
           user_cpu_ns, system_cpu_ns);
    if (failed_phase != NULL) {
        fprintf(stderr, "soak phase failed: %s (rc=%d)\n", failed_phase, failure);
    }
    return failure == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 6) {
        fprintf(stderr,
                "usage: %s request HOST PORT FLOWS PAYLOAD_BYTES\n"
                "       %s idle HOST PORT FLOWS HOLD_MS [READY_PATH]\n"
                "       %s stalled HOST PORT FLOWS BYTES_PER_FLOW HOLD_MS READY_PATH\n"
                "       %s stream HOST PORT FLOWS BYTES_PER_FLOW DIRECTION RATE_BYTES_PER_SECOND\n"
                "       %s reset HOST PORT FLOWS REQUEST_BYTES PREFIX_BYTES CONSUME_BYTES\n"
                "       %s fairness HOST ECHO_PORT STREAM_PORT QUIET_FLOWS QUIET_ITERATIONS QUIET_PAYLOAD_BYTES HOT_BYTES\n"
                "       %s soak HOST ECHO_PORT STREAM_PORT DURATION_SECONDS PROFILE PROGRESS_PATH ACK_PATH\n",
                argv[0], argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "soak") == 0) {
        if (argc != 9) {
            fprintf(stderr,
                    "soak requires HOST ECHO_PORT STREAM_PORT DURATION_SECONDS "
                    "PROFILE PROGRESS_PATH ACK_PATH\n");
            return 2;
        }
        return run_soak(argv[0], argv[2], argv[3], argv[4],
                        parse_size(argv[5], "duration seconds"), argv[6],
                        argv[7], argv[8]);
    }
    if (strcmp(argv[1], "fairness") == 0) {
        if (argc != 9) {
            fprintf(stderr,
                    "fairness requires HOST ECHO_PORT STREAM_PORT QUIET_FLOWS "
                    "QUIET_ITERATIONS QUIET_PAYLOAD_BYTES HOT_BYTES\n");
            return 2;
        }
        struct endpoint echo_endpoint = resolve_endpoint(argv[2], argv[3]);
        struct endpoint stream_endpoint = resolve_endpoint(argv[2], argv[4]);
        size_t quiet_payload = parse_size(argv[7], "quiet payload bytes");
        if (quiet_payload == 0) {
            fprintf(stderr, "quiet payload must be positive\n");
            return 2;
        }
        return run_fairness(&echo_endpoint, &stream_endpoint,
                            parse_size(argv[5], "quiet flows"),
                            parse_size(argv[6], "quiet iterations"),
                            quiet_payload, parse_size(argv[8], "hot bytes"));
    }
    struct endpoint endpoint = resolve_endpoint(argv[2], argv[3]);
    size_t flows = parse_size(argv[4], "flows");
    size_t value = parse_size(argv[5], "payload bytes or hold milliseconds");
    if (strcmp(argv[1], "request") == 0 && argc == 6) {
        return run_request(&endpoint, flows, value);
    }
    if (strcmp(argv[1], "idle") == 0 && (argc == 6 || argc == 7)) {
        return run_idle(&endpoint, flows, value, argc == 7 ? argv[6] : NULL);
    }
    if (strcmp(argv[1], "stalled") == 0 && argc == 8) {
        return run_stalled(&endpoint, flows, value,
                           parse_size(argv[6], "hold milliseconds"), argv[7]);
    }
    if (strcmp(argv[1], "stream") == 0 && argc == 8) {
        return run_stream(&endpoint, flows, value, argv[6],
                          parse_size(argv[7], "rate bytes per second"));
    }
    if (strcmp(argv[1], "reset") == 0 && argc == 8) {
        return run_reset(&endpoint, flows, value,
                         parse_size(argv[6], "prefix bytes"),
                         parse_size(argv[7], "consume bytes"));
    }
    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
