#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int is_valid_port(const char *s) {
    if (s == NULL || s[0] == '\0') return 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    long v = strtol(s, NULL, 10);
    return (v >= 1 && v <= 65535);
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -m peerport [-n DSIP] [-p DSport]\n", prog);
}

int parse_args(int argc, char *argv[], DSConfig *cfg) {
    int have_peer_port = 0;
    strncpy(cfg->ds_ip, DEFAULT_DS_IP, sizeof(cfg->ds_ip) - 1);
    strncpy(cfg->ds_port, DEFAULT_DS_PORT, sizeof(cfg->ds_port) - 1);

    int opt;
    while ((opt = getopt(argc, argv, "m:n:p:")) != -1) {
        switch (opt) {
            case 'm':
                if (!is_valid_port(optarg)) {
                    fprintf(stderr, "Invalid peerport \"%s\" (must be 1-65535).\n", optarg);
                    return -1;
                }
                strncpy(cfg->peer_port, optarg, sizeof(cfg->peer_port) - 1);
                have_peer_port = 1;
                break;
            case 'n':
                strncpy(cfg->ds_ip, optarg, sizeof(cfg->ds_ip) - 1);
                cfg->ds_ip[sizeof(cfg->ds_ip) - 1] = '\0';
                break;
            case 'p':
                if (!is_valid_port(optarg)) {
                    fprintf(stderr, "Invalid DSport \"%s\" (must be 1-65535).\n", optarg);
                    return -1;
                }
                strncpy(cfg->ds_port, optarg, sizeof(cfg->ds_port) - 1);
                cfg->ds_port[sizeof(cfg->ds_port) - 1] = '\0';
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    if (!have_peer_port) {
        fprintf(stderr, "Error: -m peerport is mandatory.\n");
        usage(argv[0]);
        return -1;
    }

    return 0;
}

int send_udp_request(const char *ds_ip, const char *ds_port,
                     const char *request,
                     char *reply_out, size_t reply_out_size) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int gai_err = getaddrinfo(ds_ip, ds_port, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "Error resolving DS address %s:%s -> %s\n",
                ds_ip, ds_port, gai_strerror(gai_err));
        close(sockfd);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec  = UDP_TIMEOUT_S;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
    }

    char wire_msg[MAX_MSG];
    int n = snprintf(wire_msg, sizeof(wire_msg), "%s\n", request);
    if (n < 0 || (size_t)n >= sizeof(wire_msg)) {
        fprintf(stderr, "Request too long to send.\n");
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }

    int result = -1;
    char buf[MAX_UDP_REPLY];

    for (int attempt = 0; attempt < UDP_MAX_RETRIES && result != 0; attempt++) {
        ssize_t sent = sendto(sockfd, wire_msg, strlen(wire_msg), 0,
                              res->ai_addr, res->ai_addrlen);
        if (sent < 0) {
            perror("sendto");
            break;
        }

        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t recvd = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&from_addr, &from_len);

        if (recvd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                fprintf(stderr, "(no reply from DS, attempt %d/%d - retrying)\n",
                        attempt + 1, UDP_MAX_RETRIES);
                continue;
            }
            perror("recvfrom");
            break;
        }

        buf[recvd] = '\0';
        while (recvd > 0 && (buf[recvd - 1] == '\n' || buf[recvd - 1] == '\r')) {
            buf[--recvd] = '\0';
        }

        if (reply_out_size > 0) {
            strncpy(reply_out, buf, reply_out_size - 1);
            reply_out[reply_out_size - 1] = '\0';
        }
        result = 0;
    }

    freeaddrinfo(res);
    close(sockfd);
    return result;
}

/* write() may send fewer bytes than asked, so keep going until done */
static int write_all(int fd, const char *data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        data += n;
        len  -= (size_t)n;
    }
    return 0;
}

int send_tcp_request(const char *ds_ip, const char *ds_port,
                     const char *request, char **reply_out) {
    *reply_out = NULL;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int gai_err = getaddrinfo(ds_ip, ds_port, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "Error resolving DS address %s:%s -> %s\n",
                ds_ip, ds_port, gai_strerror(gai_err));
        return -1;
    }

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv;
    tv.tv_sec  = TCP_TIMEOUT_S;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(timeout)");
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("connect");
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }
    freeaddrinfo(res);

    char wire_msg[MAX_MSG];
    int n = snprintf(wire_msg, sizeof(wire_msg), "%s\n", request);
    if (n < 0 || (size_t)n >= sizeof(wire_msg)) {
        fprintf(stderr, "Request too long to send.\n");
        close(sockfd);
        return -1;
    }
    if (write_all(sockfd, wire_msg, (size_t)n) != 0) {
        perror("write");
        close(sockfd);
        return -1;
    }

    /* The reply size is not known in advance: grow the buffer as needed
     * and read until the terminating '\n' arrives. */
    size_t cap = 1024, len = 0;
    char *buf = malloc(cap);
    if (buf == NULL) {
        perror("malloc");
        close(sockfd);
        return -1;
    }

    int got_newline = 0;
    while (!got_newline) {
        if (len + 1 >= cap) {
            if (cap >= MAX_TCP_REPLY) {
                fprintf(stderr, "Reply from DS is too long.\n");
                break;
            }
            char *tmp = realloc(buf, cap * 2);
            if (tmp == NULL) {
                perror("realloc");
                break;
            }
            buf = tmp;
            cap *= 2;
        }

        ssize_t r = read(sockfd, buf + len, cap - len - 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                fprintf(stderr, "(timed out waiting for DS reply)\n");
            } else {
                perror("read");
            }
            break;
        }
        if (r == 0) break; /* DS closed the connection */

        if (memchr(buf + len, '\n', (size_t)r) != NULL) got_newline = 1;
        len += (size_t)r;
    }
    close(sockfd);

    if (!got_newline) {
        free(buf);
        return -1;
    }

    buf[len] = '\0';
    char *nl = strchr(buf, '\n');
    *nl = '\0';
    if (nl > buf && nl[-1] == '\r') nl[-1] = '\0';

    *reply_out = buf;
    return 0;
}

void build_login_msg(char *out, size_t out_size,
                     const char *uid, const char *password,
                     const char *peer_port) {
    snprintf(out, out_size, "LIN %s %s %s", uid, password, peer_port);
}

void build_logout_msg(char *out, size_t out_size,
                      const char *uid, const char *password) {
    snprintf(out, out_size, "LOU %s %s", uid, password);
}

void build_unregister_msg(char *out, size_t out_size,
                         const char *uid, const char *password) {
    snprintf(out, out_size, "UNR %s %s", uid, password);
}

void build_publish_msg(char *out, size_t out_size,
                       const char *uid, const char *password,
                       const char *filename, long fsize, const char *label) {
    snprintf(out, out_size, "PUB %s %s %s %ld %s",
             uid, password, filename, fsize, label);
}

void build_remove_msg(char *out, size_t out_size,
                      const char *uid, const char *password,
                      const char *filename) {
    snprintf(out, out_size, "REM %s %s %s", uid, password, filename);
}

void build_list_msg(char *out, size_t out_size) {
    snprintf(out, out_size, "LST");
}

void build_versions_msg(char *out, size_t out_size, const char *filename) {
    snprintf(out, out_size, "VRS %s", filename);
}

int parse_status_reply(const char *reply, char *tag_out, size_t tag_size,
                       char *status_out, size_t status_size) {
    char tag[16], status[16];
    if (sscanf(reply, "%15s %15s", tag, status) != 2) {
        return -1;
    }
    strncpy(tag_out, tag, tag_size - 1);
    tag_out[tag_size - 1] = '\0';
    strncpy(status_out, status, status_size - 1);
    status_out[status_size - 1] = '\0';
    return 0;
}