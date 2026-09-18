#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
 
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
 
/* ---------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------*/
 
/* Defaults used when -n / -p are not given on the command line.
 * TODO: confirm these against whatever "value provided by the professors"
 * ends up being announced (the handout gives these as the DS's current
 * location/port, which is what we use as the fallback default). */
#define DEFAULT_DS_IP   "193.136.138.142"
#define DEFAULT_DS_PORT "59000"
 
#define UID_LEN       6     /* exactly 6 decimal digits */
#define PASSWORD_LEN  8     /* exactly 8 alphanumeric characters */
 
#define MAX_CMD_LINE   512
#define MAX_MSG        512
#define UDP_TIMEOUT_S  5    /* seconds to wait for a DS reply before giving up */
#define UDP_MAX_RETRIES 3   /* simple retry count on timeout */
 
/* ---------------------------------------------------------------------------
 * Global application state (kept intentionally small for Phase I)
 * -------------------------------------------------------------------------*/
 
typedef struct {
    char ds_ip[64];
    char ds_port[16];
    char peer_port[16];      /* this instance's TCP port for future file transfer */
 
    int  logged_in;          /* 0 = not logged in, 1 = logged in */
    char uid[UID_LEN + 1];
    char password[PASSWORD_LEN + 1];
} AppState;
 
/* ---------------------------------------------------------------------------
 * Validation helpers
 * -------------------------------------------------------------------------*/
 
/* Returns 1 if s is exactly n decimal digits, 0 otherwise. */
static int is_n_digits(const char *s, size_t n) {
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++) {
        if (!isdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}
 
/* Returns 1 if s is exactly n alphanumeric characters, 0 otherwise. */
static int is_n_alnum(const char *s, size_t n) {
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)s[i])) return 0;
    }
    return 1;
}
 
/* Returns 1 if the string is a valid TCP/UDP port (1-65535), 0 otherwise. */
static int is_valid_port(const char *s) {
    if (s == NULL || s[0] == '\0') return 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    long v = strtol(s, NULL, 10);
    return (v >= 1 && v <= 65535);
}
 
/* ---------------------------------------------------------------------------
 * UDP core: one reusable function for sending a request and getting a reply.
 * All Phase I (and later, additional) UDP commands should go through this.
 * -------------------------------------------------------------------------*/
 
/*
 * send_udp_request()
 *   Sends `request` (a NUL-terminated protocol message, WITHOUT the trailing
 *   '\n' - it is added here) to ds_ip:ds_port over UDP, and waits for a
 *   reply, with a timeout and a small number of retries in case a packet
 *   is lost.
 *
 * Returns:
 *   0 on success, with the reply (NUL-terminated, '\n' stripped) copied
 *     into `reply_out` (buffer of size reply_out_size).
 *  -1 on failure (could not resolve address, socket error, or no reply
 *     after all retries) - caller should inform the user and NOT crash.
 */
static int send_udp_request(const char *ds_ip, const char *ds_port,
                             const char *request,
                             char *reply_out, size_t reply_out_size) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }
 
    /* Resolve DS address (works with numeric IPs too). */
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
 
    /* Set a receive timeout so a lost/blocked reply doesn't hang forever. */
    struct timeval tv;
    tv.tv_sec  = UDP_TIMEOUT_S;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        /* not fatal - continue without a timeout guarantee */
    }
 
    /* Build the wire message: request + '\n' */
    char wire_msg[MAX_MSG];
    int n = snprintf(wire_msg, sizeof(wire_msg), "%s\n", request);
    if (n < 0 || (size_t)n >= sizeof(wire_msg)) {
        fprintf(stderr, "Request too long to send.\n");
        freeaddrinfo(res);
        close(sockfd);
        return -1;
    }
 
    int result = -1;
    char buf[MAX_MSG];
 
    for (int attempt = 0; attempt < UDP_MAX_RETRIES && result != 0; attempt++) {
        ssize_t sent = sendto(sockfd, wire_msg, strlen(wire_msg), 0,
                               res->ai_addr, res->ai_addrlen);
        if (sent < 0) {
            perror("sendto");
            break; /* socket-level error: no point retrying */
        }
 
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t recvd = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
                                  (struct sockaddr *)&from_addr, &from_len);
 
        if (recvd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                fprintf(stderr, "(no reply from DS, attempt %d/%d - retrying)\n",
                        attempt + 1, UDP_MAX_RETRIES);
                continue; /* retry */
            }
            perror("recvfrom");
            break;
        }
 
        buf[recvd] = '\0';
        /* strip trailing newline(s) */
        while (recvd > 0 && (buf[recvd - 1] == '\n' || buf[recvd - 1] == '\r')) {
            buf[--recvd] = '\0';
        }
 
        if (reply_out_size > 0) {
            strncpy(reply_out, buf, reply_out_size - 1);
            reply_out[reply_out_size - 1] = '\0';
        }
        result = 0; /* success */
    }
 
    freeaddrinfo(res);
    close(sockfd);
    return result;
}
 
/* ---------------------------------------------------------------------------
 * Protocol message builders / reply parsers (section 4.1 of the handout)
 * -------------------------------------------------------------------------*/
 
static void build_login_msg(char *out, size_t out_size,
                             const char *uid, const char *password,
                             const char *peer_port) {
    snprintf(out, out_size, "LIN %s %s %s", uid, password, peer_port);
}
 
static void build_logout_msg(char *out, size_t out_size,
                              const char *uid, const char *password) {
    snprintf(out, out_size, "LOU %s %s", uid, password);
}
 
static void build_unregister_msg(char *out, size_t out_size,
                                  const char *uid, const char *password) {
    snprintf(out, out_size, "UNR %s %s", uid, password);
}
 
/* Generic 2-token reply parser: "<TAG> <STATUS>" -> extracts STATUS.
 * Returns 0 on a well-formed reply, -1 if the reply couldn't be parsed. */
static int parse_status_reply(const char *reply, char *tag_out, size_t tag_size,
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
 
/* ---------------------------------------------------------------------------
 * Command handlers
 * -------------------------------------------------------------------------*/
 
static void cmd_login(AppState *st, const char *uid, const char *password) {
    if (st->logged_in) {
        printf("You are already logged in as %s. Logout first.\n", st->uid);
        return;
    }
    if (!is_n_digits(uid, UID_LEN)) {
        printf("Invalid UID: must be exactly %d digits.\n", UID_LEN);
        return;
    }
    if (!is_n_alnum(password, PASSWORD_LEN)) {
        printf("Invalid password: must be exactly %d alphanumeric characters.\n",
               PASSWORD_LEN);
        return;
    }
 
    char msg[MAX_MSG], reply[MAX_MSG];
    build_login_msg(msg, sizeof(msg), uid, password, st->peer_port);
 
    if (send_udp_request(st->ds_ip, st->ds_port, msg, reply, sizeof(reply)) != 0) {
        printf("Login failed: no response from Directory Server.\n");
        return;
    }
 
    char tag[16], status[16];
    if (parse_status_reply(reply, tag, sizeof(tag), status, sizeof(status)) != 0
        || strcmp(tag, "RLI") != 0) {
        printf("Login failed: unexpected reply from DS (\"%s\").\n", reply);
        return;
    }
 
    if (strcmp(status, "OK") == 0) {
        printf("Successful login.\n");
        st->logged_in = 1;
        strncpy(st->uid, uid, UID_LEN); st->uid[UID_LEN] = '\0';
        strncpy(st->password, password, PASSWORD_LEN); st->password[PASSWORD_LEN] = '\0';
    } else if (strcmp(status, "NOK") == 0) {
        printf("Incorrect login attempt.\n");
    } else if (strcmp(status, "REG") == 0) {
        printf("New user registered and logged in.\n");
        st->logged_in = 1;
        strncpy(st->uid, uid, UID_LEN); st->uid[UID_LEN] = '\0';
        strncpy(st->password, password, PASSWORD_LEN); st->password[PASSWORD_LEN] = '\0';
    } else if (strcmp(status, "ERR") == 0) {
        printf("Login failed: DS reports a protocol error.\n");
    } else {
        printf("Login failed: unknown status \"%s\".\n", status);
    }
}
 
static void cmd_logout(AppState *st) {
    if (!st->logged_in) {
        printf("No user is currently logged in.\n");
        return;
    }
 
    char msg[MAX_MSG], reply[MAX_MSG];
    build_logout_msg(msg, sizeof(msg), st->uid, st->password);
 
    if (send_udp_request(st->ds_ip, st->ds_port, msg, reply, sizeof(reply)) != 0) {
        printf("Logout failed: no response from Directory Server.\n");
        return;
    }
 
    char tag[16], status[16];
    if (parse_status_reply(reply, tag, sizeof(tag), status, sizeof(status)) != 0
        || strcmp(tag, "RLO") != 0) {
        printf("Logout failed: unexpected reply from DS (\"%s\").\n", reply);
        return;
    }
 
    if (strcmp(status, "OK") == 0) {
        printf("Successful logout.\n");
        st->logged_in = 0;
        memset(st->uid, 0, sizeof(st->uid));
        memset(st->password, 0, sizeof(st->password));
    } else if (strcmp(status, "NLG") == 0) {
        printf("User is not logged in.\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("User is not registered.\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Incorrect password.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Logout failed: DS reports a protocol error.\n");
    } else {
        printf("Logout failed: unknown status \"%s\".\n", status);
    }
}
 
static void cmd_unregister(AppState *st) {
    if (!st->logged_in) {
        printf("No user is currently logged in.\n");
        return;
    }
 
    char msg[MAX_MSG], reply[MAX_MSG];
    build_unregister_msg(msg, sizeof(msg), st->uid, st->password);
 
    if (send_udp_request(st->ds_ip, st->ds_port, msg, reply, sizeof(reply)) != 0) {
        printf("Unregister failed: no response from Directory Server.\n");
        return;
    }
 
    char tag[16], status[16];
    if (parse_status_reply(reply, tag, sizeof(tag), status, sizeof(status)) != 0
        || strcmp(tag, "RUR") != 0) {
        printf("Unregister failed: unexpected reply from DS (\"%s\").\n", reply);
        return;
    }
 
    if (strcmp(status, "OK") == 0) {
        printf("Successful unregister.\n");
        /* unregister implies a logout as well */
        st->logged_in = 0;
        memset(st->uid, 0, sizeof(st->uid));
        memset(st->password, 0, sizeof(st->password));
    } else if (strcmp(status, "NOK") == 0) {
        printf("Incorrect unregister attempt (user not logged in).\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("Unknown user (not registered).\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Incorrect password.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Unregister failed: DS reports a protocol error.\n");
    } else {
        printf("Unregister failed: unknown status \"%s\".\n", status);
    }
}
 
/* ---------------------------------------------------------------------------
 * Command-line input parsing / dispatch loop
 * -------------------------------------------------------------------------*/
 
/* Trims the trailing newline (and any trailing whitespace) fgets() leaves. */
static void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r'
                        || isspace((unsigned char)s[len - 1]))) {
        s[--len] = '\0';
    }
}
 
static void print_help(void) {
    printf(
        "Available commands:\n"
        "  login UID password\n"
        "  logout\n"
        "  unregister\n"
        "  exit\n");
}
 
static void command_loop(AppState *st) {
    char line[MAX_CMD_LINE];
 
    printf("NetBoX User application ready. Type a command (or 'exit').\n");
 
    while (1) {
        printf("> ");
        fflush(stdout);
 
        if (fgets(line, sizeof(line), stdin) == NULL) {
            /* EOF (e.g. Ctrl-D) - treat like exit, but respect the logout rule */
            putchar('\n');
            if (st->logged_in) {
                printf("Please logout before exiting.\n");
                continue;
            }
            break;
        }
 
        trim_newline(line);
        if (line[0] == '\0') continue; /* ignore blank lines */
 
        char cmd[32] = {0};
        int consumed = 0;
        if (sscanf(line, "%31s%n", cmd, &consumed) != 1) {
            printf("Unrecognized command. ");
            print_help();
            continue;
        }
        char *rest = line + consumed;
        while (*rest == ' ') rest++; /* skip leading spaces of the remainder */
 
        if (strcmp(cmd, "login") == 0) {
            char uid[64] = {0}, password[64] = {0};
            if (sscanf(rest, "%63s %63s", uid, password) != 2) {
                printf("Usage: login UID password\n");
                continue;
            }
            cmd_login(st, uid, password);
 
        } else if (strcmp(cmd, "logout") == 0) {
            cmd_logout(st);
 
        } else if (strcmp(cmd, "unregister") == 0) {
            cmd_unregister(st);
 
        } else if (strcmp(cmd, "exit") == 0) {
            if (st->logged_in) {
                printf("Please logout before exiting.\n");
            } else {
                break;
            }
 
        } else {
            printf("Unrecognized command \"%s\". ", cmd);
            print_help();
        }
    }
 
    printf("Bye.\n");
}
 
/* ---------------------------------------------------------------------------
 * Argument parsing:  ./user -m peerport [-n DSIP] [-p DSport]
 * -------------------------------------------------------------------------*/
 
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s -m peerport [-n DSIP] [-p DSport]\n", prog);
}
 
static int parse_args(int argc, char *argv[], AppState *st) {
    int have_peer_port = 0;
    strncpy(st->ds_ip, DEFAULT_DS_IP, sizeof(st->ds_ip) - 1);
    strncpy(st->ds_port, DEFAULT_DS_PORT, sizeof(st->ds_port) - 1);
 
    int opt;
    while ((opt = getopt(argc, argv, "m:n:p:")) != -1) {
        switch (opt) {
            case 'm':
                if (!is_valid_port(optarg)) {
                    fprintf(stderr, "Invalid peerport \"%s\" (must be 1-65535).\n", optarg);
                    return -1;
                }
                strncpy(st->peer_port, optarg, sizeof(st->peer_port) - 1);
                have_peer_port = 1;
                break;
            case 'n':
                strncpy(st->ds_ip, optarg, sizeof(st->ds_ip) - 1);
                st->ds_ip[sizeof(st->ds_ip) - 1] = '\0';
                break;
            case 'p':
                if (!is_valid_port(optarg)) {
                    fprintf(stderr, "Invalid DSport \"%s\" (must be 1-65535).\n", optarg);
                    return -1;
                }
                strncpy(st->ds_port, optarg, sizeof(st->ds_port) - 1);
                st->ds_port[sizeof(st->ds_port) - 1] = '\0';
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
 
/* ---------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------*/
 
int main(int argc, char *argv[]) {
    AppState st;
    memset(&st, 0, sizeof(st));
 
    if (parse_args(argc, argv, &st) != 0) {
        return EXIT_FAILURE;
    }
 
    printf("DS address: %s:%s | local peer TCP port: %s\n",
           st.ds_ip, st.ds_port, st.peer_port);
 
    command_loop(&st);
 
    return EXIT_SUCCESS;
}