#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>

#define DEFAULT_DS_IP   "193.136.138.142"
#define DEFAULT_DS_PORT "59000"

#define UID_LEN          6
#define PASSWORD_LEN     8

#define MAX_CMD_LINE    512
#define MAX_MSG         512
#define UDP_TIMEOUT_S   5
#define UDP_MAX_RETRIES 3

#define MAX_FILENAME_LEN 24          /* "nnn...nnnn.xxx", dot and extension included */
#define MAX_LABEL_LEN    20
#define MAX_FSIZE        10000000L   /* 10 MB */
#define MAX_UDP_REPLY    2048        /* RLS carries up to 50 filenames */
#define TCP_TIMEOUT_S    5
#define MAX_TCP_REPLY    (1 << 20)   /* safety cap for RVR replies */

/** Directory Server Configuration */
typedef struct {
    char ds_ip[64];
    char ds_port[16];
    char peer_port[16];
} DSConfig;

/** User Session */
typedef struct {
    int  logged_in;
    char uid[UID_LEN + 1];
    char password[PASSWORD_LEN + 1];
} UserSession;


/** Validates a port number
 * @return 1 if the string is a valid port number, 0 otherwise
 */
int  is_valid_port(const char *s);

/** Prints usage information for the program
 */
void usage(const char *prog);

/** Parses command line arguments
 * @return 0 on success, -1 on failure
 */
int  parse_args(int argc, char *argv[], DSConfig *cfg);

/* Core Networking */
/* Sends a UDP request to the Directory Server and waits for a reply
 * Returns 0 on success, -1 on failure
 * The reply is copied into reply_out */
int  send_udp_request(const char *ds_ip, const char *ds_port,
                      const char *request,
                      char *reply_out, size_t reply_out_size);

/* Opens a TCP connection to the Directory Server, sends a request and reads
 * the reply up to (and including) the terminating '\n'.
 * Returns 0 on success, -1 on failure.
 * On success *reply_out points to a malloc'd string (without the trailing
 * newline) that the caller must free. */
int  send_tcp_request(const char *ds_ip, const char *ds_port,
                      const char *request, char **reply_out);


/* Wire Protocol Builders */
void build_login_msg(char *out, size_t out_size,
                     const char *uid, const char *password,
                     const char *peer_port);
void build_logout_msg(char *out, size_t out_size,
                      const char *uid, const char *password);
void build_unregister_msg(char *out, size_t out_size,
                         const char *uid, const char *password);
void build_publish_msg(char *out, size_t out_size,
                       const char *uid, const char *password,
                       const char *filename, long fsize, const char *label);
void build_remove_msg(char *out, size_t out_size,
                      const char *uid, const char *password,
                      const char *filename);
void build_list_msg(char *out, size_t out_size);
void build_versions_msg(char *out, size_t out_size, const char *filename);

/** Parses a status reply
 * @return 0 on success, -1 on failure
 */
int  parse_status_reply(const char *reply,
                        char *tag_out, size_t tag_size,
                        char *status_out, size_t status_size);

#endif /* NETWORK_H */