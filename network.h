#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include "netbox.h"

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


/* Wire Protocol Builders */
void build_login_msg(char *out, size_t out_size,
                     const char *uid, const char *password,
                     const char *peer_port);
void build_logout_msg(char *out, size_t out_size,
                      const char *uid, const char *password);
void build_unregister_msg(char *out, size_t out_size,
                         const char *uid, const char *password);

/** Parses a status reply
 * @return 0 on success, -1 on failure
 */
int  parse_status_reply(const char *reply,
                        char *tag_out, size_t tag_size,
                        char *status_out, size_t status_size);

#endif /* NETWORK_H */