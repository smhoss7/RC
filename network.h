#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include "netbox.h"

/* Argument & Port Validation */
int  is_valid_port(const char *s);
void usage(const char *prog);
int  parse_args(int argc, char *argv[], DSConfig *cfg);

/* Core Networking */
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

/* Protocol Reply Parser */
int  parse_status_reply(const char *reply,
                        char *tag_out, size_t tag_size,
                        char *status_out, size_t status_size);

#endif /* NETWORK_H */