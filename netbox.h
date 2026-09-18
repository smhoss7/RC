#ifndef NETBOX_H
#define NETBOX_H

#include <stddef.h>

#define DEFAULT_DS_IP   "193.136.138.142"
#define DEFAULT_DS_PORT "59000"

#define UID_LEN          6
#define PASSWORD_LEN     8

#define MAX_CMD_LINE    512
#define MAX_MSG         512
#define UDP_TIMEOUT_S   5
#define UDP_MAX_RETRIES 3

typedef struct {
    char ds_ip[64];
    char ds_port[16];
    char peer_port[16];
} DSConfig;

typedef struct {
    int  logged_in;
    char uid[UID_LEN + 1];
    char password[PASSWORD_LEN + 1];
} UserSession;

#endif /* NETBOX_H */