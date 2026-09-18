#include "netbox.h"
#include "network.h"
#include "app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    DSConfig cfg;
    memset(&cfg, 0, sizeof(cfg));

    UserSession sess;
    memset(&sess, 0, sizeof(sess));

    if (parse_args(argc, argv, &cfg) != 0) {
        return EXIT_FAILURE;
    }

    printf("DS address: %s:%s | local peer TCP port: %s\n",
           cfg.ds_ip, cfg.ds_port, cfg.peer_port);

    command_loop(&cfg, &sess);

    return EXIT_SUCCESS;
}