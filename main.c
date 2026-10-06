#define _POSIX_C_SOURCE 200809L

#include "network.h"
#include "app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

int main(int argc, char *argv[]) {
    DSConfig cfg;
    memset(&cfg, 0, sizeof(cfg));

    UserSession sess;
    memset(&sess, 0, sizeof(sess));

    /* Writing to a TCP socket the other side closed must not kill us */
    signal(SIGPIPE, SIG_IGN);

    if (parse_args(argc, argv, &cfg) != 0) {
        return EXIT_FAILURE;
    }

    printf("DS address: %s:%s | local peer TCP port: %s\n",
           cfg.ds_ip, cfg.ds_port, cfg.peer_port);

    command_loop(&cfg, &sess);

    return EXIT_SUCCESS;
}