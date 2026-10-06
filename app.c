#include "app.h"
#include "network.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

static int check_uid(const char *str, size_t expected_len) {
    if (strlen(str) != expected_len) return 0;
    for (size_t i = 0; i < expected_len; i++) {
        if (!isdigit((unsigned char)str[i])) return 0;
    }
    return 1;
}

static int check_pass(const char *str, size_t expected_len) {
    if (strlen(str) != expected_len) return 0;
    for (size_t i = 0; i < expected_len; i++) {
        if (!isalnum((unsigned char)str[i])) return 0;
    }
    return 1;
}

static void clean_input(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len-1] == '\n' || str[len - 1] == '\r'
                        || str[len - 1] == ' ')) {
        str[len-1] = '\0';
        len--;
    }
}

static void print_help(void) {
    printf(
        "\n\nTry one of the following commands:\n"
        "  login UID password\n"
        "  logout\n"
        "  unregister\n"
        "  exit\n");
}

static void handle_login(const DSConfig *cfg, UserSession *sess,
                      const char *uid, const char *password) {

    if (sess->logged_in) {
        printf("You are already logged in as %s. Logout first.\n", sess->uid);
        return;
    }
    if (!check_uid(uid, UID_LEN)) {
        printf("Invalid UID: must be %d digits.\n", UID_LEN);
        return;
    }
    if (!check_pass(password, PASSWORD_LEN)) {
        printf("Invalid password: must be %d alphanumeric characters.\n",
               PASSWORD_LEN);
        return;
    }

    char msg[MAX_MSG];
    char reply[MAX_MSG];
    build_login_msg(msg, sizeof(msg), uid, password, cfg->peer_port);

    if (send_udp_request(cfg->ds_ip, cfg->ds_port, msg, reply, sizeof(reply)) != 0) {
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
        printf("You are now logged in.\n\nWelcome back %s!\n", uid);
        sess->logged_in = 1;
        strncpy(sess->uid, uid, UID_LEN); 
        sess->uid[UID_LEN] = '\0';
        strncpy(sess->password, password, PASSWORD_LEN); 
        sess->password[PASSWORD_LEN] = '\0';
    } else if (strcmp(status, "REG") == 0) {
        printf("New user registered and logged in.\n");
        sess->logged_in = 1;
        strncpy(sess->uid, uid, UID_LEN); sess->uid[UID_LEN] = '\0';
        strncpy(sess->password, password, PASSWORD_LEN); sess->password[PASSWORD_LEN] = '\0';
    } else if (strcmp(status, "NOK") == 0) {
        printf("Incorrect login attempt. Try again.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Login failed: DS reports a protocol error.\n");
    } else {
        printf("Login failed: unknown status \"%s\".\n", status);
    }
}

static void handle_logout(const DSConfig *cfg, UserSession *sess) {
    if (!sess->logged_in) {//if logged_in is 0
        printf("No user is currently logged in.\n");
        return;
    }

    char msg[MAX_MSG], reply[MAX_MSG];
    build_logout_msg(msg, sizeof(msg), sess->uid, sess->password);

    if (send_udp_request(cfg->ds_ip, cfg->ds_port, msg, reply, sizeof(reply)) != 0) {
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
        printf("You are now logged out.\n");
        sess->logged_in = 0;
        memset(sess->uid, 0, sizeof(sess->uid));
        memset(sess->password, 0, sizeof(sess->password));
    } else if (strcmp(status, "NLG") == 0) {
        printf("User is not logged in.\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("User is not registered.\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Incorrect password. Try again.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Logout failed: DS reports a protocol error.\n");
    } else {
        printf("Logout failed: unknown status \"%s\".\n", status);
    }
}

static void handle_unregister(const DSConfig *cfg, UserSession *sess) {
    if (!sess->logged_in) {
        printf("No user is currently logged in.\n");
        return;
    }

    char msg[MAX_MSG], reply[MAX_MSG];
    build_unregister_msg(msg, sizeof(msg), sess->uid, sess->password);

    if (send_udp_request(cfg->ds_ip, cfg->ds_port, msg, reply, sizeof(reply)) != 0) {
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
        sess->logged_in = 0;
        memset(sess->uid, 0, sizeof(sess->uid));
        memset(sess->password, 0, sizeof(sess->password));
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

void command_loop(const DSConfig *cfg, UserSession *sess) {
    char input[MAX_CMD_LINE];
    char cmd[32] = {0};
    printf("\n\nNetBoX is ready for you!\n\n"
                "Type a command, to talk, or 'exit', to leave.\n\nHave fun! :)\n");

    while (1) {
        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) {//if fgets == NULL
            putchar('\n');
            if (sess->logged_in) {
                printf("Don't forget to logout before exiting.\n");
                continue;
            }
            break;
        }

        clean_input(input);
        if (input[0] == '\0') continue;

        
        int consumed = 0;
        if (sscanf(input, "%31s%n", cmd, &consumed) != 1) {
            printf("I don't recognized that command. ");
            print_help();
            continue;
        }
        char *rest = input + consumed;
        while (*rest == ' ') rest++;

        if (strcmp(cmd, "login") == 0) {
            char uid[64] = {0}, password[64] = {0};
            if (sscanf(rest, "%63s %63s", uid, password) != 2) {
                printf("Format: login UID password\n");
                continue;
            }
            handle_login(cfg, sess, uid, password);

        } else if (strcmp(cmd, "logout") == 0) {
            handle_logout(cfg, sess);

        } else if (strcmp(cmd, "unregister") == 0) {
            handle_unregister(cfg, sess);

        } else if (strcmp(cmd, "exit") == 0) {
            if (sess->logged_in) {
                printf("Don't forget to logout before exiting.\n");
            } else {
                break;
            }

        } else {
            printf("I don't recognized the command \"%s\". ", cmd);
            print_help();
        }
    }

    printf("Bye! <3\n");
}