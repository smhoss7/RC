#define _POSIX_C_SOURCE 200809L

#include "app.h"
#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

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

/* Filename: up to 24 chars, "base.ext" where base is letters, digits,
 * '-' or '_' and ext is exactly 3 alphanumeric characters */
static int check_filename(const char *str) {
    size_t len = strlen(str);
    if (len < 5 || len > MAX_FILENAME_LEN) return 0;
    if (str[len - 4] != '.') return 0;
    for (size_t i = 0; i < len - 4; i++) {
        unsigned char c = (unsigned char)str[i];
        if (!isalnum(c) && c != '-' && c != '_') return 0;
    }
    for (size_t i = len - 3; i < len; i++) {
        if (!isalnum((unsigned char)str[i])) return 0;
    }
    return 1;
}

/* Label: 1-20 chars, letters, digits, '-' or '_' */
static int check_label(const char *str) {
    size_t len = strlen(str);
    if (len < 1 || len > MAX_LABEL_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)str[i];
        if (!isalnum(c) && c != '-' && c != '_') return 0;
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
        "  publish filename label\n"
        "  remove filename\n"
        "  list\n"
        "  versions filename\n"
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

static void handle_publish(const DSConfig *cfg, UserSession *sess,
                           const char *filename, const char *label) {
    if (!sess->logged_in) {
        printf("No user is currently logged in.\n");
        return;
    }
    if (!check_filename(filename)) {
        printf("Invalid filename: up to %d characters, \"name.ext\" with a "
               "3-character extension (letters, digits, '-', '_').\n",
               MAX_FILENAME_LEN);
        return;
    }
    if (!check_label(label)) {
        printf("Invalid label: 1-%d characters (letters, digits, '-', '_').\n",
               MAX_LABEL_LEN);
        return;
    }

    /* The file must exist locally before anything is sent to the DS */
    struct stat st;
    if (stat(filename, &st) != 0 || !S_ISREG(st.st_mode)) {
        printf("File \"%s\" does not exist in the local directory.\n", filename);
        return;
    }
    if (st.st_size > MAX_FSIZE) {
        printf("File \"%s\" is too large (%lld bytes, max %ld).\n",
               filename, (long long)st.st_size, MAX_FSIZE);
        return;
    }
    long fsize = (long)st.st_size;

    char msg[MAX_MSG], reply[MAX_MSG];
    build_publish_msg(msg, sizeof(msg), sess->uid, sess->password,
                      filename, fsize, label);

    if (send_udp_request(cfg->ds_ip, cfg->ds_port, msg, reply, sizeof(reply)) != 0) {
        printf("Publish failed: no response from Directory Server.\n");
        return;
    }

    char tag[16], status[16];
    if (parse_status_reply(reply, tag, sizeof(tag), status, sizeof(status)) != 0
        || strcmp(tag, "RPB") != 0) {
        printf("Publish failed: unexpected reply from DS (\"%s\").\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("File \"%s\" published successfully (%ld bytes, label \"%s\").\n",
               filename, fsize, label);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Unsuccessful publication of \"%s\".\n", filename);
    } else if (strcmp(status, "NLG") == 0) {
        printf("User is not logged in.\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("User is not registered.\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Incorrect password.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Publish failed: DS reports a protocol error.\n");
    } else {
        printf("Publish failed: unknown status \"%s\".\n", status);
    }
}

static void handle_remove(const DSConfig *cfg, UserSession *sess,
                          const char *filename) {
    if (!sess->logged_in) {
        printf("No user is currently logged in.\n");
        return;
    }
    if (!check_filename(filename)) {
        printf("Invalid filename: up to %d characters, \"name.ext\" with a "
               "3-character extension (letters, digits, '-', '_').\n",
               MAX_FILENAME_LEN);
        return;
    }

    char msg[MAX_MSG], reply[MAX_MSG];
    build_remove_msg(msg, sizeof(msg), sess->uid, sess->password, filename);

    if (send_udp_request(cfg->ds_ip, cfg->ds_port, msg, reply, sizeof(reply)) != 0) {
        printf("Remove failed: no response from Directory Server.\n");
        return;
    }

    char tag[16], status[16];
    if (parse_status_reply(reply, tag, sizeof(tag), status, sizeof(status)) != 0
        || strcmp(tag, "RRM") != 0) {
        printf("Remove failed: unexpected reply from DS (\"%s\").\n", reply);
        return;
    }

    if (strcmp(status, "OK") == 0) {
        printf("File \"%s\" removed successfully.\n", filename);
    } else if (strcmp(status, "NOK") == 0) {
        printf("Resource \"%s\" not found among your published files.\n", filename);
    } else if (strcmp(status, "NLG") == 0) {
        printf("User is not logged in.\n");
    } else if (strcmp(status, "UNR") == 0) {
        printf("User is not registered.\n");
    } else if (strcmp(status, "WRP") == 0) {
        printf("Incorrect password.\n");
    } else if (strcmp(status, "ERR") == 0) {
        printf("Remove failed: DS reports a protocol error.\n");
    } else {
        printf("Remove failed: unknown status \"%s\".\n", status);
    }
}

static void handle_list(const DSConfig *cfg) {
    char msg[MAX_MSG], reply[MAX_UDP_REPLY];
    build_list_msg(msg, sizeof(msg));

    if (send_udp_request(cfg->ds_ip, cfg->ds_port, msg, reply, sizeof(reply)) != 0) {
        printf("List failed: no response from Directory Server.\n");
        return;
    }

    /* RLS status [filename]* -- consumed marks where the filenames start */
    char tag[16], status[16];
    int consumed = 0;
    if (sscanf(reply, "%15s %15s%n", tag, status, &consumed) != 2
        || strcmp(tag, "RLS") != 0) {
        printf("List failed: unexpected reply from DS (\"%s\").\n", reply);
        return;
    }

    if (strcmp(status, "NOK") == 0) {
        printf("No resources are currently available.\n");
        return;
    } else if (strcmp(status, "ERR") == 0) {
        printf("List failed: DS reports a protocol error.\n");
        return;
    } else if (strcmp(status, "OK") != 0) {
        printf("List failed: unknown status \"%s\".\n", status);
        return;
    }

    printf("Resources available in the network:\n");
    int count = 0;
    for (char *tok = strtok(reply + consumed, " "); tok != NULL;
         tok = strtok(NULL, " ")) {
        printf("  %2d. %s\n", ++count, tok);
    }
    if (count == 0) {
        printf("  (none)\n");
    } else {
        printf("%d file(s) found.\n", count);
    }
}

static void handle_versions(const DSConfig *cfg, const char *filename) {
    if (!check_filename(filename)) {
        printf("Invalid filename: up to %d characters, \"name.ext\" with a "
               "3-character extension (letters, digits, '-', '_').\n",
               MAX_FILENAME_LEN);
        return;
    }

    char msg[MAX_MSG];
    char *reply = NULL;
    build_versions_msg(msg, sizeof(msg), filename);

    if (send_tcp_request(cfg->ds_ip, cfg->ds_port, msg, &reply) != 0) {
        printf("Versions failed: no response from Directory Server.\n");
        return;
    }

    /* RVR status [UID Fsize label publication_time availability]* */
    char tag[16], status[16];
    int consumed = 0;
    if (sscanf(reply, "%15s %15s%n", tag, status, &consumed) != 2
        || strcmp(tag, "RVR") != 0) {
        printf("Versions failed: unexpected reply from DS (\"%s\").\n", reply);
        free(reply);
        return;
    }

    if (strcmp(status, "NOK") == 0) {
        printf("No peer is sharing \"%s\".\n", filename);
        free(reply);
        return;
    } else if (strcmp(status, "ERR") == 0) {
        printf("Versions failed: DS reports a protocol error.\n");
        free(reply);
        return;
    } else if (strcmp(status, "OK") != 0) {
        printf("Versions failed: unknown status \"%s\".\n", status);
        free(reply);
        return;
    }

    printf("Versions of \"%s\":\n", filename);
    printf("  %-6s  %10s  %-20s  %-20s  %s\n",
           "UID", "Size (B)", "Label", "Published", "Status");

    int count = 0, malformed = 0;
    char *tok = strtok(reply + consumed, " ");
    while (tok != NULL) {
        char *uid   = tok;
        char *fsize = strtok(NULL, " ");
        char *label = (fsize != NULL) ? strtok(NULL, " ") : NULL;
        if (label == NULL) { malformed = 1; break; }

        /* The publication time may itself contain spaces (e.g. date and
         * hour), so gather tokens until the AVL/NAV availability marker. */
        char when[64] = {0};
        char *avail = NULL;
        for (tok = strtok(NULL, " "); tok != NULL; tok = strtok(NULL, " ")) {
            if (strcmp(tok, "AVL") == 0 || strcmp(tok, "NAV") == 0) {
                avail = tok;
                break;
            }
            if (when[0] != '\0') strncat(when, " ", sizeof(when) - strlen(when) - 1);
            strncat(when, tok, sizeof(when) - strlen(when) - 1);
        }
        if (avail == NULL) { malformed = 1; break; }

        printf("  %-6s  %10s  %-20s  %-20s  %s\n", uid, fsize, label, when,
               strcmp(avail, "AVL") == 0 ? "online" : "offline");
        count++;
        tok = strtok(NULL, " ");
    }

    if (malformed || count == 0) {
        printf("(the reply from DS was malformed; some entries may be missing)\n");
    } else {
        printf("%d version(s) found.\n", count);
    }
    free(reply);
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

        } else if (strcmp(cmd, "publish") == 0) {
            char filename[64] = {0}, label[64] = {0};
            if (sscanf(rest, "%63s %63s", filename, label) != 2) {
                printf("Format: publish filename label\n");
                continue;
            }
            handle_publish(cfg, sess, filename, label);

        } else if (strcmp(cmd, "remove") == 0) {
            char filename[64] = {0};
            if (sscanf(rest, "%63s", filename) != 1) {
                printf("Format: remove filename\n");
                continue;
            }
            handle_remove(cfg, sess, filename);

        } else if (strcmp(cmd, "list") == 0) {
            handle_list(cfg);

        } else if (strcmp(cmd, "versions") == 0) {
            char filename[64] = {0};
            if (sscanf(rest, "%63s", filename) != 1) {
                printf("Format: versions filename\n");
                continue;
            }
            handle_versions(cfg, filename);

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