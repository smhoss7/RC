#ifndef APP_H
#define APP_H

#include "network.h"

// /** Validates a UID
//  * @return 1 if the UID is valid, 0 otherwise
//  */
// static int check_uid(const char *str, size_t expected_len);

// /** Validates a password
//  * @return 1 if the password is valid, 0 otherwise
//  */
// static int check_pass(const char *str, size_t expected_len);

// /** Cleans a string by removing leading and trailing whitespace
//  */
// static void clean_input(char *str);

// /** Prints the help message
//  */
// static void print_help(void);

// /** Handles the login command
//  */
// static void handle_login(const DSConfig *cfg, UserSession *sess,
//                       const char *uid, const char *password);

// /** Handles the logout command
//  */
// static void handle_logout(const DSConfig *cfg, UserSession *sess);

// /** Handles the unregister command
//  */
// static void handle_unregister(const DSConfig *cfg, UserSession *sess);

/** The main command loop
 * Runs the interactive command prompt, for the program.
 */
void command_loop(const DSConfig *cfg, UserSession *sess);

#endif /* APP_H */