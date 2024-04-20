#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdatomic.h>

#include "server.h"

// CONSTANTS
#define NUM_ARGS 3
#define MAX_MSG_LEN 1024
#define MAX_FILENAME_LEN 256
#define LISTEN_WAIT_SIZE 5
#define MAX_USERNAME_LEN 31
#define MAX_PASSWORD_LEN 31
#define INVALID_LOGIN_MSG_LEN 83
#define TIMESTAMP_LEN 21
#define COMMAND_PROMPT_LEN 117
#define BLOCK_TIME 10
#define INITIAL_MAX_USERS 100
#define CREDENTIALS_FILE "credentials.txt"
#define USER_FILE "userlog.txt"
#define BLOCK_FILE "blocklog.txt"
#define MESSAGE_FILE "messagelog.txt"
#define USERNAME_TYPE "Username"
#define PASSWORD_TYPE "Password"
#define COMMAND_PROMPT "Enter one of the following commands (/msgto, /activeuser,"\
                       " /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout): "
#define PRIV_MSG_COMMAND "/msgto"
#define ACTIVE_USER_COMMAND "/activeuser"
#define CREATE_GRP_COMMAND "/creategroup"
#define JOIN_GRP_COMMAND "/joingroup"
#define GRP_MSG_COMMAND "/groupmsg"
#define LOGOUT_COMMAND "/logout"
#define P2P_VID_COMMAND "/p2pvideo"

// keep track of how many users have logged in
atomic_int num_active_users = 0;

// keep track of the number of messages made
atomic_int num_messages = 0;

// keep track of the number of group chats that have been made
atomic_int num_groups = 0;

// mutex lock for adding client socket num and username to active_users struct
pthread_mutex_t add_active_user_mutex = PTHREAD_MUTEX_INITIALIZER;

// mutex lock for removing user from active_users struct array
pthread_mutex_t remove_active_user_mutex = PTHREAD_MUTEX_INITIALIZER;

// mutex lock for searching active_users struct array
pthread_mutex_t find_active_user_mutex = PTHREAD_MUTEX_INITIALIZER;


int main(int argc, char *argv[]) {
    if (argc != NUM_ARGS) {
        fprintf(stderr, "Usage: %s <port num> <num allowed consec failed attempts>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (atoi(argv[2]) < 1 || atoi(argv[2]) > 5) {
        fprintf(stderr, "Invalid number of allowed failed consecutive attempts: %s\n", argv[2]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    // convert port string to port number in network byte ordering
    server_addr.sin_port = htons((uint16_t)atoi(argv[1]));

    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // create TCP server socket
    int server_sock;
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("could not create server socket");
        exit(EXIT_FAILURE);
    }

    // bind socket to listen to incoming connections on connected server
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("could not bind server socket");
        exit(EXIT_FAILURE);
    }

    // make socket listen for incoming connections
    if (listen(server_sock, LISTEN_WAIT_SIZE) == -1) {
        perror("could not open socket for listening");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    create_empty_files();

    int max_users = INITIAL_MAX_USERS;
    // malloc memory for the thread id nums and thread arguments (to be passed into pthread_create)
    pthread_t *thread_ids = malloc(sizeof(pthread_t) * max_users);
    mem_allocation_fail_check(thread_ids);
    struct thread_arg *thread_args = malloc(sizeof(struct thread_arg) * max_users);
    mem_allocation_fail_check(thread_args);

    // malloc memory for the active_users struct (keep track of all connected clients)
    struct connected_client *active_users = malloc(sizeof(struct connected_client) * max_users);
    mem_allocation_fail_check(active_users);

    // malloc memory for an initial group chat
    struct group *groups = malloc(sizeof(struct group) * max_users);
    mem_allocation_fail_check(groups);

    for (int i = 0; ; i++) {
        int client_sock;
        // accept an incoming client connection
        if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len)) == -1) {
            perror("could not accept incoming client");
            exit(EXIT_FAILURE);
        }

        // if the number of users exceeds the current maximum, double the amount of 
        // thread_ids, thread args and active_users struct
        if (i == max_users - 1) {
            max_users *= 2;
            thread_ids = realloc(thread_ids, sizeof(pthread_t) * max_users);
            mem_allocation_fail_check(thread_ids);

            thread_args = realloc(thread_args, sizeof(struct thread_arg) * max_users);
            mem_allocation_fail_check(thread_args);
            
            active_users = realloc(active_users, sizeof(struct connected_client) * max_users);
            mem_allocation_fail_check(active_users);

            groups = realloc(groups, sizeof(struct group) * max_users);
            mem_allocation_fail_check(groups);
        }

        // initialise the thread arguments for the respective client
        struct thread_arg new_thread_arg;
        new_thread_arg.client_sock = client_sock;
        new_thread_arg.max_login_fails = atoi(argv[2]);
        new_thread_arg.active_users = active_users;
        new_thread_arg.groups = groups;
        thread_args[i] = new_thread_arg;

        // create a new thread for client
        if (pthread_create(&thread_ids[i], NULL, thread_run, &thread_args[i]) != 0) {
            perror("could not create client process");
            exit(EXIT_FAILURE);
        };
    }
    
    free_groups(groups);
    free(active_users);
    free(thread_args);
    free(thread_ids);
    destroy_mutexes();

    close(server_sock);

    return 0;
}

void create_empty_files(void) {
    // create new empty userlogs
    FILE *user_log = fopen(USER_FILE, "w");
    file_open_fail_check(user_log, USER_FILE);
    fclose(user_log);

    // create new empty blocklogs
    FILE *block_log = fopen(BLOCK_FILE, "w");
    file_open_fail_check(block_log, BLOCK_FILE);
    fclose(block_log);

    // create new empty messagelogs
    FILE *msg_log = fopen(MESSAGE_FILE, "w");
    file_open_fail_check(msg_log, MESSAGE_FILE);
    fclose(msg_log);
}

void destroy_mutexes(void) {
    // destroy all initalised mutexes
    if (pthread_mutex_destroy(&add_active_user_mutex) != 0) {
        fprintf(stderr, "could not destroy mutex");
        exit(EXIT_FAILURE);
    };

    if (pthread_mutex_destroy(&remove_active_user_mutex) != 0) {
        fprintf(stderr, "could not destroy mutex");
        exit(EXIT_FAILURE);
    };

    if (pthread_mutex_destroy(&find_active_user_mutex) != 0) {
        fprintf(stderr, "could not destroy mutex");
        exit(EXIT_FAILURE);
    };
}

void *thread_run(void *args) {
    int client_sock = (*(struct thread_arg *)args).client_sock;
    int max_fails = (*(struct thread_arg *)args).max_login_fails;
    struct connected_client *active_users = (*(struct thread_arg *)args).active_users;
    struct group *groups = (*(struct thread_arg *)args).groups;

    char login_prompt[] = "Please login\nUsername: ";
    send(client_sock, login_prompt, strlen(login_prompt) + 1, 0);

    // if user was authenticated, username will point to a string of the username, 
    // otherwise it will be NULL
    char *username = authenticate_username(client_sock, 0, max_fails);

    if (username != NULL) {
        // add logged in user to the active users struct array
        pthread_mutex_lock(&add_active_user_mutex);
        active_users[num_active_users].sock = client_sock;
        memcpy(active_users[num_active_users].username, username, strlen(username) + 1);
        num_active_users++;
        pthread_mutex_unlock(&add_active_user_mutex);

        // add logged in user to the userlog.txt file
        log_user(client_sock, username);

        // prompt user for commands
        commands(client_sock, username, active_users, groups);

        free(username);
        close(client_sock);
    }
    
    return NULL;
}

void mem_allocation_fail_check(void *ptr) {
    if (ptr == NULL) {
        fprintf(stderr, "could not allocate memory");
        exit(EXIT_FAILURE);
    }
}

void file_open_fail_check(void *ptr, char *filename) {
    char fail_msg[MAX_FILENAME_LEN];
    if (ptr == NULL) {
        snprintf(fail_msg, MAX_FILENAME_LEN, "could not open %s", filename);
        perror(fail_msg);
        exit(EXIT_FAILURE);
    }
} 

char *authenticate_username(int client_sock, int num_failed_attempts, int max_fails) {
    char username[MAX_USERNAME_LEN];
    recv(client_sock, username, MAX_USERNAME_LEN, 0);
    username[strlen(username) - 1] = '\0';

    FILE *credentials = fopen(CREDENTIALS_FILE, "r");
    file_open_fail_check(credentials, CREDENTIALS_FILE);

    fseek(credentials, 0, SEEK_SET);
    // check the username exists in the database
    char *real_password = find_username_info(credentials, username, ' ');

    if (real_password == NULL) {
        // username did not exist
        return invalid_credentials(client_sock, USERNAME_TYPE, real_password, 
                                   num_failed_attempts + 1, max_fails, username);
    }

    fclose(credentials);
    // correct username, now have to authenticate password (reset number of 
    // consecutive fails after a successful username given
    char *valid_username = malloc(sizeof(username));
    mem_allocation_fail_check(valid_username);
    memcpy(valid_username, username, sizeof(username));

    // after username is successfully found, prompt client for password
    char password_prompt[] = "Password: ";
    send(client_sock, password_prompt, strlen(password_prompt) + 1, 0);
    return authenticate_password(client_sock, real_password, 0, max_fails, valid_username);
}

char *authenticate_password(int client_sock, char *real_password, int num_failed_attempts,
                            int max_fails, char *username) {
    // receive password input from client
    char password[MAX_PASSWORD_LEN];
    recv(client_sock, password, MAX_PASSWORD_LEN, 0);
    password[strlen(password) - 1] = '\0';

    // check password is valid
    if (strcmp(real_password, password) != 0) {
        // password did not match the provided usernames password
        return invalid_credentials(client_sock, PASSWORD_TYPE, real_password,
                                   num_failed_attempts + 1, max_fails, username);
    }

    free(real_password);
    bool is_blocked = check_blocked_user(username, client_sock);

    if (is_blocked) {
        // user is blocked
        return NULL;
    }

    // password inputted is valid
    send(client_sock, "Welcome to TESSENGER!\n", strlen("Welcome to TESSENGER!\n") + 1, 0);
    return username;
}

char *find_username_info(FILE *file, char *username, char char_divider) {
    char byte;
    int index = 0;
    while ((byte = fgetc(file)) != EOF) {
        if (byte == char_divider && index == strlen(username)) {
            // the next byte will be the start of the required info (either password
            // when searching credentials.txt or blocking time for blocking.txt)
            char *info = malloc(sizeof(char) * MAX_PASSWORD_LEN);
            mem_allocation_fail_check(info);
            byte = fgetc(file);
            // copy the info until a newline or EOF (end of respective information)
            for (index = 0; byte != '\n' && byte != EOF; index++) {
                info[index] = byte;
                byte = fgetc(file);
            }
            info[index] = '\0';

            return info;
        } else if (byte != username[index]) {
            // go to the start of the next line of information
            while (byte != '\n' && byte != EOF) {
                byte = fgetc(file);
            }

            index = 0;
        } else {
            index++;
        }
    }

    // username was not found, thus information could not be attained
    return NULL;
}

char *invalid_credentials(int client_sock, char *invalid_type, char* password,
                          int num_failed_attempts, int max_fails, char *username) {
    char invalid_login_msg[INVALID_LOGIN_MSG_LEN];
    if (num_failed_attempts >= max_fails) {
        // account is now blocked since user unsuccessfully tried to log in multiple times
        snprintf(invalid_login_msg, INVALID_LOGIN_MSG_LEN, "\nInvalid %s. Your account has"
                 " been blocked. Please try again later\n", invalid_type);
        send(client_sock, invalid_login_msg, strlen(invalid_login_msg) + 1, 0);

        if (password != NULL) {
            // user failed login at password entry stage so free previously allocated password
            // memory and record the blocking time in blocking.txt
            free(password);
            FILE *block_log = fopen(BLOCK_FILE, "a");
            file_open_fail_check(block_log, BLOCK_FILE);

            char block[MAX_MSG_LEN];
            snprintf(block, MAX_MSG_LEN, "%s; %ld\n", username, time(NULL));

            fseek(block_log, 0, SEEK_END);
            fputs(block, block_log);
            fclose(block_log);
        }

        return NULL;
    }

    // user failed login but is not blocked (failed attempts didn't exceed maximum)
    snprintf(invalid_login_msg, INVALID_LOGIN_MSG_LEN, "\nInvalid %s. Please try again\n%s: ",
             invalid_type, invalid_type);
    send(client_sock, invalid_login_msg, strlen(invalid_login_msg) + 1, 0);
    
    if (strcmp(invalid_type, USERNAME_TYPE) == 0) {
        // user failed at username input, prompt again for username
        return authenticate_username(client_sock, num_failed_attempts, max_fails);
    } else {
        // user failed at password input, prompt again for password
        return authenticate_password(client_sock, password, num_failed_attempts, 
                                     max_fails, username);
    }
}

bool check_blocked_user(char *username, int client_sock) {
    FILE *block_log = fopen(BLOCK_FILE, "r");
    file_open_fail_check(block_log, BLOCK_FILE);

    // find the initial time the user was blocked (if blocked at all)
    char *time_blocked = find_username_info(block_log, username, ';');

    if (time_blocked != NULL) {
        // user was blocked (username recorded in file)
        if (time(NULL) - atoi(time_blocked) > BLOCK_TIME) {
            // user has waited out enough time since last been blocked, can continue to login
            remove_user_from_file(username, BLOCK_FILE);
        } else {
            // user is still blocked from logging in
            char blocked_msg[] = "\nYour account is blocked due to multiple login failures. Please try again later\n";
            send(client_sock, blocked_msg, strlen(blocked_msg) + 1, 0);
            return true;
        }
    }

    fclose(block_log);
    return false;
}

void remove_user_from_file(char *username, char *filename) {
    FILE *file_to_change = fopen(filename, "r");
    file_open_fail_check(file_to_change, filename);
    fseek(file_to_change, 0, SEEK_SET);
    
    // create temporary file to copy non-removed contents over to
    FILE *tmp_file = fopen("tmpfile.txt", "w");
    file_open_fail_check(tmp_file, "tmpfile.txt");

    char buffer[MAX_MSG_LEN];
    int index = 1;
    bool found_user = false;
    // check each line (each record) in the file and copy it to the temp file, 
    // except for the line referring the usernames information
    while (fgets(buffer, MAX_MSG_LEN, file_to_change) != NULL) {
        char original_buffer[MAX_MSG_LEN];
        strncpy(original_buffer, buffer, strlen(buffer) + 1);
        
        // get the username as recorded in the logs
        char *name_to_compare = strtok(buffer, "; ");
        if (strcmp(USER_FILE, filename) == 0) {
            name_to_compare = strtok(NULL, ";");
            name_to_compare = strtok(NULL, "; ");
        }

        if (strcmp(name_to_compare, username) == 0) {
            // don't add the username to be removed to the new file
            found_user = true;
            continue;
        }
        
        if (strcmp(USER_FILE, filename) == 0) {
            if (found_user) {
                // decrement the user number for each log underneath the user to be removed
                char user_log[strlen(original_buffer) + 1];
                strncpy(user_log, original_buffer, strlen(original_buffer) + 1);
                snprintf(original_buffer, MAX_MSG_LEN, "%d%s", index, &user_log[1]);
            }
        }

        index++;
        fputs(original_buffer, tmp_file);
    }

    fflush(tmp_file);
    fclose(tmp_file);
    fclose(file_to_change);

    // remove original file (without removal)
    if (remove(filename) == -1) {
        perror("could not remove file");
        exit(EXIT_FAILURE);
    }

    // rename the temporary file to the original file name (with removals)
    if (rename("tmpfile.txt", filename) == -1) {
        perror("could not rename file");
        exit(EXIT_FAILURE);
    }
}


void log_user(int client_sock, char *username) {
    FILE *user_log = fopen(USER_FILE, "a");
    file_open_fail_check(user_log, USER_FILE);
    
    char buffer[30];
    recv(client_sock, buffer, 30, 0);

    char delimit[2] = " ";
    // extract the udp port number and IP address of the client to be logged in
    char *udp_port = strtok(buffer, delimit);
    char *ip_addr = strtok(NULL, delimit);

    char time_stamp[TIMESTAMP_LEN];
    // strftime(time_stamp, TIMESTAMP_LEN, "%F %T", get_time_stamp());
    strftime(time_stamp, TIMESTAMP_LEN, "%d %b %Y %X", get_time_stamp());

    char log[MAX_MSG_LEN];
    snprintf(log, MAX_MSG_LEN, "%d; %s; %s; %s; %s\n", num_active_users, time_stamp, username, ip_addr, udp_port);

    // write to userlog.txt of user login details
    fputs(log, user_log);
    fflush(user_log);
    fclose(user_log);
}

struct tm *get_time_stamp(void) {
    time_t cur_time = time(NULL);
    struct tm *time_info = gmtime(&cur_time);
    if (time_info == NULL) {
        perror("gmtime");
        exit(EXIT_FAILURE);
    };

    return time_info;
}

void remove_active_user(char *username, struct connected_client *active_users) {
    int user_index = 0;
    pthread_mutex_lock(&remove_active_user_mutex);
    for (int i = 0; i < num_active_users; i++) {
        if (strcmp(active_users[i].username, username) == 0) {
            user_index = i;
            break;
        }
    }

    for (int i = user_index; i < num_active_users - 1; i++) {
        // shift every user that follows the user to be removed in the array
        active_users[i] = active_users[i + 1];
    }
    pthread_mutex_unlock(&remove_active_user_mutex);
}

void commands(int client_sock, char *username, struct connected_client *active_users, struct group *groups) {
    char command_prompt[MAX_MSG_LEN + COMMAND_PROMPT_LEN];
    char command_res[MAX_MSG_LEN];
    char *add_msg = calloc((MAX_MSG_LEN + COMMAND_PROMPT_LEN), sizeof(char));
    mem_allocation_fail_check(add_msg);
    char command_options[] = COMMAND_PROMPT;
    bool additional_msg = false;
    
    while (1) {
        if (additional_msg == true) {
            // include the additional message in the next command prompt
            snprintf(command_prompt, MAX_MSG_LEN + COMMAND_PROMPT_LEN, "%s\n%s", add_msg, command_options);
            additional_msg = false;
        } else {
            // send normal command prompt string
            snprintf(command_prompt, COMMAND_PROMPT_LEN, "%s", command_options);
        }

        send(client_sock, command_prompt, strlen(command_prompt) + 1, 0);
        recv(client_sock, command_res, MAX_MSG_LEN, 0);

        // separate the command string from the following arguments (if no arguments 
        // are present, args will equal NULL)
        char *command = strtok(command_res, " ");
        if (command == NULL) {
            // if the command given was empty
            strncpy(add_msg, "\nError. Invalid Command!\n", MAX_MSG_LEN);
            additional_msg = true;
            continue;
        }
        char *args = strtok(NULL, "\0");

        // if the command matches any of the provided commands, perform the relevant
        // function, otherwise continue asking for commands
        if (strcmp(command, PRIV_MSG_COMMAND) == 0) {
            send_private_msg(username, active_users, args, add_msg, &additional_msg);
        } else if (strcmp(command, ACTIVE_USER_COMMAND) == 0 && args == NULL) {
            get_active_users(add_msg, &additional_msg, username);
        } else if (strcmp(command, CREATE_GRP_COMMAND) == 0) {
            create_group_error_check(username, args, add_msg, &additional_msg, active_users, groups);
        } else if (strcmp(command, JOIN_GRP_COMMAND) == 0) {
            join_group(args, username, add_msg, &additional_msg, groups);
        } else if (strcmp(command, GRP_MSG_COMMAND) == 0) {
            send_group_msg(username, active_users, groups, args, add_msg, &additional_msg);
        } else if (strcmp(command, LOGOUT_COMMAND) == 0) {
            int logout_len = strlen(username) + 8;
            snprintf(command_prompt, logout_len, "Bye, %s!\n", username);
            send(client_sock, command_prompt, logout_len, 0);
            // remove user from the userlog.txt file and from the active_users array
            remove_user_from_file(username, USER_FILE);
            remove_active_user(username, active_users);
            num_active_users--;
            break;
        } else if (strcmp(command, P2P_VID_COMMAND) == 0) {
            continue;
        } else {
            strncpy(add_msg, "\nError. Invalid Command!\n", MAX_MSG_LEN);
            additional_msg = true;
        }
    }
    free(add_msg);
}

int find_active_user(struct connected_client *active_users, char *username) {
    pthread_mutex_lock(&find_active_user_mutex);
    for (int i = 0; i < num_active_users; i++) {
        if (strcmp(active_users[i].username, username) == 0) {
            pthread_mutex_unlock(&find_active_user_mutex);
            // return the relevant socket number of the found user
            return active_users[i].sock;
        }
    }
    pthread_mutex_unlock(&find_active_user_mutex);

    return -1;
}

void send_private_msg(char *sender, struct connected_client *active_users, char *args, char *add_msg, bool *additional_msg) {
    // check if no username was inputted
    if (args == NULL) {
        strncpy(add_msg, "\nError. Please enter a username to send message to!\n", MAX_MSG_LEN);
        *additional_msg = true;
        // print to terminal the result of the failed issued command
        printf("%s issued /msgto command\nReturn message:%s", sender, add_msg);
        return;
    }

    char *dest_user = strtok(args, " ");
    char *message = strtok(NULL, "\0");
    // check if no message body was inputted
    if (message == NULL) {
        strncpy(add_msg, "\nError. Please enter a message to send!\n", MAX_MSG_LEN);
        *additional_msg = true;
        // print to terminal the result of the failed issued command
        printf("%s issued /msgto command\nReturn message:%s", sender, add_msg);
        return;
    }

    FILE *msg_log = fopen(MESSAGE_FILE, "a");
    file_open_fail_check(msg_log, MESSAGE_FILE);

    char time_stamp[TIMESTAMP_LEN];
    struct tm *curr_time = get_time_stamp();
    strftime(time_stamp, TIMESTAMP_LEN, "%F %T", curr_time);

    for (int i = 0; i < num_active_users; i++) {
        // search all the active users until you find the destination client
        if (strcmp(active_users[i].username, dest_user) == 0) {
            num_messages++;
            char msg[MAX_MSG_LEN + COMMAND_PROMPT_LEN];
            snprintf(msg, MAX_MSG_LEN, "%d; %s; %s; %s\n", num_messages, time_stamp, dest_user, message);
            // write message to message log
            fseek(msg_log, 0, SEEK_END);
            fputs(msg, msg_log);
            fflush(msg_log);
            fclose(msg_log);

            strftime(time_stamp, TIMESTAMP_LEN, "%d %b %Y %X", curr_time);
            snprintf(msg, MAX_MSG_LEN, "\n\n%s, %s: %s\n\n%s", time_stamp, sender, message, COMMAND_PROMPT);
            // send the message to the destination client
            send(active_users[i].sock, msg, strlen(msg) + 1, 0);

            snprintf(add_msg, MAX_MSG_LEN, "\nmessage sent at %s.\n", time_stamp);
            *additional_msg = true;

            // print to server terminal a confirmation of the message sent
            printf("%s message to %s \"%s\" at %s\n", sender, dest_user, message, time_stamp);
            return;
        }
    }

    // user was not found to be active, do not send message
    strncpy(add_msg, "\nError. This user is not active at the moment. Try again later!\n", MAX_MSG_LEN);
    *additional_msg = true;
    printf("%s issued /msgto command\nReturn message:%s", sender, add_msg);
    fclose(msg_log);
}

void get_active_users(char *add_msg, bool *additional_msg, char *username) {
    if (num_active_users == 1) {
        // there are no other active users except for the client sending the request
        snprintf(add_msg, MAX_MSG_LEN, "\nNo other active user\n");
        *additional_msg = true;
        printf("%s issued /activeuser command\nReturn message:%s", username, add_msg);
        return;
    }

    FILE *user_log = fopen(USER_FILE, "r");
    file_open_fail_check(user_log, USER_FILE);

    memset(add_msg, '\0', MAX_MSG_LEN + COMMAND_PROMPT_LEN);
    add_msg[0] = '\n';
    char buffer[MAX_MSG_LEN];
    while (fgets(buffer, MAX_MSG_LEN, user_log)) {
        // extract the relevant details for each user from the userlog.txt credentials
        strtok(buffer, "; ");
        char *date = strtok(NULL, ";");
        char *name = strtok(NULL, ";");
        char *ip_addr = strtok(NULL, "; ");
        char *udp_port = strtok(NULL, "\n");

        name = strtok(name, " ");
        if (strcmp(name, username) == 0) {
            // the current usernames information should be skipped
            continue;
        }

        char msg[MAX_MSG_LEN];
        snprintf(msg, MAX_MSG_LEN, "%s, %s,%s, active since%s.\n", name, ip_addr, udp_port, date);

        // add the active clients details to the response
        strncat(add_msg, msg, MAX_MSG_LEN - strlen(add_msg));
    }

    *additional_msg = true;
    // print to server terminal a confirmation of the activeusers command being issued
    printf("%s issued /activeuser command\nReturn message:%s", username, add_msg);
    fclose(user_log);
}

bool isAlphanumeric(char *string) {
    for (int i = 0; i < strlen(string); i++) {
        if (!isalnum(string[i])) {
            // found a non-alphanumeric character in the string
            return false;
        }
    }

    return true;
}

void create_group_error_check(char *sender, char *args, char *add_msg, bool *additional_msg, struct connected_client *active_users, struct group *groups) {
    // check if no arguments were provided after command (groupname or members to add)
    if (args == NULL) {
        strncpy(add_msg, "\nPlease enter a group name and members to add!\n", MAX_MSG_LEN);
        *additional_msg = true;
        printf("%s issued /creategroup command\nReturn message:\nGroup chat room is not created.%s", sender, add_msg);
        return;
    }

    char *groupname = strtok(args, " ");
    char *members = strtok(NULL, "\0");
    // check if no members were inputted as arguments
    if (members == NULL) {
        strncpy(add_msg, "\nPlease enter at least one more active user!\n", MAX_MSG_LEN);
        *additional_msg = true;
        printf("%s issued /creategroup command\nReturn message:\nGroup chat room is not created.%s", sender, add_msg);
        return;
    }

    // check if the groupname is valid (alphanumeric characters only)
    if (!isAlphanumeric(groupname)) {
        strncpy(add_msg, "\nGroupnames can only contain alphanumeric characters!\n", MAX_MSG_LEN);
        *additional_msg = true;
        printf("%s issued /creategroup command\nReturn message:\nGroup chat room is not created.%s", sender, add_msg);
        return;
    }

    char groupmsg_filename[MAX_FILENAME_LEN];
    snprintf(groupmsg_filename, MAX_FILENAME_LEN, "%s_messagelog.txt", groupname);
    // check that the groupchat name doesn't already exist
    if (access(groupmsg_filename, F_OK) == 0) {
        snprintf(add_msg, MAX_MSG_LEN, "\nFailed to create the group chat %s: group name exists!\n", groupname);
        *additional_msg = true;
        printf("%s issued /creategroup command\nReturn message:\nGroupname %s already exists.\n", sender, groupname);
        return;
    }

    // can now create the group
    create_group(sender, members, groupmsg_filename, groupname, add_msg, additional_msg, active_users, groups);
}


void create_group(char *sender, char *members, char *groupmsg_filename, char *groupname, char *add_msg, bool *additional_msg, struct connected_client *active_users, struct group *groups) {
    char added_members_string[MAX_MSG_LEN];
    strncpy(added_members_string, members, strlen(members) + 1);

    char *all_members[MAX_USERNAME_LEN];
    members = strtok(members, " ");
    int num_members_added = 0;
    for (int i = 0; members != NULL; i++) {
        // check if any of the inputted members to be added are not active
        if (find_active_user(active_users, members) == -1) {
            strncpy(add_msg, "\nPlease enter active users only!\n", MAX_MSG_LEN);
            *additional_msg = true;
            printf("%s issued /creategroup command\nReturn message:\nGroup chat room is not created.%s", sender, add_msg);

            for (int j = 0; j < num_members_added; j++) {
                // free all memory previously allocated
                free(all_members[j]);
            }
            return;
        }

        num_members_added++;
        all_members[i] = (char *)malloc(sizeof(char) * (strlen(members) + 1));
        mem_allocation_fail_check(all_members[i]);
        // add new member to the members array
        strncpy(all_members[i], members, strlen(members) + 1);
        members = strtok(NULL, " ");
    }

    // add all added members to the groups added_members array of strings
    groups[num_groups].added_members = (char **)malloc(sizeof(char *) * num_members_added);
    mem_allocation_fail_check(groups[num_groups].added_members);
    for (int i = 0; i < num_members_added; i++) {
        groups[num_groups].added_members[i] = (char *)malloc(sizeof(char) * (strlen(all_members[i]) + 1));
        mem_allocation_fail_check(groups[num_groups].added_members[i]);
        memcpy(groups[num_groups].added_members[i], all_members[i], strlen(all_members[i]) + 1);
        free(all_members[i]);
    }

    // add creator of group to the joined_members array of strings
    groups[num_groups].joined_members = (char **)malloc(sizeof(char *) * (num_members_added + 1));
    mem_allocation_fail_check(groups[num_groups].joined_members);
    groups[num_groups].joined_members[0] = (char *)malloc(sizeof(char) * (strlen(sender) + 1));
    mem_allocation_fail_check(groups[num_groups].joined_members[0]);
    memcpy(groups[num_groups].joined_members[0], sender, strlen(sender) + 1);

    // initialise all other fields for the group
    strncpy(groups[num_groups].groupname, groupname, strlen(groupname) + 1);
    groups[num_groups].num_add_membs = num_members_added;
    groups[num_groups].num_joined_membs = 1;
    groups[num_groups].num_grp_msgs = 0;
    num_groups++;

    // create message log file for groupchat
    FILE *group_msg_log = fopen(groupmsg_filename, "w");
    file_open_fail_check(group_msg_log, groupmsg_filename);
    fclose(group_msg_log);

    snprintf(add_msg, MAX_MSG_LEN, "\nGroup chat created %s\n", groupname);
    *additional_msg = true;
    // print to server terminal a confirmation of the group being created
    printf("%s issued /creategroup command\nReturn message:\nGroup chat room has been created"
           ", room name: %s, users in this room: %s, %s\n", sender, groupname, sender, added_members_string);
}


void free_groups(struct group *groups) {
    // free all memory allocated for the groups array
    for (int i = 0; i < num_groups; i++) {
        for (int j = 0; j < groups[i].num_add_membs; j++) {
            free(groups[i].added_members[j]);
        }
        
        for (int j = 0; j < groups[i].num_joined_membs; j++) {
            free(groups[i].joined_members[j]);
        }

        free(groups[i].added_members);
        free(groups[i].joined_members);
    }

    free(groups);
}

void join_group(char *groupname, char *username, char *add_msg, bool *additional_msg, struct group *groups) {
    if (groupname == NULL) {
        // client didn't give a groupname argument
        snprintf(add_msg, MAX_MSG_LEN, "\nPlease specify group to join!\n");
        *additional_msg = true;
        printf("%s issued /joingroup command\nReturn message:%s", username, add_msg);
        return;
    }

    // search the groups array until the wanted group is found
    for (int i = 0; i < num_groups; i++) {
        if (strcmp(groups[i].groupname, groupname) != 0) {
            continue;
        }

        // found groupchat with same groupname, now check if user has already joined the chat
        for (int j = 0; j < groups[i].num_joined_membs; j++) {
            if (strcmp(groups[i].joined_members[j], username) == 0) {
                // member has already joined the group
                snprintf(add_msg, MAX_MSG_LEN, "\nYou have already joined group chat %s\n", groupname);
                *additional_msg = true;
                printf("%s tries to re-join to a group chat %s\n", username, groupname);
                return;
            }
        }

        // now check if user is added to the chat, in which they can join the group chat
        for (int j = 0; j < groups[i].num_add_membs; j++) {
            if (strcmp(groups[i].added_members[j], username) == 0) {
                // join member to the group (joined_members array) and remove from added_members array
                groups[i].joined_members[groups[i].num_joined_membs] = (char *)malloc(sizeof(char) * (strlen(groups[i].added_members[j]) + 1));
                mem_allocation_fail_check(groups[i].joined_members[groups[i].num_joined_membs]);
                strncpy(groups[i].joined_members[groups[i].num_joined_membs], 
                        groups[i].added_members[j], strlen(groups[i].added_members[j]) + 1);
                free(groups[i].added_members[j]);
                
                for (int k = j; k < groups[i].num_add_membs - 1; k++) {
                    // rearrange the added members array to remove the newly joined member
                    groups[i].added_members[k] = groups[i].added_members[k + 1];
                }

                groups[i].added_members = (char **)realloc(groups[i].added_members, 
                                                           (groups[i].num_add_membs - 1) * sizeof(char *));
                if (groups[i].num_add_membs > 1) {
                    // if no members are left in the added_members array, pointer will
                    // equal NULL and always fail the check below
                    mem_allocation_fail_check(groups[i].added_members);
                }
                
                groups[i].num_add_membs--;
                groups[i].num_joined_membs++;

                snprintf(add_msg, MAX_MSG_LEN, "\nJoined the group chat: %s successfully.\n", groupname);
                *additional_msg = true;

                char print_msg[MAX_MSG_LEN];
                snprintf(print_msg, MAX_MSG_LEN, "%s issued /joingroup command\nReturn message: Join group chat room"
                        " successfully, room name: %s, users in this room: ", username, groupname);
                // concat all members name to server output statement
                concat_members_names(print_msg, groups[i]);

                return;
            }
        }

        // user is not a member of the group chat
        strncpy(add_msg, "\nYou are not a member of this group!\n", MAX_MSG_LEN);
        *additional_msg = true;
        // print to server terminal a confirmation of the member failing to join group
        printf("%s issued /joingroup command\nReturn message:%s", username, add_msg);
        return;
    }

    // group chat name doesn't exist
    snprintf(add_msg, MAX_MSG_LEN, "\nGroupchat %s doesn't exist.\n", groupname);
    *additional_msg = true;
    // print to server terminal a confirmation of member failing to join non-existent group
    printf("%s tried to join a group chat that doesn't exist.\n", username);
}

void concat_members_names(char *msg, struct group group) {
    for (int i = 0; i < group.num_joined_membs; i++) {
        strncat(msg, group.joined_members[i], (strlen(group.joined_members[i]) + 1));
        strncat(msg, ", ", 3);
    }

    for (int i = 0; i < group.num_add_membs; i++) {
        strncat(msg, group.added_members[i], (strlen(group.added_members[i]) + 1));
        strncat(msg, ", ", 3);
    }

    msg[strlen(msg) - 2] = '\0';
    printf("%s\n", msg);
}


void send_group_msg(char *sender, struct connected_client *active_users, struct group *groups, char *args, char *add_msg, bool *additional_msg) {
    // check that the group was inputted as an argument
    if (args == NULL) {
        strncpy(add_msg, "\nError. Please enter a group to send message to!\n", MAX_MSG_LEN);
        *additional_msg = true;
        printf("%s issued /groupmsg command\nReturn message:%s", sender, add_msg);
        return;
    }

    char *groupchat = strtok(args, " ");
    char *message = strtok(NULL, "\0");
    // check that there is a message body to send to the group
    if (message == NULL) {
        strncpy(add_msg, "\nError. Please enter a message to send to group!\n", MAX_MSG_LEN);
        *additional_msg = true;
        printf("%s issued /groupmsg command\nReturn message:%s", sender, add_msg);
        return;
    }

    for (int i = 0; i < num_groups; i++) {
        if (strcmp(groupchat, groups[i].groupname) != 0) {
            continue;
        }

        // found groupchat with same groupname, now check if sender has joined the chat
        for (int j = 0; j < groups[i].num_joined_membs; j++) {
            if (strcmp(groups[i].joined_members[j], sender) == 0) {
                // member has joined the group, can now send message
                char timestamp[TIMESTAMP_LEN];
                struct tm *curr_time = get_time_stamp();
                strftime(timestamp, TIMESTAMP_LEN, "%d %b %Y %X", curr_time);

                // send to all joined members of the group
                send_to_grp_members(sender, message, &groups[i], active_users, timestamp, groupchat);

                strncpy(add_msg, "\nGroup chat message sent\n", MAX_MSG_LEN);
                *additional_msg = true;
                // print to server terminal a confirmation of the message sent
                printf("%s issued a message in group chat %s: %s; %s; %s\n", sender, groupchat, timestamp, sender, message);
                return;
            }
        }

        // client was not a joined member of group, but check if they have been added (not joined)
        for (int j = 0; j < groups[i].num_add_membs; j++) {
            if (strcmp(groups[i].added_members[j], sender) == 0) {
                // member has been added to the group but hasn't joined (cannot send message)
                strncpy(add_msg, "\nPlease join the group before sending messages.\n", MAX_MSG_LEN);
                *additional_msg = true;
                // print to server terminal the command response
                printf("%s sent a message to a group chat, but %s hasn't joined the group.\n", sender, sender);
                return;
            }
        }

        // the sender isn't a member of this group
        strncpy(add_msg, "\nYou are not in this group chat.\n", MAX_MSG_LEN);
        *additional_msg = true;
        // print to server terminal the command response
        printf("%s sent a message to a group chat, but %s isn't a member of the group.\n", sender, sender);
        return;
    }

    // group chat doesn't exist
    snprintf(add_msg, MAX_MSG_LEN, "\nGroupchat %s doesn't exist.\n", groupchat);
    *additional_msg = true;
    printf("%s tried to send a message to a group chat that doesn't exist.\n", sender);
}

void send_to_grp_members(char *sender, char *msg, struct group *group, struct connected_client *active_users, char *timestamp, char *groupchat) {
    char group_file[MAX_MSG_LEN];
    snprintf(group_file, MAX_MSG_LEN, "%s_messagelog.txt", groupchat);
    
    FILE *msg_log = fopen(group_file, "a");
    file_open_fail_check(msg_log, group_file);
    
    group->num_grp_msgs++;
    char message[MAX_MSG_LEN + COMMAND_PROMPT_LEN];
    snprintf(message, MAX_MSG_LEN, "%d; %s; %s; %s\n", group->num_grp_msgs, timestamp, sender, msg);
    // write message to group message log
    fputs(message, msg_log);
    fflush(msg_log);

    for (int i = 0; i < group->num_joined_membs; i++) {
        if (strcmp(sender, group->joined_members[i]) == 0) {
            // don't send message to client who issued the group message
            continue;
        }

        int dest_sock = find_active_user(active_users, group->joined_members[i]);
        if (dest_sock == -1) {
            // group member is not active at current time, do not send message
            continue;
        }

        snprintf(message, MAX_MSG_LEN, "\n\n%s, %s, %s: %s\n\n%s", timestamp, groupchat, sender, msg, COMMAND_PROMPT);
        send(dest_sock, message, strlen(message) + 1, 0);
    }

    fclose(msg_log);
}
