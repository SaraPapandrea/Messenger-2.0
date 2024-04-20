// Interface for Server program

#ifndef SERVER_H
#define SERVER_H


// Constants
#define MAX_USERNAME_LEN 31
#define MAX_GROUPCHAT_NAME_LEN 51

// Struct Definitions
struct thread_arg{
    int client_sock;
    int max_login_fails;
    struct connected_client *active_users;
    struct group *groups;
};

struct connected_client {
    int sock;
    char username[MAX_USERNAME_LEN];
};

struct group {
    char groupname[MAX_GROUPCHAT_NAME_LEN];
    char **joined_members;
    char **added_members;
    int num_add_membs;
    int num_joined_membs;
    int num_grp_msgs;
};

/**
 * Creates new empty userlog, blocklog and messagelog files.
 */
void create_empty_files(void);

/**
 * Destroys all initialised mutexes.
*/
void destroy_mutexes(void);

/**
 * Starts a client thread that will be used to start a client session including
 * authentication and command response.
 */
void *thread_run(void *args);

/**
 * Checks if the pointer parameter is NULL, meaning a memory allocation failed
 * and program will quit.
*/
void mem_allocation_fail_check(void *ptr);

/**
 * Checks if the pointer parameter is NULL, meaning a file failed to open, and
 * program will quit.
*/
void file_open_fail_check(void *ptr, char *filename);

/**
 * Authenticates clients username by comparing to credentials file. If client fails
 * to provide a valid username after the maximum amount of failed login attempts
 * client program will close.
*/
char *authenticate_username(int client_sock, int num_failed_attempts, int max_fails);

/**
 * Given a valid username (from authenticate_username), waits for client input
 * and will log client in if password matches username credentials. If after the
 * maximum amount of login attempts is exceeded, client is blocked for 10 seconds.
*/
char *authenticate_password(int client_sock, char *real_password, int num_failed_attempts, int max_fails, char *username);

/**
 * Searches the credentials.txt file to find a given username. Returns the username
 * if found else NULL.
*/
char *find_username_info(FILE *file, char *username, char char_divider);

/**
 * Upon giving invalid credentials (username or password), will check if the
 * maximum login attempts has been exceeded, in which case client is added to blocklog.txt
 * and blocked for 10 seconds, otherwise client is prompted to enter the credentials
 * again.
*/
char *invalid_credentials(int client_sock, char *invalid_type, char* password, int num_failed_attempts, int max_fails, char *username);

/**
 * Searches the blocklog.txt file to find if a given client is blocked. If function
 * is called after a client's blocking time is completed, client will be removed from
 * block file.
*/
bool check_blocked_user(char *username, int client_sock);

/**
 * Removes a particular username (and its log of information) from a particular
 * file.
*/
void remove_user_from_file(char *username, char *filename);

/**
 * Upon successful authentication, client is added to userlog.txt. This includes
 * username, IP address, UDP port number and the time logged in.
*/
void log_user(int client_sock, char *username);

/**
 * Fills a tm structure to represent the corresponding time.
*/
struct tm *get_time_stamp(void);

/**
 * Upon logging out, will remove the client from the active users struct array
 * containing a clients username and port number.
*/
void remove_active_user(char *username, struct connected_client *active_users);

/**
 * Upon receiving a command input from client, will call the corresponding command
 * request and send reply to respective client.
*/
void commands(int client_sock, char *username, struct connected_client *active_users, struct group *groups);

/**
 * Returns the port number of a connected client by searching the active users
 * struct array. Returns -1 if no client is found.
*/
int find_active_user(struct connected_client *active_users, char *username);

/**
 * Sends message to a particular client based off senders /msgto command arguments.
 * Checks to see if sender correctly inputted a username and a body of text to send
 * to destination client.
*/
void send_private_msg(char *sender, struct connected_client *active_users, char *args, char *add_msg, bool *additional_msg);

/**
 * Concatinates all active users details, or none if no users are active, to reply 
 * to an activeusers command request.
*/
void get_active_users(char *add_msg, bool *additional_msg, char *username);

/**
 * Checks to see a given string only contains alphanumeric characters.
*/
bool isAlphanumeric(char *string);

/**
 * Checks that the groupname to be created is valid and checks the client wanting
 * to create the group entered groupname and group member arguments.
*/
void create_group_error_check(char *sender, char *args, char *add_msg, bool *additional_msg, struct connected_client *active_users, struct group *groups);

/**
 * Creates the group chat and group chat message log.
*/
void create_group(char *sender, char *members, char *groupmsg_filename, char *groupname, char *add_msg, bool *additional_msg, struct connected_client *active_users, struct group *groups);

/**
 * Frees all memory associated with the array containing all made group information
*/
void free_groups(struct group *groups);

/**
 * Given a member hasn't already joined the group, and the member has been added to
 * the group in the first place, joins the member to the group.
*/
void join_group(char *groupname, char *username, char *add_msg, bool *additional_msg, struct group *groups);

/**
 * Adds all members names to the groups array.
*/
void concat_members_names(char *msg, struct group group);

/**
 * Will check to see if group exists and a message is given as an argument to send
 * to group. Only if the sender is a joined member of the group will the message
 * be sent.
*/
void send_group_msg(char *sender, struct connected_client *active_users, struct group *groups, char *args, char *add_msg, bool *additional_msg);

/**
 * For every joined member of an existing group, send the respective message and
 * add single message to the groups message log.
*/
void send_to_grp_members(char *sender, char *msg, struct group *group, struct connected_client *active_users, char *timestamp, char *groupchat);


#endif
