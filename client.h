// Interface for Client program

#ifndef CLIENT_H
#define CLIENT_H


// Constants
#define MAX_USERNAME_LEN 31

// Struct Definitions
struct client_input_args {
    int tcp_sock;
    int *thread_status;
    char username[MAX_USERNAME_LEN];
    bool *p2p_activeusers_issued;
    char *activeusers_res;
    pthread_mutex_t *p2p_activeusers_mutex;
    pthread_cond_t *p2p_activeusers_cond;
};

struct udp_server_args {
    int *client_status;
    char *udp_port;
};

/**
 * Prompts client to input either a username or password depending on the stage
 * of authentication (as received back from server).
*/
char *login_authentication(int tcp_sock);

/**
 * Thread to continuously get client command inputs. If the command is a p2pvideo
 * command request, an additional request for the activeuser command is made.
*/
void *client_input_thread(void *args);

/**
 * Thread to start a UDP socket connection to wait for any incoming p2pvideo transfer
 * requests.
*/
void *client_audience_thread(void *args);

/**
 * Wait to receive packets of data from presenter client for p2pvideo transfer.
*/
void receive_udp_packets(int *client_status, struct sockaddr_in client_audience, int sock);

/**
 * Thread that will receive any server responses from the command input thread.
 * Thread will close all other threads upon client logging out.
*/
void input_commands(int tcp_sock, char *udp_port, char *username);

/**
 * Given the p2pcommand line client inputted and the corresponding response from
 * the activeuser command made, extracts the details required for a p2pvideo
 * request. If any details are invalid, such as user being offline, file not existing,
 * or user not inputting existing files to transfer, command is not proccessed.
*/
void get_p2p_details(char *p2p_command, char *activeusers_res, char *username);

/**
 * Opens a UDP socket to send the file to audience client. Implements a reliability
 * application layer protocol.
*/
void send_p2p_file(FILE *file, char *username, char *file_to_transfer, char *addr, char *udp_port, long file_size);


#endif
