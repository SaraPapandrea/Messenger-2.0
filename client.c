#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include "client.h"

#define NUM_ARGS 4
#define MAX_MSG_LEN 1024
#define MAX_HOSTNAME_LEN 256
#define PENDING 0
#define SUCCESS 1
#define FAILED -1
#define MAX_USERNAME_LEN 31
#define MAX_PASSWORD_LEN 31
#define COMMAND_PROMPT_LEN 117
#define ACTIVE 1
#define LOGOUT 0
#define COMPLETE 1
#define NOT_COMPLETE 0
#define MAX_FILENAME_LEN 256
#define COMMAND_PROMPT "Enter one of the following commands (/msgto, /activeuser,"\
                       " /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout): "
#define ACTIVE_USER_COMMAND "/activeuser"
#define LOGOUT_COMMAND "/logout"
#define P2P_VID_COMMAND "/p2pvideo"


int main(int argc, char *argv[]) {
    if (argc != NUM_ARGS) {
        fprintf(stderr, "Usage: %s <server IP> <server port> <client udp port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;

    // convert IP address string to network address (in network byte ordering)
    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) != 1) {
        perror("could not set server IP address");
        exit(EXIT_FAILURE);
    }
    // convert port string to port number in network byte ordering
    server_addr.sin_port = htons((uint16_t)atoi(argv[2]));

    // create TCP client socket
    int tcp_sock;
    if ((tcp_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("could not create tcp socket");
        exit(EXIT_FAILURE);
    }

    // connect client to server
    if (connect(tcp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("could not connect to server");
        exit(EXIT_FAILURE);
    }

    // if username is NULL, then the client could not log in
    char *username = login_authentication(tcp_sock);
    if (username == NULL) {
        close(tcp_sock);
        exit(EXIT_FAILURE);
    }

    // the following four lines were adapted from 
    // <https://www.scaler.com/topics/display-hostname-and-ip-address/>
    char hostname[MAX_HOSTNAME_LEN];
    gethostname(hostname, MAX_HOSTNAME_LEN);
    struct hostent *host_info = gethostbyname(hostname);
    char *ip_addr = inet_ntoa(*(struct in_addr *)host_info->h_addr_list[0]);

    // send server the udp port number and IP address client listens to
    char numbers_to_send[30];
    snprintf(numbers_to_send, 30, "%s %s", argv[3], ip_addr);
    send(tcp_sock, numbers_to_send, strlen(numbers_to_send) + 1, 0);

    // client can now input commands
    input_commands(tcp_sock, argv[3], username);

    free(username);
    close(tcp_sock);

    return 0;
}

char *login_authentication(int tcp_sock) {
    char *username = malloc(sizeof(char) * MAX_USERNAME_LEN);
    int login_attempt = PENDING;
    while (login_attempt == PENDING) {
        // prepare to receive connection (login) response back from server
        char login_reply[MAX_MSG_LEN];
        int bytes_received = recv(tcp_sock, login_reply, MAX_MSG_LEN, 0);
        if (bytes_received == -1) {
            perror("could not receive server response");
            exit(EXIT_FAILURE);
        }
        
        printf("%s", login_reply);
        if (strstr(login_reply, "Username: ") != NULL) {
            // if response contains "Username:", client must input username
            fgets(username, MAX_USERNAME_LEN, stdin);
            send(tcp_sock, username, strlen(username) + 1, 0);
        } else if (strstr(login_reply, "Password: ") != NULL) {
            // if response contains "Password:", client must input password
            char password[MAX_PASSWORD_LEN];
            fgets(password, MAX_PASSWORD_LEN, stdin);
            send(tcp_sock, password, strlen(password) + 1, 0);
        } else if (strstr(login_reply, "Please try again later\n") != NULL) {
            // client is currently blocked from logging in, exit program
            login_attempt = FAILED;
        } else if (strcmp(login_reply, "Welcome to TESSENGER!\n") == 0) {
            // client successfully logged in, proceed to command prompts
            login_attempt = SUCCESS;
        }
    }

    // client was successfully authenticated, return the username
    if (login_attempt == SUCCESS) {
        username[strlen(username) - 1] = '\0';
        return username;
    }

    free(username);
    return NULL;
}

void *client_input_thread(void *args) {
    // access struct members contained in args
    int tcp_sock = (*(struct client_input_args *)args).tcp_sock;
    int *thread_status = (*(struct client_input_args *)args).thread_status;
    char *username = (*(struct client_input_args *)args).username;
    bool *p2p_activeusers_issued = (*(struct client_input_args *)args).p2p_activeusers_issued;
    char *activeusers_res = (*(struct client_input_args *)args).activeusers_res;
    pthread_mutex_t *p2p_activeusers_mutex = (*(struct client_input_args *)args).p2p_activeusers_mutex;
    pthread_cond_t *p2p_activeusers_cond = (*(struct client_input_args *)args).p2p_activeusers_cond;

    // char command[MAX_MSG_LEN];
    char *command = malloc(sizeof(char) * MAX_MSG_LEN);
    while (strcmp(command, LOGOUT_COMMAND) != 0) {        
        // get user input
        fgets(command, MAX_MSG_LEN, stdin);
        command[strlen(command) - 1] = '\0';
        send(tcp_sock, command, strlen(command) + 1, 0);

        // check if the respective command request was a p2pvideo request
        if (strncmp(command, P2P_VID_COMMAND, strlen(P2P_VID_COMMAND)) == 0 &&
            (command[strlen(P2P_VID_COMMAND)] == ' ' || command[strlen(P2P_VID_COMMAND)] == '\0')) {
            pthread_mutex_lock(p2p_activeusers_mutex);
            *p2p_activeusers_issued = true;
            // make an /activeuser command request
            send(tcp_sock, ACTIVE_USER_COMMAND, strlen(ACTIVE_USER_COMMAND) + 1, 0);
            while (*p2p_activeusers_issued) {
                // wait for the input_commands thread to copy the activeusers response
                // into activeusers_res
                pthread_cond_wait(p2p_activeusers_cond, p2p_activeusers_mutex);
            }
            pthread_mutex_unlock(p2p_activeusers_mutex);

            // continue to complete the p2pvideo transfer request
            get_p2p_details(command, activeusers_res, username);
        }
    }

    free(command);
    *thread_status = COMPLETE;
    return NULL;
}

void *client_audience_thread(void *args) {
    int *client_status = (*(struct udp_server_args *)args).client_status;
    char *udp_port = (*(struct udp_server_args *)args).udp_port;

    // create a udp socket to listen for incoming udp file sharing requests
    struct sockaddr_in client_audience;
    memset(&client_audience, 0, sizeof(client_audience));
    client_audience.sin_family = AF_INET;

    // convert port string to a port number in Network Byte Ordering
    client_audience.sin_port = htons((uint16_t)atoi(udp_port));
    client_audience.sin_addr.s_addr = htonl(INADDR_ANY);

    // create a UDP socket
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("could not create udp listen socket");
        exit(EXIT_FAILURE);
    }

    // bind socket to listen to incoming request on server
    if ((bind(sock, (struct sockaddr *)&client_audience, sizeof(client_audience))) == -1) {
        perror("could not bind udp socket");
        exit(EXIT_FAILURE);
    }

    // wait to receive udp requests
    receive_udp_packets(client_status, client_audience, sock);
    
    close(sock);
    return NULL;
}

void receive_udp_packets(int *client_status, struct sockaddr_in client_audience, int sock) {
    struct sockaddr_in presenter_client;
    socklen_t presenter_client_len = sizeof(presenter_client);

    while (*client_status == ACTIVE) {
        char sender[MAX_USERNAME_LEN];
        ssize_t bytes_received;
        int acknowledgement = 0;
        // first message received will be the senders username
        bytes_received = recvfrom(sock, sender, sizeof(sender), 0, 
                                  (struct sockaddr *)&presenter_client, &presenter_client_len);
        if (bytes_received <= 0) {
            perror("could not receive sender information");
            continue;
        }
        // send ACK for receiving senders username
        sendto(sock, &acknowledgement, sizeof(acknowledgement), 0,
               (struct sockaddr *)&presenter_client, presenter_client_len);

        char file_name[MAX_FILENAME_LEN];
        // next message received will be the file name
        bytes_received = recvfrom(sock, file_name, sizeof(file_name), 0, 
                                  (struct sockaddr *)&presenter_client, &presenter_client_len);
        if (bytes_received <= 0) {
            perror("could not receive file name");
            continue;
        }
        // send ACK for receiving file name
        sendto(sock, &acknowledgement, sizeof(acknowledgement), 0, 
               (struct sockaddr *)&presenter_client, presenter_client_len);

        long file_size;
        // next message received will be the size of the file
        bytes_received = recvfrom(sock, &file_size, sizeof(file_size), 0, 
                                  (struct sockaddr *)&presenter_client, &presenter_client_len);
        if (bytes_received <= 0) {
            perror("could not receive file size");
            continue;
        }
        // send ACK for receiving file size
        sendto(sock, &acknowledgement, sizeof(acknowledgement), 0, 
               (struct sockaddr *)&presenter_client, presenter_client_len);

        FILE *new_file = fopen(file_name, "wb");
        if (new_file == NULL) {
            perror("could not create file");
            continue;
        }

        char buffer[MAX_MSG_LEN];
        int expected_seq_num = 0;
        int total_bytes_received = 0;
        while (1) {
            if (total_bytes_received == file_size) {
                // received all packets so break out of loop to close socket
                break;
            }

            // receive the sequence number of the data packet being sent;
            int received_seq_num;
            recvfrom(sock, &received_seq_num, sizeof(received_seq_num), 0, 
                     (struct sockaddr *)&presenter_client, &presenter_client_len);
            // send ACK for receiving sequence number
            sendto(sock, &acknowledgement, sizeof(acknowledgement), 0, 
                   (struct sockaddr *)&presenter_client, presenter_client_len);

            // receive data packet (payload)
            bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, 
                                      (struct sockaddr *)&presenter_client, &presenter_client_len);
            if (received_seq_num == expected_seq_num) {
                fwrite(buffer, 1, bytes_received, new_file);
                total_bytes_received += bytes_received;
                expected_seq_num++;
            }

            // send ACK (number will be the same if presenter client needs to retransmit a packet)
            sendto(sock, &expected_seq_num, sizeof(expected_seq_num), 0, 
                   (struct sockaddr *)&presenter_client, presenter_client_len);
        }

        fclose(new_file);
        printf("\n\nReceived %s from %s\n\n%s", file_name, sender, COMMAND_PROMPT);
        fflush(stdout);
    }
}


void input_commands(int tcp_sock, char *udp_port, char *username) {
    int client_status = ACTIVE;
    int thread_status = NOT_COMPLETE;
    bool p2p_activeusers_issued = false;
    char *activeusers_res = malloc(sizeof(char) * (MAX_MSG_LEN + COMMAND_PROMPT_LEN));
    char *command_prompt = malloc(sizeof(char) * (MAX_MSG_LEN + COMMAND_PROMPT_LEN));
    
    // initialise arguments for client input thread
    pthread_t input_thread;
    struct client_input_args input_args;
    input_args.tcp_sock = tcp_sock;
    input_args.thread_status = &thread_status;
    strncpy(input_args.username, username, strlen(username) + 1);
    input_args.p2p_activeusers_issued = &p2p_activeusers_issued;
    input_args.activeusers_res = activeusers_res;
    pthread_cond_t p2p_activeusers_cond = PTHREAD_COND_INITIALIZER;
    input_args.p2p_activeusers_cond = &p2p_activeusers_cond;
    pthread_mutex_t p2p_activeusers_mutex = PTHREAD_MUTEX_INITIALIZER;
    input_args.p2p_activeusers_mutex = &p2p_activeusers_mutex;
    // create thread for user input
    if (pthread_create(&input_thread, NULL, client_input_thread, &input_args) != 0) {
        perror("could not create client input thread");
        exit(EXIT_FAILURE);
    };

    // initialise arguments for client udp server thread
    pthread_t udp_thread;
    struct udp_server_args udp_args;
    udp_args.client_status = &client_status;
    udp_args.udp_port = udp_port;
    // create thread for udp file transfer (user becomes a udp server)
    if (pthread_create(&udp_thread, NULL, client_audience_thread, &udp_args) != 0) {
        perror("could not create udp server thread");
        exit(EXIT_FAILURE);
    };

    while (client_status == ACTIVE) {
        // prepare to receive command prompt from server
        int bytes_received = recv(tcp_sock, command_prompt, MAX_MSG_LEN + COMMAND_PROMPT_LEN, 0);
        if (bytes_received == -1) {
            perror("could not receive server response");
            exit(EXIT_FAILURE);
        }

        if (p2p_activeusers_issued) {
            // the activeusers command was issued as a result of a p2pvideo command
            recv(tcp_sock, command_prompt, MAX_MSG_LEN + COMMAND_PROMPT_LEN, 0);
            pthread_mutex_lock(&p2p_activeusers_mutex);
            // copy the activeusers response to activeusers_res so audience_client_thread
            // can use the details
            strncpy(activeusers_res, command_prompt, strlen(command_prompt) + 1);
            p2p_activeusers_issued = false;
            // signal to the audience_client_thread that condition has been completed
            pthread_cond_signal(&p2p_activeusers_cond);
            pthread_mutex_unlock(&p2p_activeusers_mutex);
        } else {
            printf("%s", command_prompt);
            fflush(stdout);
            if (thread_status == COMPLETE && strstr(command_prompt, "Bye, ") != NULL) {
                // client issues logout command, exit the loop and continue to close connection
                client_status = LOGOUT;
            }
        }
    }

    // cleanup threads and memory allocations
    pthread_cond_destroy(&p2p_activeusers_cond);
    pthread_mutex_destroy(&p2p_activeusers_mutex);
    pthread_cancel(udp_thread);
    pthread_join(input_thread, NULL);
    free(command_prompt);
    free(activeusers_res);
}

void get_p2p_details(char *p2p_command, char *activeusers_res, char *username) {
    // extract the audience client username and file to be transferred name
    char *p2p_dest_user = strtok(p2p_command, " ");
    p2p_dest_user = strtok(NULL, " ");
    char *file_to_transfer = strtok(NULL, "\0");

    // check if a destination user and/or a file was not specified
    if (p2p_dest_user == NULL) {
        printf("\nPlease specify a user to transfer file to!\n\n%s", COMMAND_PROMPT);
        return;
    } else if (file_to_transfer == NULL) {
        printf("\nPlease specify a file to transfer!\n\n%s", COMMAND_PROMPT);
        return;
    }

    // check file exists of client presenter side
    FILE *file = fopen(file_to_transfer, "rb");
    if (file == NULL) {
        printf("\nFile does not exist!\n\n%s", COMMAND_PROMPT);
        return;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char audience_filename[strlen(file_to_transfer) + strlen(username) + 2];
    // add the presenter client name to the beginning of the file name
    snprintf(audience_filename, sizeof(audience_filename), "%s_%s", username, file_to_transfer);

    char *user_active = strstr(activeusers_res, p2p_dest_user);
    // check the client to send file to is active
    if (user_active == NULL || strncmp(user_active, p2p_dest_user, strlen(p2p_dest_user)) != 0 ||
        strncmp(&user_active[strlen(p2p_dest_user)], ", ", 2) != 0) {
        printf("\nUser is currently not active!\n\n%s", COMMAND_PROMPT);
        return;
    }

    // extract the udp port number and IP address of audience client from activeuser response
    char *addr = strtok(user_active, ", ");
    char *udp_port = strtok(NULL, ", ");
    udp_port = strtok(NULL, ", ");

    // file is now valid to be transferred
    send_p2p_file(file, username, audience_filename, addr, udp_port, file_size);
}


void send_p2p_file(FILE *file, char *username, char *file_to_transfer, char *addr, char *udp_port, long file_size) {
    // make UDP connection to destination user
    struct sockaddr_in presenter;
    memset(&presenter, 0, sizeof(presenter));
    presenter.sin_family = AF_INET;

    // convert IP address string to a network address (in Network Byte Ordering)
    inet_pton(AF_INET, addr, &presenter.sin_addr);
    // convert port string to a port number in Network Byte Ordering
    presenter.sin_port = htons((uint16_t)atoi(udp_port));

    int sock;
    // create socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("could not create socket");
        return;
    }

    socklen_t presenter_len = sizeof(presenter);
    int acknowledgement = 0;
    // send the username of the sender to client audience and receive an ACK 
    sendto(sock, username, strlen(username) + 1, 0, (struct sockaddr *)&presenter, presenter_len);
    recvfrom(sock, &acknowledgement, sizeof(acknowledgement), 0, (struct sockaddr *)&presenter, &presenter_len);

    // send file name to client audience and get an ACK back
    sendto(sock, file_to_transfer, strlen(file_to_transfer) + 1, 0, (struct sockaddr *)&presenter, presenter_len);
    recvfrom(sock, &acknowledgement, sizeof(acknowledgement), 0, (struct sockaddr *)&presenter, &presenter_len);

    // send file size to client audience (to know when to stop receiving packets) and receive an ACK
    sendto(sock, &file_size, sizeof(file_size), 0, (struct sockaddr *)&presenter, presenter_len);
    recvfrom(sock, &acknowledgement, sizeof(acknowledgement), 0, (struct sockaddr *)&presenter, &presenter_len);

    char buffer[MAX_MSG_LEN];
    ssize_t bytes_read;
    int seq_num = 0;
    while ((bytes_read = fread(buffer, 1, MAX_MSG_LEN, file)) > 0) {
        // send sequence number and receive an ACK
        sendto(sock, &seq_num, sizeof(seq_num), 0, (struct sockaddr *)&presenter, presenter_len);
        recvfrom(sock, &acknowledgement, sizeof(acknowledgement), 0, (struct sockaddr *)&presenter, &presenter_len);

        // send data with sequence number
        sendto(sock, buffer, bytes_read, 0, (struct sockaddr *)&presenter, presenter_len);

        while (1) {
            // wait for ACK
            int received_ack_num;
            recvfrom(sock, &received_ack_num, sizeof(received_ack_num), 0, (struct sockaddr *)&presenter, &presenter_len);

            // if audience received correct packet, break out of loop and send next packet
            if (received_ack_num == seq_num + 1) {
                break;
            }

            // audience did not receive correct packet, retransmit sequence number and receive an ACK
            sendto(sock, &seq_num, sizeof(seq_num), 0, (struct sockaddr *)&presenter, presenter_len);
            recvfrom(sock, &acknowledgement, sizeof(acknowledgement), 0, (struct sockaddr *)&presenter, &presenter_len);
            
            // retransmit packet data
            sendto(sock, buffer, bytes_read, 0, (struct sockaddr *)&presenter, presenter_len);
        }

        seq_num++;
    }

    printf("\n%s has been uploaded\n\n%s", file_to_transfer, COMMAND_PROMPT);

    fclose(file);
    close(sock);
}
