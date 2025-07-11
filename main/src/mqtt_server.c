#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>

#include "../include/mqtt_parser.h"
#include "../include/mqtt_protocol.h"
#include "../include/mqtt_util.h"


#define PORT 1883
#define BACKLOG 5
#define TIMEOUT_INTERVAL_SECONDS    20      // The client socket will timeout following this interval before a CONNECT (keep alive) packet is sent
#define TIMEOUT_INTERVAL_USECONDS   0       // Time interval in microseconds

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

volatile sig_atomic_t keep_running = 1;
vector client_list = {0};


void handle_sigint() {
    keep_running = 0;
}


int mqtt_handle_connect(int client_socket, mqtt_connect connect) {
    // Store session state for the current client
    session_state client_session = {
        .client_socket = client_socket,
        .clean_session = (connect.connect_flags & CLEAN_SESSION_FLAG) == CLEAN_SESSION_FLAG,
        .subscriptions = NULL,
        .unaknowledged_message_ids = NULL,
    };
    client_session.client_id = malloc(strlen(connect.payload.client_id));
    if (!client_session.client_id) {
        perror("Failed client ID malloc when trying to update session state!");
        return -1;
    }
    strcpy(client_session.client_id, connect.payload.client_id);

    return 0;

    // Pack and send connack
}


void *process_client_messages(void *arg) {
    /*
    Params: client_socket is an integer file descriptor that represents a specific client/server socket connection.
    */

    /*
    The first message that is expected from the client once communication is established is an MQTT CONNECT control packet.
    Any other initial message will result in the client network connection being dropped.
    A unique client must only send one CONNECT packet throghout its connection lifetime. Any duplicate CONNECT packets will
    result in the client network connection being dropped.
    */
    int client_socket = *(int *)arg;

    // Set an initial appropriate client timeout before the keep alive parameter is set via the CONNECT packet
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_INTERVAL_SECONDS;
    timeout.tv_usec = TIMEOUT_INTERVAL_USECONDS;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    unsigned msg_number = 0;
    bool connection_alive = true;

    while (connection_alive) {
        mqtt_packet packet = {0};
        uint8_t *buffer = malloc(1024);
        if (!buffer) exit(EXIT_FAILURE);
        
        int read_size = read(client_socket, buffer, 1024);  // The size in bytes of the message read from the client socket
        printf("Buffer Size = %d\n", read_size);
        for (int i = 0; i < read_size; ++i) {
            printf("%02X\n", buffer[i]);
        }

        if (read_size > 0) {
            // Parse the message received from the client.
            int packet_type = unpack(&packet, &buffer, read_size);  // Reconstruct bytestream as mqtt_packet and store in packet
            if (msg_number == 0 && packet_type != MQTT_CONNECT) {
                perror("Unexpected MQTT packet type. First packet MUST be MQTT_CONNECT, dropping connection...\n");
                // drop_client(*(int *)client_socket);
                exit(EXIT_FAILURE);
            }
            if (msg_number > 0 && packet_type == MQTT_CONNECT) {
                perror("Duplicate MQTT_CONNECT packet detected, dropping connection...\n");
                // drop_client(*(int *)client_socket);
                exit(EXIT_FAILURE);
            }

            switch(packet_type) {
                case MQTT_CONNECT: {
                    // Validate connect
                    mqtt_connect con = packet.type.connect;
                    timeout.tv_sec = con.keep_alive;
                    timeout.tv_usec = TIMEOUT_INTERVAL_USECONDS;
                    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    printf("Client ID = %s\n", con.payload.client_id);

                    if (mqtt_handle_connect(client_socket, con)) {
                        return NULL;  // Terminate client connection
                    }
                    break;
                }
                // case MQTT_PUBLISH:
                //     mqtt_handle_publish();
                //     break;
                // case MQTT_PUBACK:
                //     mqtt_handle_puback();
                //     break;
                // case MQTT_SUBSCRIBE:
                //     mqtt_handle_subscribe();
                //     break;
                // case MQTT_UNSUBSCRIBE:
                //     mqtt_handle_unsubscribe();
                //     break;
                // case MQTT_DISCONNECT:
                //     mqtt_handle_disconnect();
                //     break;
                
                default:
                    perror("Encountered error while parsing client message!\n");
                    break;
            }
            ++msg_number;
        }
        else {
            connection_alive = false;
            close(client_socket);
            printf("Client connection terminated!\n");
        }
    }   
    return NULL;
};


int main() {
    vector threads = {
        .capacity = 10,     // Assign some initial capacity for client connections
        .size = 0,
        .data = malloc(threads.capacity * sizeof(pthread_t)),
        .item_size = sizeof(pthread_t)
    };
    if (!threads.data) {
        perror("Malloc failed!");
        exit(EXIT_FAILURE);
    }

    int server_socket;
    sockaddr_in address;
    int addr_len = sizeof(address);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    check(server_socket, "Failed to create socket!");

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    check(bind(server_socket, (sockaddr *)&address, sizeof(address)), "Failed to bind socket!");
    check(listen(server_socket, BACKLOG), "Failed to start listening for connections!");

    printf("MQTT server listening on port %d...\n", PORT);

    signal(SIGINT, handle_sigint);  // Shutdown gracefully on ctrl + c
    while (keep_running) {
        pthread_t thread_id;

        int client_socket = accept(server_socket, (sockaddr *)&address, (socklen_t*)&addr_len);
        if (client_socket > 0) {
            printf("Established communication channel with client, waiting for CONNECT packet...\n");
            // Start a thread that handles client messages
            if (pthread_create(&thread_id, NULL, process_client_messages, &client_socket)) {
                perror("Failed to start thread");
            } else { 
                push(&threads, *(pthread_t *)thread_id);
            }
        }
        else {
            perror("Connecting to client socket failed");
        }
    }

    printf("Cleanup!\n");   // for debugging
    // Cleanup
    for (size_t i=0; i < threads.size; ++i) {
        pthread_join(((pthread_t *)threads.data)[i], NULL);
    }
    free_vec(&threads);
    close(server_socket);
    return 0;
} 
