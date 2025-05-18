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

#include "../include/mqtt_com.h"
#include "../include/mqtt_control.h"
#include "../include/mqtt_util.h"


#define PORT 1883
#define BACKLOG 5

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

volatile sig_atomic_t keep_running = 1;


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

    int server_socket, client_socket;
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

        printf("Waiting for connection...");
        client_socket = accept(server_socket, (sockaddr *)&address, (socklen_t*)&addr_len);

        if (client_socket > 0) {
            printf("Established communication channel with client, waiting for CONNECT packet...\n");
            // Start a thread that handles client messages
            if (pthread_create(thread_id, NULL, process_client_messages, &client_socket)) {
                perror("Failed to start thread");
            } else { 
                push(&threads, thread_id);
            }
        }
        else {
            perrror("Connecting to client socket failed");
        }
    }

    // Cleanup
    for (size_t i=0; i < threads.size; ++i) {
        pthread_join(((pthread_t *)threads.data)[i], NULL);
    }
    free_vec(&threads);
    close(server_socket);
    return 0;
} 


void handle_sigint(int sig) {
    keep_running = 0;
}


void* process_client_messages(void* client_socket) {
    /*
    Params: client_socket is an integer file descriptor that represents a specific client/server socket connection.
    */

    /*
    The first message that is expected from the client once communication is established is an MQTT CONNECT control packet.
    Any other initial message will result in the client network connection being dropped.
    A unique client shall only send one CONNECT packet throghout its connection lifetime. Any duplicate CONNECT packets will
    result in the client network connection being dropped.
    */

    bool connection_alive = true;
    unsigned msg_number = 0;

    while (connection_alive) {
        mqtt_packet packet;
        char buffer[1024] = {0};
        int read_size = read(*(int *)client_socket, buffer, sizeof(buffer));  // The size in bytes of the message read from the client socket
        // Start a message timer

        if (read_size > 0) {
            // Parse the message received from the client.
            int packet_type = unpack(&packet, buffer, sizeof(buffer));
            switch(packet_type) {
                case -1:
                    printf("Encountered error while parsing client message");
                    break;
                case MQTT_CONNECT:
                    break;
            }

            // Check if the message received is a CONNECT packet.
            // ...

            // If yes, serialize a CONNACK message and send it to the client in acknowledgment of successful mqtt connection.
            // ...
        }
        else {
            connection_alive = false;
        }
    }   
};
