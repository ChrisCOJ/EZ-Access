#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../include/mqtt_protocol.h"
#include "../include/mqtt_parser.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 1883


int send_connect_packet(int socket) {
    char *client_id = "Test Client";
    mqtt_connect conn = default_init_connect(client_id, strlen(client_id));

    packing_status status = pack_connect(&conn);
    if (status.return_code < 0) {
        printf("Packing connect failed with err code %d", status.return_code);
    }

    // for (int i = 0; i < status.buf_len; ++i) {
    //     printf("%X\n", status.buf[i]);
    // }

    ssize_t bytes_written = send(socket, (uint8_t *)status.buf, status.buf_len, 0);
    if (bytes_written  == -1) {
        perror("Send failed!");
    }
    return 0;
}


void on_connect(int socket) {
    send_connect_packet(socket);
}


int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    // Set server details
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convert IP
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        return EXIT_FAILURE;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return EXIT_FAILURE;
    }

    printf("Connected to MQTT server.\n");

    on_connect(sock);
}