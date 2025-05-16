#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 1883
#define BACKLOG 5

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;


int check(int status) {
    /* Error checking function */
    
    if (status < 0) {
        perror("Failed to establish socket connection!");
        exit(EXIT_FAILURE);
        return -1;
    }
    return 0;
}


int main() {
    int server_socket, client_socket;
    sockaddr_in address;
    int addr_len = sizeof(address);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    check(server_socket);

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    check(bind(server_socket, (sockaddr *)&address, sizeof(address)));
    check(listen(server_socket, BACKLOG));

    printf("MQTT server listening on port %d...\n", PORT);

    while ((client_socket = accept(server_socket, (sockaddr *)&address, (socklen_t*)&addr_len)) >= 0) {
        printf("Client connected\n");

        char buffer[1024] = {0};
        int read_size = read(client_socket, buffer, sizeof(buffer));  // The size in bytes of the message read from the client socket
        if (read_size > 0) {
            printf("Received %d bytes:\n", read_size);
            for (int i = 0; i < read_size; ++i) {
                printf("%02X ", (unsigned char)buffer[i]);
            }
            printf("\n");
        }

        close(client_socket);
        printf("Client disconnected\n");
    }

    close(server_socket);
    return 0;
}
