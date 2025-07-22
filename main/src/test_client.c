#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#include "../include/mqtt_protocol.h"
#include "../include/mqtt_parser.h"
#include "../include/mqtt_util.h"

#define SERVER_IP                   "127.0.0.1"
#define SERVER_PORT                 1883


int subscribe_to_topic(subscribe_tuples subscription, uint16_t *packet_id, int socket) {
    /* 
    Function that allows subscription to a single topic 
    */

    mqtt_subscribe sub = {
        .pkt_id = *packet_id,
        .tuples = &subscription,
        .tuples_len = 1,
    };
    ++(*packet_id);

    packing_status packed = pack_subscribe(&sub);
    if (packed.return_code < 0) {
        printf("Packing subscribe failed with err code %d\n", packed.return_code);
        return -1;
    }    
    ssize_t bytes_written = send(socket, (uint8_t *)packed.buf, packed.buf_len, 0);
    if (bytes_written == -1) {
        perror("Failed sending subscribe packet to broker");
        return -1;
    }
    printf("Subscribe packet sent to broker succsessfully!\n");
    return 0;
}


int send_connect_packet(int socket) {
    char *client_id = "Test Client";
    mqtt_connect conn = default_init_connect(client_id, strlen(client_id));

    packing_status status = pack_connect(&conn);
    if (status.return_code < 0) {
        printf("Packing connect failed with err code %d\n", status.return_code);
    }

    ssize_t bytes_written = send(socket, (uint8_t *)status.buf, status.buf_len, 0);
    if (bytes_written  == -1) {
        perror("Send failed!");
    }
    return 0;
}


void *process_server_messages(void *arg) {
    int socket = *(int *)arg;
    free(arg);
    int msg_number = 0;
    uint16_t packet_id = 1;
    vector subscriptions = {
        .item_size = sizeof(subscribe_tuples),
    };

    while (1) {
        mqtt_packet packet = {0};
        uint8_t *original_buffer = malloc(DEFAULT_BUFF_SIZE);
        if (!original_buffer) return NULL;
        uint8_t *buffer = original_buffer;

        int bytes_read = read(socket, buffer, DEFAULT_BUFF_SIZE);
        if (bytes_read <= 0) {
            printf("bytes read = %d\n", bytes_read);
            perror("Server communication channel closed!");
            free(original_buffer);
            return NULL;
        }
        printf("Buffer Size = %d\n", bytes_read);
        for (int i = 0; i < bytes_read; ++i) {
            printf("%02X\n", buffer[i]);
        }

        // Parse the message received from the client.
        int packet_type = unpack(&packet, &buffer, bytes_read);  // Reconstruct bytestream as mqtt_packet and store in packet
        printf("PACKET TYPE = %d\n", packet_type);
        if (msg_number == 0 && packet_type != MQTT_CONNACK) {
            perror("Unexpected MQTT packet type. First packet from server MUST be MQTT_CONNACK, dropping connection...\n");
            return NULL;
        }
        if (msg_number > 0 && packet_type == MQTT_CONNACK) {
            perror("Duplicate MQTT_CONNACK packet detected, dropping connection...\n");
            return NULL;
        }

        switch(packet_type) {
            case MQTT_CONNACK: {
                mqtt_connack connack = packet.type.connack;
                if (connack.return_code != 0) {
                    printf("Connection rejected by the broker, return code = %d\n", connack.return_code);
                    return NULL;
                }
                printf("Received CONNACK correctly, connection with broker validated.\n");
                
                // Pack and send subscribe request
                char *topic_name = "test/topic";
                subscribe_tuples subscription_inst = {
                    .topic = topic_name,
                    .qos = 1,
                    .topic_len = strlen(topic_name),
                };
                int ret = subscribe_to_topic(subscription_inst, &packet_id, socket);
                if (ret) return NULL;
                // Store the subscription instance in a list of client subscriptions
                push(&subscriptions, &subscription_inst);
                break;
            }
            case MQTT_PUBLISH: {
                break;
            }
            case MQTT_PUBACK: {
                break;
            }
            case MQTT_SUBACK: {
                mqtt_suback suback = packet.type.suback;
                for (int i = 0; i < suback.rc_len; ++i) {
                    printf("Suback%d return code = %02X\n", i, suback.return_codes[i]);
                }
                break;
            }
            case MQTT_PINGRESP: {
                break;
            }
            default:
                perror("Encountered error while parsing server message!\n");
                break;
        }
        ++msg_number;
        free(original_buffer);
    }
    return NULL;
}


void on_connect(int socket) {
    send_connect_packet(socket);

    // Start a thread listening to mqtt broker messages
    pthread_t thread_id;
    int *socket_ptr = malloc(sizeof(int));
    *socket_ptr = socket;
    if (pthread_create(&thread_id, NULL, process_server_messages, socket_ptr)) {
        perror("Failed to start thread");
    }

    pthread_join(thread_id, NULL);
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