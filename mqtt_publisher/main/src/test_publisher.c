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
#include "../include/mqtt_client_api.h"

#define SERVER_IP                   "127.0.0.1"
#define SERVER_PORT                 1883


void turn_led_on(void *context) {
    printf("on");
}

void turn_led_off(void *context) {
    printf("off");
}


void process_server_messages(int sock, vector *subscriptions) {
    int msg_number = 0;
    uint16_t packet_id = 1;     // Packet ID 0 is not allowed

    while (1) {
        mqtt_packet packet = {0};
        uint8_t *original_buffer = malloc(DEFAULT_BUFF_SIZE);
        if (!original_buffer) return;
        uint8_t *buffer = original_buffer;

        int bytes_read = read(sock, buffer, DEFAULT_BUFF_SIZE);
        if (bytes_read <= 0) {
            printf("bytes read = %d\n", bytes_read);
            perror("Server communication channel closed!");
            free(original_buffer);
            return;
        }
        printf("Buffer Size = %d\n", bytes_read);
        for (int i = 0; i < bytes_read; ++i) {
            printf("%02X\n", buffer[i]);
        }

        // Parse the message received from the client.
        int packet_type = unpack(&packet, &buffer, bytes_read);  // Reconstruct bytestream as mqtt_packet and store in packet
        if (msg_number == 0 && packet_type != MQTT_CONNACK) {
            perror("Unexpected MQTT packet type. First packet from server MUST be MQTT_CONNACK, dropping connection...\n");
            return;
        }
        if (msg_number > 0 && packet_type == MQTT_CONNACK) {
            perror("Duplicate MQTT_CONNACK packet detected, dropping connection...\n");
            return;
        }

        switch(packet_type) {
            case MQTT_CONNACK: {
                mqtt_connack connack = packet.type.connack;
                if (connack.return_code != 0) {
                    printf("Connection rejected by the broker, return code = %d\n", connack.return_code);
                    return;
                }
                printf("Received CONNACK correctly, connection with broker validated.\n");
                
                // Pack and send publish
                char *topic_name = "home/chris/smart_led";
                char *command = "on";
                mqtt_publish pub = {
                    .pkt_id = packet_id,
                    .topic = topic_name,
                    .topic_len = strlen(topic_name),
                    .payload = command,
                    .payload_len = strlen(command),
                };
                ++packet_id;
                publish(pub, PUBLISH_QOS_1, sock);
                break;
            }
            case MQTT_PUBLISH: {
                mqtt_publish pub = packet.type.publish;
                int err = mqtt_client_handle_publish(pub, *subscriptions, sock);
                if (err) return;
                break;
            }
            case MQTT_PUBACK: {
                mqtt_puback puback = packet.type.puback;
                printf("Puback packet ID: %d", puback.pkt_id);
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
}


int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    vector subscriptions = {
        .item_size = sizeof(app_subscription_entry),
    };

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

    mqtt_client_send_connect_packet(sock, "Publisher");
    process_server_messages(sock, &subscriptions);
}