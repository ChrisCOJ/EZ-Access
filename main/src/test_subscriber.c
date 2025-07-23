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
#define MAX_COMMAND_NUM             10          // App enforces a maximum number of 10 possible commands for each subscription


typedef struct {
    char *command_name;
    void (*callback)(void *);
} command_table;

typedef struct {
    subscribe_tuples sub_properties;
    command_table commands[MAX_COMMAND_NUM];
    size_t command_count;
} app_subscription_entry;


void turn_led_on(void *context) {
    printf("on\n");
}

void turn_led_off(void *context) {
    printf("off\n");
}


app_subscription_entry match_topic(char *topic_filter, vector subscription_list) {
    for (int i = 0; i < subscription_list.size; ++i) {
        app_subscription_entry *sub_entry = (app_subscription_entry *)subscription_list.data + i;
        if (!strcmp(sub_entry->sub_properties.topic, topic_filter)) {
            return *sub_entry;
        }
    }
    // Return empty struct on failure
    app_subscription_entry fail_ret = {0};
    return fail_ret;
}


int handle_publish(mqtt_publish pub, vector subscription_list, int sock) {
    app_subscription_entry ret_sub_entry = match_topic(pub.topic, subscription_list);
    if (ret_sub_entry.sub_properties.topic == NULL) {   // If empty (topic must have a value)
        perror("Topic name attempting to publish to doesn't exist!");
        return -1;
    }
    // Match payload to allowed commands for the particular subscription
    for (int i = 0; i < ret_sub_entry.command_count; ++i) {
        if (!strcmp(pub.payload, ret_sub_entry.commands[i].command_name)) {
            ret_sub_entry.commands[i].callback(NULL);   // Invoke callback if command is validated
        }
    }

    // Pack and send puback to broker
    mqtt_puback puback = {
        .pkt_id = pub.pkt_id,
    };
    packing_status packed = pack_puback(puback);
    if (packed.return_code < 0) {
        printf("Packing puback failed with err code %d", packed.return_code);
        return -1;
    }
    ssize_t bytes_written = send(sock, (uint8_t *)packed.buf, packed.buf_len, 0);
    if (bytes_written == -1) {
        perror("Send failed!");
        return -1;
    }
    return 0;
}


int subscribe_to_topic(subscribe_tuples subscription, uint16_t *packet_id, int sock) {
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
    ssize_t bytes_written = send(sock, (uint8_t *)packed.buf, packed.buf_len, 0);
    if (bytes_written == -1) {
        perror("Failed sending subscribe packet to broker");
        return -1;
    }
    printf("Subscribe packet sent to broker succsessfully!\n");
    return 0;
}


int send_connect_packet(int sock) {
    char *client_id = "Subscriber";
    mqtt_connect conn = default_init_connect(client_id, strlen(client_id));

    packing_status status = pack_connect(&conn);
    if (status.return_code < 0) {
        printf("Packing connect failed with err code %d\n", status.return_code);
    }

    ssize_t bytes_written = send(sock, (uint8_t *)status.buf, status.buf_len, 0);
    if (bytes_written  == -1) {
        perror("Send failed!");
    }
    return 0;
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
                
                // Pack and send subscribe request
                char *topic_name = "home/chris/smart_led";
                subscribe_tuples sub_properties = {
                    .topic = topic_name,
                    .qos = 1,
                    .topic_len = strlen(topic_name),
                };
                // Store app actions associated with the subscription
                app_subscription_entry sub_entry = {
                    .sub_properties = sub_properties,
                    .commands = {
                        { .command_name = "on", .callback = turn_led_on },
                        { .command_name = "off", .callback = turn_led_off },
                    },
                    .command_count = 2,
                };
                int ret = subscribe_to_topic(sub_properties, &packet_id, sock);
                if (ret) return;
                push(subscriptions, &sub_entry);
                break;
            }
            case MQTT_PUBLISH: {
                mqtt_publish pub = packet.type.publish;
                int err = handle_publish(pub, *subscriptions, sock);
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
    return;
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

    send_connect_packet(sock);
    process_server_messages(sock, &subscriptions);
}