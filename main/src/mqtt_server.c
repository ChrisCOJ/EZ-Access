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


#define PORT                        1883
#define BACKLOG                     5
#define TIMEOUT_INTERVAL_SECONDS    20      // The client socket will timeout following this interval before a CONNECT (keep alive) packet is sent
#define TIMEOUT_INTERVAL_USECONDS   0       // Time interval in microseconds

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr sockaddr;

typedef struct { 
    char *client_id;
    int client_socket;
    vector subscriptions;    // list of subscriptions
    int *unaknowledged_message_ids;
    bool clean_session;
    int return_code;
} session_state;

typedef struct {
    char *name;
    vector associated_clients;
} subscription_instance;

/****************************************************************************************************************************/

static volatile sig_atomic_t keep_running = 1;
static volatile vector session_list = {.item_size = sizeof(session_state)};
static volatile vector subscription_list = {.item_size = sizeof(subscription_instance)};


void handle_sigint() {
    keep_running = 0;
}


bool is_client_subscribed(char *client_id, subscription_instance subscription) {
    for (int n = 0; n < subscription.associated_clients.size; ++n) {
        char *client_n_id = (char *)subscription.associated_clients.data + n;
        if (client_n_id == client_id) {
            return true;
        }
    }
    return false;
}


void match_topic(subscribe_tuples topic_filter, session_state *current_client_session) {
    int i = 0;
    bool matched_subscription = false;
    do {
        subscription_instance *existing_subscription = (subscription_instance *)subscription_list.data + i;
        // If topic exists and client is subscribed already, replace subscription
        if (!strcmp(topic_filter.topic, existing_subscription->name) && 
            is_client_subscribed(current_client_session->client_id, *existing_subscription)) {
            matched_subscription = true;
            for (int j = 0; j < current_client_session->subscriptions.size; ++j) {
                subscribe_tuples *client_sub = (subscribe_tuples *)current_client_session->subscriptions.data + j;
                if (strcmp(client_sub->topic, topic_filter.topic)) {
                    *client_sub = topic_filter;
                }
            }
        }
        // If topic_filter matches and the client is not already subscribed, subscribe the client to the topic
        else if (!strcmp(topic_filter.topic, existing_subscription->name) && 
                 !is_client_subscribed(current_client_session->client_id, *existing_subscription)) {
            matched_subscription = true;
            // Add client name to the appropriate subscription inside the global subscription list
            push(&existing_subscription->associated_clients, &current_client_session->client_id);
            // Add subscription to the client's session subscription list
            push(&current_client_session->subscriptions, &topic_filter);
        }
        ++i;
    } while (i < subscription_list.size);

    if (!matched_subscription) {
        // If topic doesn't already exist, add it and subscribe the client
        subscription_instance subscription_inst = {
            .name = topic_filter.topic,
            .associated_clients.item_size = sizeof(char *),
        };
        push(&subscription_inst, &current_client_session->client_id);
        push(&subscription_list, &subscription_inst);

        current_client_session->subscriptions.item_size = sizeof(subscribe_tuples);
        push(&current_client_session->subscriptions, &topic_filter);
    }
}


void mqtt_handle_subscribe(mqtt_subscribe sub, int socket, session_state *current_client_session) {
    // Compare topic filters against existing topics.
    for (int i = 0; i < sub.tuples_len; ++i) {
        match_topic(sub.tuples[i], current_client_session);
        // Pack and send suback
        mqtt_suback suback = {
            .pkt_id = sub.pkt_id,
            .return_code = sub.tuples[i].qos,
        };
        packing_status packed = pack_suback(suback);
        if (packed.return_code < 0) {
            printf("Packing suback failed with err code %d", packed.return_code);
        }
        ssize_t bytes_written = send(socket, (uint8_t *)packed.buf, packed.buf_len, 0);
        if (bytes_written  == -1) {
            perror("Send failed!");
        }
    }

}


session_state mqtt_handle_connect(int client_socket, mqtt_connect connect) {
    /* Store session state for the current client */
    // Dynamic array of client subscriptions
    vector topic_list = {
        .item_size = sizeof(subscribe_tuples),
    };
    session_state client_session = {
        .client_socket = client_socket,
        .clean_session = (connect.connect_flags & CLEAN_SESSION_FLAG) == CLEAN_SESSION_FLAG,
        .subscriptions = &topic_list,
        .unaknowledged_message_ids = NULL,
        .return_code = 0,
    };
    client_session.client_id = malloc(strlen(connect.payload.client_id));
    if (!client_session.client_id) {
        perror("Failed client ID malloc when trying to update session state!");
        client_session.return_code = -1;
        return client_session;
    }
    strcpy(client_session.client_id, connect.payload.client_id);
    push(session_list.data, &client_session);

    /* Pack and send connack */
    mqtt_connack connack = {
        .session_present_flag = 0,
        .return_code = 0,
    };
    // Return code
    if (connect.protocol_level != 4) connack.return_code = CONNACK_UNACCEPTABLE_PROTOCOL_VERSION; 
    // If ID is taken, set return code to CONNACK_ID_REJECTED

    packing_status packed = pack_connack(connack);
    if (packed.return_code < 0) {
        printf("Packing connack failed with err code %d", packed.return_code);
        client_session.return_code = -1;
        return client_session;
    }

    ssize_t bytes_written = send(client_socket, (uint8_t *)packed.buf, packed.buf_len, 0);
    if (bytes_written  == -1) {
        perror("Send failed!");
        client_session.return_code = -1;
        return client_session;
    }
    return client_session;
}


void *process_client_messages(void *arg) {
    // client_socket is an integer file descriptor that represents a specific client/server socket connection.
    int client_socket = *(int *)arg;
    session_state client_session = {0};

    // Set an initial appropriate client timeout before the keep alive parameter is set via the CONNECT packet
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_INTERVAL_SECONDS;
    timeout.tv_usec = TIMEOUT_INTERVAL_USECONDS;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    unsigned msg_number = 0;
    bool connection_alive = true;

    while (connection_alive) {
        mqtt_packet packet = {0};
        uint8_t *original_buffer = malloc(DEFAULT_BUFF_SIZE);
        if (!original_buffer) exit(EXIT_FAILURE);
        uint8_t *buffer = original_buffer;
        
        int read_size = read(client_socket, buffer, DEFAULT_BUFF_SIZE);  // The size in bytes of the message read from the client socket
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
                    mqtt_connect con = packet.type.connect;
                    timeout.tv_sec = con.keep_alive;
                    timeout.tv_usec = TIMEOUT_INTERVAL_USECONDS;
                    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                    printf("Client ID = %s\n", con.payload.client_id);

                    client_session = mqtt_handle_connect(client_socket, con);
                    if (client_session.return_code < 0) {
                        return NULL;  // Terminate client connection
                    }
                    break;
                }
                case MQTT_PUBLISH:
                    break;
                case MQTT_PUBACK:
                    break;
                case MQTT_SUBSCRIBE:
                    mqtt_subscribe sub = packet.type.subscribe;
                    mqtt_handle_subscribe(sub, client_socket, &client_session);
                    break;
                case MQTT_UNSUBSCRIBE:
                    break;
                case MQTT_PINGREQ: 
                    break;
                case MQTT_DISCONNECT:
                    break;
                
                default:
                    perror("Encountered error while parsing client message!\n");
                    break;
            }
            ++msg_number;
        }
        else {
            connection_alive = false;
            printf("Client connection terminated!\n");
        }
        free(original_buffer);
    }   
    return NULL;
};


int main() {
    vector threads = {
        .capacity = 10,  // Assign some initial capacity for client connections
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

    printf("Cleanup!\n");
    // Cleanup
    for (size_t i=0; i < threads.size; ++i) {
        pthread_join(((pthread_t *)threads.data)[i], NULL);
    }
    free_vec(&threads);
    close(server_socket);
    return 0;
} 
