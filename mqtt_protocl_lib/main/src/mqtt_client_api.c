#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../include/mqtt_client_api.h"
#include "../include/mqtt_parser.h"


mqtt_callback client_callback = NULL;

void mqtt_client_register_callback(mqtt_callback callback_func) {
    client_callback = callback_func;
}

void mqtt_trigger_event(int event_type, mqtt_publish *pub_pkt) {
    if (client_callback) {
        client_callback(event_type, pub_pkt);
    }
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


int mqtt_client_handle_publish(mqtt_publish pub, vector subscription_list, int sock) {
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


int mqtt_client_subscribe_to_topic(subscribe_tuples subscription, uint16_t *packet_id, int sock) {
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


int mqtt_client_send_connect_packet(int sock, char *client_id) {
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


void publish(mqtt_publish pub, uint8_t pub_flags, int sock) {
    packing_status packed = pack_publish(&pub, pub_flags);
    if (packed.return_code < 0) {
        printf("Packing publish failed with err code %d", packed.return_code);
        return;
    }
    ssize_t bytes_written = send(sock, (uint8_t *)packed.buf, packed.buf_len, 0);
    if (bytes_written == -1) {
        perror("Send failed!");
    }
}