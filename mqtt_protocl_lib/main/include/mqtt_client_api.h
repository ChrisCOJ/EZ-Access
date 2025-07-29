#ifndef MQTT_CLIENT_API_H
#define MQTT_CLIENT_API_H

#include "mqtt_protocol.h"
#include "mqtt_util.h"

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

typedef void (*mqtt_callback)(int event_type, mqtt_publish *pub_pkt);

extern mqtt_callback client_callback;
void mqtt_client_register_callback(mqtt_callback callback_func);
void mqtt_trigger_event(int event_type, mqtt_publish *pub_pkt);

app_subscription_entry match_topic(char *topic_filter, vector subscription_list);
int mqtt_client_handle_publish(mqtt_publish pub, vector subscription_list, int sock);
int mqtt_client_subscribe_to_topic(subscribe_tuples subscription, uint16_t *packet_id, int sock);
int mqtt_client_send_connect_packet(int sock);
void publish(mqtt_publish pub, uint8_t pub_flags, int sock);

#endif