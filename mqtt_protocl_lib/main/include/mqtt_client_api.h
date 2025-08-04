#ifndef MQTT_CLIENT_API_H
#define MQTT_CLIENT_API_H

#include "mqtt_protocol.h"
#include "mqtt_util.h"

#define MAX_COMMAND_NUM             10          /**< Maximum number of commands per subscription */

/**
 * @brief Command entry mapping a command name to its callback.
 */
typedef struct {
    char *command_name;             /**< Name of the command */
    void (*callback)(void *);       /**< Callback function for the command */
} command_table;

/**
 * @brief Represents a subscription entry with associated commands.
 */
typedef struct {
    subscribe_tuples sub_properties;          /**< Properties of the subscription (topic, QoS, etc.) */
    command_table commands[MAX_COMMAND_NUM];  /**< List of commands associated with this subscription */
    size_t command_count;                     /**< Number of commands currently registered */
} app_subscription_entry;

/**
 * @brief Application-level callback type for MQTT events.
 *
 * @param event_type  Integer representing the type of event triggered.
 * @param pub_pkt     Pointer to the published MQTT packet data.
 */
typedef void (*mqtt_callback)(int event_type, mqtt_publish *pub_pkt);

/**
 * @brief Global callback pointer used by the client to handle events.
 */
extern mqtt_callback client_callback;

/**
 * @brief Registers a callback function for MQTT client events.
 *
 * @param callback_func  Pointer to the function to register as the callback.
 */
void mqtt_client_register_callback(mqtt_callback callback_func);

/**
 * @brief Triggers a registered client callback for a given event.
 *
 * @param event_type  Integer representing the event type.
 * @param pub_pkt     Pointer to the MQTT publish packet associated with the event.
 */
void mqtt_trigger_event(int event_type, mqtt_publish *pub_pkt);

/**
 * @brief Matches a topic filter against the client's subscription list.
 *
 * @param topic_filter      Topic string to match against subscriptions.
 * @param subscription_list Vector of app_subscription_entry elements.
 *
 * @return The matching app_subscription_entry if found, otherwise an entry with no match.
 */
app_subscription_entry match_topic(char *topic_filter, vector subscription_list);

/**
 * @brief Handles an incoming MQTT PUBLISH packet and routes it to matching subscriptions.
 *
 * @param pub                The MQTT publish packet received.
 * @param subscription_list  Vector of app_subscription_entry elements to check against.
 * @param sock               Socket descriptor used for acknowledgment (if required).
 *
 * @return 0 on success, negative value on error.
 */
int mqtt_client_handle_publish(mqtt_publish pub, vector subscription_list, int sock);

/**
 * @brief Subscribes to a topic using the given subscription tuple.
 *
 * @param subscription  Subscription properties (topic, QoS).
 * @param packet_id     Pointer to store the generated packet ID for the SUBSCRIBE request.
 * @param sock          Socket descriptor to send the packet through.
 *
 * @return 0 on success, negative value on error.
 */
int mqtt_client_subscribe_to_topic(subscribe_tuples subscription, uint16_t *packet_id, int sock);

/**
 * @brief Sends an MQTT CONNECT packet to the broker.
 *
 * @param sock       Socket descriptor to send the CONNECT packet through.
 * @param client_id  Unique client identifier string.
 *
 * @return 0 on success, negative value on error.
 */
int mqtt_client_send_connect_packet(int sock, char *client_id);

/**
 * @brief Publishes a message to the broker on the specified topic.
 *
 * @param pub        MQTT publish packet to send.
 * @param pub_flags  Flags indicating QoS, retain, and duplicate states.
 * @param sock       Socket descriptor to send the packet through.
 */
void publish(mqtt_publish pub, uint8_t pub_flags, int sock);

#endif
