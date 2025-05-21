#ifndef mqtt_com_h
#define mqtt_com_h

#include "mqtt_control.h"

// Packet types
enum packet_type {    
    MQTT_CONNECT     = 1,
    MQTT_CONNACK     = 2,
    MQTT_PUBLISH     = 3,
    MQTT_PUBACK      = 4,
    MQTT_PUBREC      = 5,
    MQTT_PUBREL      = 6,
    MQTT_PUBCOMP     = 7,
    MQTT_SUBSCRIBE   = 8,
    MQTT_SUBACK      = 9,
    MQTT_UNSUBSCRIBE = 10,
    MQTT_UNSUBACK    = 11,
    MQTT_PINGREQ     = 12,
    MQTT_PINGRESP    = 13,
    MQTT_DISCONNECT  = 14,
};
// Error numbers
#define GENERIC_ERR     -1

uint8_t unpack_uint8(const uint8_t **buf);
uint16_t unpack_uint16(const uint8_t **buf);
void unpack_str(const uint8_t **buf, char **str, uint16_t len);
int unpack(mqtt_packet *packet, char *buffer, size_t buffer_size);

int encode_remaining_length(const uint8_t *buf, size_t remaining_length);
uint32_t decode_remaining_length(uint8_t *buf, uint8_t offset);

void mqtt_send(int client, mqtt_packet *packet_type);

void free_connect(mqtt_connect *connect_packet);
void free_publish(mqtt_connect *publish_packet);
void free_subscribe(mqtt_connect *subscribe_packet);
void free_unsubscribe(mqtt_connect *unsubscribe_packet);
void free_puback(mqtt_connect *puback_packet);
void free_disconnect(mqtt_connect *disconnect_packet);


#endif