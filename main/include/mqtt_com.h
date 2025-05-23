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
#define OK                           0
#define GENERIC_ERR                 -1
#define INCORRECT_FLAGS             -2
#define MALFORMED_PACKET            -3
#define FAILED_MEM_ALLOC            -4


int encode_remaining_length(uint8_t **buf, size_t remaining_length);
uint32_t decode_remaining_length(uint8_t **buf);

uint8_t unpack_uint8(uint8_t **buf);
uint16_t unpack_uint16(uint8_t **buf);
int unpack_str(uint8_t **buf, char **str, uint16_t len);

int unpack_subscribe(mqtt_packet *packet, uint8_t **buf);
int unpack_unsubscribe(mqtt_packet *packet, uint8_t **buf);
int unpack_publish(mqtt_packet *packet, uint8_t **buf);
int unpack_connect(mqtt_packet *packet, uint8_t **buf);
int unpack(mqtt_packet *packet, uint8_t **buf, size_t buffer_size);

void free_connect(mqtt_connect *connect_packet);
void free_publish(mqtt_connect *publish_packet);
void free_subscribe(mqtt_connect *subscribe_packet);
void free_unsubscribe(mqtt_connect *unsubscribe_packet);
void free_puback(mqtt_connect *puback_packet);
void free_disconnect(mqtt_connect *disconnect_packet);

void mqtt_send(int client, mqtt_packet *packet_type);

#endif