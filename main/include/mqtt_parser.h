#ifndef mqtt_parser_h
#define mqtt_parser_h

#include "mqtt_protocol.h"

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

// Error return codes for parser
enum return_codes {
    OK                      =  0,
    GENERIC_ERR             = -1,
    INCORRECT_FLAGS         = -2,
    MALFORMED_PACKET        = -3,
    FAILED_MEM_ALLOC        = -4,
    INVALID_PACKET_TYPE     = -5,
};


int encode_remaining_length(uint8_t *buf, size_t remaining_length);
uint32_t decode_remaining_length(uint8_t **buf);

uint8_t unpack_uint8(uint8_t **buf);
uint16_t unpack_uint16(uint8_t **buf);
int unpack_str(uint8_t **buf, char **str, uint16_t len);

int unpack_subscribe(mqtt_packet *packet, uint8_t **buf);
int unpack_unsubscribe(mqtt_packet *packet, uint8_t **buf);
int unpack_publish(mqtt_packet *packet, uint8_t **buf);
int unpack_connect(mqtt_connect *conn, uint8_t **buf);
int unpack(mqtt_packet *packet, uint8_t **buf, size_t buffer_size);

int pack8(uint8_t **buf, size_t *len, uint8_t item);
int pack16(uint8_t **buf, size_t *len, uint16_t item);
int pack32(uint8_t **buf, size_t *len, uint32_t item);
int pack_str(uint8_t **buf, size_t *len, char *str, uint16_t str_len);

void free_connect(mqtt_connect *connect_packet);
void free_publish(mqtt_connect *publish_packet);
void free_subscribe(mqtt_connect *subscribe_packet);
void free_unsubscribe(mqtt_connect *unsubscribe_packet);
void free_puback(mqtt_connect *puback_packet);
void free_disconnect(mqtt_connect *disconnect_packet);

void mqtt_send(int client, mqtt_packet *packet_type);

#endif