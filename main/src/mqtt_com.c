#include "../include/mqtt_com.h"


uint32_t decode_remaining_length(uint8_t **buf) {
    uint32_t remaining_length;  // in bytes
    // ...

    return remaining_length;
}

int encode_remaining_length(const uint8_t *buf, size_t remaining_len) {
    int bytes = 0;
    // ...

    return bytes;
}


uint8_t unpack_uint8(const uint8_t **buf) {
    uint8_t value = **buf;
    (*buf)++;
    return value;
}


uint16_t unpack_uint16(const uint8_t **buf) {
    uint16_t value;
    memcpy(&value, *buf, sizeof(uint16_t));
    (*buf) += sizeof(uint16_t);
    return ntohs(value);
}


void unpack_str(const uint8_t **buf, char **str, uint16_t len) {
    *str = malloc(len + 1);
    memcpy(*str, *buf, len);
    (*str)[len] = '\0';
    *buf += len;
}


int unpack(mqtt_packet *packet, char *buffer, size_t buffer_size){
    // Extract the fixed header
    uint8_t packet_type = buffer[0] & 0xF0;
    uint32_t remaining_length = decode_variable_length(&remaining_length, buffer);
    mqtt_header header = {
        .fixed_header = packet_type,
        .remaining_length = remaining_length
    };
    packet->header = header;

    switch (packet_type) {
        case CONNECT_TYPE:
            /* VARIABLE HEADER */
            // Protocol name length
            packet->type.connect.protocol_name.len = unpack_uint16((const uint8_t **)&buffer);
            // Protocol name
            unpack_str(&buffer, &packet->type.connect.protocol_name.name, packet->type.connect.protocol_name.len);
            // Protocol level
            packet->type.connect.protocol_level = unpack_uint8((const uint8_t **)&buffer);
            // Connect flags
            packet->type.connect.connect_flags = unpack_uint8((const uint8_t **)&buffer);
            // Keep alive
            packet->type.connect.keep_alive = unpack_uint16((const uint8_t **)&buffer);
            /* PAYLAOD */
            // Client ID
            packet->type.connect.payload.client_id_len = unpack_uint16((const uint8_t **)&buffer);
            unpack_str(&buffer, &packet->type.connect.payload.client_id, packet->type.connect.payload.client_id_len);
            // Will topic

            return CONNECT_TYPE;

        case PUBLISH_TYPE:
            /* FIXED HEADER */
            uint8_t publish_flags = buffer[0] & 0x0F;
            packet->header.fixed_header |= publish_flags;

            /* VAIABLE HEADER */

            return PUBLISH_TYPE;
        }
}