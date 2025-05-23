#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "../include/mqtt_com.h"


uint32_t decode_remaining_length(uint8_t **buf) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint8_t encoded_byte;

    do {
        encoded_byte = **buf;
        (*buf)++;
        value += (encoded_byte & 127) * multiplier;
        multiplier *= 128;
        if (multiplier > (128 * 128 * 128)) {
            // Malformed Remaining Length (greater than 4 bytes)
            return 0xFFFFFFFF; // error
        }
    } while ((encoded_byte & 128) != 0);

    return value;
}


int encode_remaining_length(uint8_t *buf, size_t remaining_length) {
    int bytes_written = 0;

    do {
        uint8_t encoded_byte = remaining_length % 128;
        remaining_length /= 128;

        // If there are more digits to encode, set the top bit of this digit
        if (remaining_length > 0) {
            encoded_byte |= 128;
        }

        buf[bytes_written++] = encoded_byte;
    } while (remaining_length > 0 && bytes_written < 4);

    return bytes_written;
}



uint8_t unpack_uint8(uint8_t **buf) {
    uint8_t value = **buf;
    (*buf)++;
    return value;
}


uint16_t unpack_uint16(uint8_t **buf) {
    uint16_t value;
    memcpy(&value, *buf, sizeof(uint16_t));
    (*buf) += sizeof(uint16_t);
    return ntohs(value);
}


int unpack_str(uint8_t **buf, char **str, uint16_t len) {
    *str = malloc(len + 1);
    if (!*str) return -1;
    memcpy(*str, *buf, len);
    (*str)[len] = '\0';
    *buf += len;
    return 0;
}


int unpack_connect(mqtt_packet *packet, uint8_t **buf) {
    // Protocol name length
    packet->type.connect.protocol_name.len = unpack_uint16(buf);
    // Protocol name
    int err = unpack_str(buf, &packet->type.connect.protocol_name.name, 
                packet->type.connect.protocol_name.len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    // Protocol level
    packet->type.connect.protocol_level = unpack_uint8(buf);
    // Connect flags
    packet->type.connect.connect_flags = unpack_uint8(buf);
    // Keep alive
    packet->type.connect.keep_alive = unpack_uint16(buf);
    // Client ID
    packet->type.connect.payload.client_id_len = unpack_uint16(buf);
    int err = unpack_str(buf, &packet->type.connect.payload.client_id, 
                packet->type.connect.payload.client_id_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    // Will
    if ((packet->type.connect.connect_flags & WILL_FLAG) == WILL_FLAG) {
        packet->type.connect.payload.will_topic_len = unpack_uint16(buf);
        if (packet->type.connect.payload.will_topic_len) {
            int err = unpack_str(buf, &packet->type.connect.payload.will_topic, 
                        packet->type.connect.payload.will_topic_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
        packet->type.connect.payload.will_message_len = unpack_uint16(buf);
        if (packet->type.connect.payload.will_message_len) {
            int err = unpack_str(buf, &packet->type.connect.payload.will_message, 
                        packet->type.connect.payload.will_message_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
    }
    // Username
    if (((packet->type.connect.connect_flags & USERNAME_FLAG) == USERNAME_FLAG)) {
        packet->type.connect.payload.username_len = unpack_uint16(buf);
        if (packet->type.connect.payload.username_len) {
            int err = unpack_str(buf, &packet->type.connect.payload.username, 
                        packet->type.connect.payload.username_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
    }
    // Password
    if (((packet->type.connect.connect_flags & PASSWORD_FLAG) == PASSWORD_FLAG)) {
        packet->type.connect.payload.password_len = unpack_uint16(buf);
        if (packet->type.connect.payload.password_len) {
            int err = unpack_str(buf, &packet->type.connect.payload.password, 
                        packet->type.connect.payload.password_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
    }
    return MQTT_CONNECT;
}


int unpack_publish(mqtt_packet *packet, uint8_t **buf) {
    uint32_t variable_header_len = 0;
    // Topic
    packet->type.publish.topic_len = unpack_uint16(buf);
    variable_header_len += sizeof(uint16_t);
    int err = unpack_str(buf, &packet->type.publish.topic, packet->type.publish.topic_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    variable_header_len += packet->type.publish.topic_len;
    // Packet ID
    if ((packet->header.fixed_header.flags & QOS_FLAG_MASK) != QOS_AMO_FLAG) {
        packet->type.publish.pkt_id = unpack_uint16(buf);
        variable_header_len += sizeof(uint16_t);
    }
    // Payload
    packet->type.publish.payload_len = packet->header.remaining_length - variable_header_len;
    int err = unpack_str(buf, &packet->type.publish.payload, packet->type.publish.payload_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }

    return MQTT_PUBLISH;
}


int unpack_subscribe(mqtt_packet *packet, uint8_t **buf) {
    uint32_t remaining_len = packet->header.remaining_length;
    if (packet->header.fixed_header.flags != SUBSCRIBE_FLAGS) {
        return INCORRECT_FLAGS;
    }
    // Packet ID
    if (remaining_len >= sizeof(uint16_t)) {
        packet->type.subscribe.pkt_id = unpack_uint16(buf);
        remaining_len -= sizeof(uint16_t);
    }
    int i = 0;
    // Payload
    while (remaining_len > 0) {
        if (remaining_len < sizeof(uint16_t)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= (sizeof(uint16_t));
        void *tmp = realloc(packet->type.subscribe.tuples, (i + 1) * sizeof(*packet->type.subscribe.tuples));
        if (!tmp) return GENERIC_ERR;
        packet->type.subscribe.tuples = tmp;
        packet->type.subscribe.tuples[i].topic_len = unpack_uint16(buf);

        if ((remaining_len < packet->type.subscribe.tuples[i].topic_len) || (packet->type.subscribe.tuples[i].topic_len == 0)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= packet->type.subscribe.tuples[i].topic_len;
        int err = unpack_str(buf, &packet->type.subscribe.tuples[i].topic, packet->type.subscribe.tuples[i].topic_len);
        if (err) {
            return FAILED_MEM_ALLOC;
        }

        if (remaining_len < sizeof(uint8_t)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= sizeof(uint8_t);
        packet->type.subscribe.tuples[i].qos = unpack_uint8(buf);
        i++;
    }
    packet->type.subscribe.tuples_len = i;
    return MQTT_SUBSCRIBE;
}


int unpack_unsubscribe(mqtt_packet *packet, uint8_t **buf) {
    uint32_t remaining_len = packet->header.remaining_length;
    if (packet->header.fixed_header.flags != SUBSCRIBE_FLAGS) {
        return INCORRECT_FLAGS;
    }
    // Packet ID
    if (remaining_len >= sizeof(uint16_t)) {
        packet->type.unsubscribe.pkt_id = unpack_uint16(buf);
        remaining_len -= sizeof(uint16_t);
    }
    int i = 0;
    // Payload
    while (remaining_len > 0) {
        if (remaining_len < sizeof(uint16_t)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= (sizeof(uint16_t));
        void *tmp = realloc(packet->type.unsubscribe.tuples, (i + 1) * sizeof(*packet->type.unsubscribe.tuples));
        if (!tmp) return GENERIC_ERR;
        packet->type.unsubscribe.tuples = tmp;
        packet->type.unsubscribe.tuples[i].topic_len = unpack_uint16(buf);

        if ((remaining_len < packet->type.unsubscribe.tuples[i].topic_len) || (packet->type.unsubscribe.tuples[i].topic_len == 0)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= packet->type.unsubscribe.tuples[i].topic_len;
        int err = unpack_str(buf, &packet->type.unsubscribe.tuples[i].topic, packet->type.unsubscribe.tuples[i].topic_len);
        if (err) {
            return FAILED_MEM_ALLOC;
        }
    }
    packet->type.unsubscribe.tuples_len = i;
    return MQTT_UNSUBSCRIBE;
}


int unpack(mqtt_packet *packet, uint8_t **buf, size_t buf_size){
    // Extract the fixed header
    uint8_t packet_type = **buf & TYPE_MASK;
    uint8_t packet_flags = **buf & FLAG_MASK;
    (*buf)++;
    uint32_t remaining_length = decode_remaining_length(&buf);
    packet->header.fixed_header.type = packet_type;
    packet->header.fixed_header.flags = packet_flags;
    packet->header.remaining_length = remaining_length;

    switch (packet_type) {
        case CONNECT_TYPE: {
            return unpack_connect(packet, buf);
        }

        case PUBLISH_TYPE: {
            return unpack_publish(packet, buf);
        }

        case PUBACK_TYPE: {
            if (packet->header.remaining_length >= 2) {
                packet->type.puback.pkt_id = unpack_uint16(buf);
            }
            return MQTT_PUBACK;
        }

        case SUBSCRIBE_TYPE: {
            return unpack_subscribe(packet, buf);
        }

        case UNSUBSCRIBE_TYPE: {
            return unpack_unsubscribe(packet, buf);
        }

        case DISCONNECT_TYPE: {
            if (packet->header.fixed_header.flags != DISCONNECT_FLAGS) {
                return MALFORMED_PACKET;
            }
            return MQTT_DISCONNECT;
        }
    }
    return GENERIC_ERR;
}