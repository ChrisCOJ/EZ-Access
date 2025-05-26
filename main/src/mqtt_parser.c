#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "../include/mqtt_parser.h"

#define CHECK(x, err) do { if ((x)) return (err); } while (0)


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


int encode_remaining_length(size_t remaining_length, uint8_t *remaining_len_bytes) {
    size_t remaining_len_size = 0;

    do {
        uint8_t encoded_byte = remaining_length % 128;
        remaining_length /= 128;
        // If there are more digits to encode, set the top bit of this digitz
        if (remaining_length > 0) {
            encoded_byte |= 128;
        }
        remaining_len_bytes[remaining_len_size++] = encoded_byte;
    } while (remaining_length > 0 && remaining_len_size < 4);

    return remaining_len_size;
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


int unpack_connect(mqtt_connect *conn, uint8_t **buf) {
    // Protocol name length
    conn->protocol_name.len = unpack_uint16(buf);
    // Protocol name
    int err = unpack_str(buf, &conn->protocol_name.name, conn->protocol_name.len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    // Protocol level
    conn->protocol_level = unpack_uint8(buf);
    // Connect flags
    conn->connect_flags = unpack_uint8(buf);
    // Keep alive
    conn->keep_alive = unpack_uint16(buf);
    // Client ID
    conn->payload.client_id_len = unpack_uint16(buf);
    int err = unpack_str(buf, &conn->payload.client_id, conn->payload.client_id_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    // Will
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {
        conn->payload.will_topic_len = unpack_uint16(buf);
        if (conn->payload.will_topic_len) {
            int err = unpack_str(buf, &conn->payload.will_topic, conn->payload.will_topic_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
        conn->payload.will_message_len = unpack_uint16(buf);
        if (conn->payload.will_message_len) {
            int err = unpack_str(buf, &conn->payload.will_message, conn->payload.will_message_len);
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
    if ((packet->header.fixed_header & QOS_FLAG_MASK) != QOS_AMO_FLAG) {
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
    if ((packet->header.fixed_header & FLAG_MASK) != SUBSCRIBE_FLAGS) {
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
    if ((packet->header.fixed_header & FLAG_MASK) != SUBSCRIBE_FLAGS) {
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
    (*buf)++;
    uint32_t remaining_length = decode_remaining_length(buf);
    packet->header.fixed_header = **buf;
    packet->header.remaining_length = remaining_length;

    switch (packet_type) {
        case CONNECT_TYPE: {
            mqtt_connect *conn = &(packet->type.connect);
            return unpack_connect(conn, buf);
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
            if ((packet->header.fixed_header & FLAG_MASK) != DISCONNECT_FLAGS) {
                return MALFORMED_PACKET;
            }
            return MQTT_DISCONNECT;
        }
    }
    return GENERIC_ERR;
}


int pack8(uint8_t **buf, size_t *len, uint8_t item) {
    uint8_t *tmp = realloc(*buf, *len + sizeof(uint8_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    (*buf)[*len] = item;
    (*len) += sizeof(uint8_t);
    return 0;
}

int pack16(uint8_t **buf, size_t *len, uint16_t item) {
    uint16_t *tmp = realloc(*buf, *len + sizeof(uint16_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    uint16_t network_item = htons(item);  // Convert to network byte order
    memcpy(*buf + *len, &network_item, sizeof(uint16_t));
    (*len) += sizeof(uint16_t);
    return 0;
}

int pack32(uint8_t **buf, size_t *len, uint32_t item) {
    uint32_t *tmp = realloc(*buf, *len + sizeof(uint32_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    uint32_t network_item = htonl(item);  // Convert to network byte order
    memcpy(*buf + *len, &network_item, sizeof(uint32_t));
    (*len) += sizeof(uint32_t);
    return 0;
}

int pack_str(uint8_t **buf, size_t *len, char *str, uint16_t str_len) {
    char *tmp = realloc(*buf, *len + str_len);
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    memcpy(*buf + *len, str, str_len);
    (*len) += str_len;
    return 0;
}


int pack_connect(mqtt_header header, mqtt_connect *conn, uint8_t **buf) {
    size_t len = 0;
    size_t remaining_len = 0;
    /* --- Sanity Checks --- */
    CHECK(!conn->protocol_name.len, MALFORMED_PACKET);
    CHECK(!conn->protocol_name.name, MALFORMED_PACKET);
    CHECK(!conn->protocol_level, MALFORMED_PACKET);
    CHECK(!conn->connect_flags, MALFORMED_PACKET);
    CHECK(!conn->keep_alive, MALFORMED_PACKET);
    CHECK(!conn->payload.client_id_len, MALFORMED_PACKET);
    CHECK(!conn->payload.client_id, MALFORMED_PACKET);

    /* --- Allocate buffer size --- */
    *buf = malloc(1024);
    CHECK(!(*buf), FAILED_MEM_ALLOC);
    // Reserve space for the fixed header
    uint8_t *buf_start = *buf;
    uint8_t *payload_buf = *buf + 5;

    /* --- PACK --- */
    /* Variable Header */
    // Pack protocol name
    CHECK(pack16(payload_buf, &len, conn->protocol_name.len), FAILED_MEM_ALLOC);
    CHECK(pack_str(payload_buf, &len, conn->protocol_name.name, 
        conn->protocol_name.len), FAILED_MEM_ALLOC);
    remaining_len += (sizeof(uint16_t) + conn->protocol_name.len);
    // Pack protocol level
    CHECK(pack8(payload_buf, &len, conn->protocol_level), FAILED_MEM_ALLOC);
    remaining_len += sizeof(uint8_t);
    // Pack connect flags
    CHECK(pack8(payload_buf, &len, conn->connect_flags), FAILED_MEM_ALLOC);
    remaining_len += sizeof(uint8_t);
    // Pack keep alive
    CHECK(pack16(payload_buf, &len, conn->keep_alive), FAILED_MEM_ALLOC);
    remaining_len += sizeof(uint16_t);

    /* Payload */
    // Pack client ID
    CHECK(pack16(payload_buf, &len, conn->payload.client_id_len), FAILED_MEM_ALLOC);
    CHECK(pack_str(payload_buf, &len, conn->payload.client_id, conn->payload.client_id_len), FAILED_MEM_ALLOC);
    remaining_len += (sizeof(uint16_t) + conn->payload.client_id_len);
    // Pack will topic + will message if will flag is set
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {
        // Check if will message/topic aren't empty
        CHECK(!conn->payload.will_topic_len, MALFORMED_PACKET);
        CHECK(!conn->payload.will_topic, MALFORMED_PACKET);
        CHECK(!conn->payload.will_message_len, MALFORMED_PACKET);
        CHECK(!conn->payload.will_message, MALFORMED_PACKET);
        // Pack will topic
        CHECK(pack16(payload_buf, &len, conn->payload.will_topic_len), FAILED_MEM_ALLOC);
        CHECK(pack_str(payload_buf, &len, conn->payload.will_topic, conn->payload.will_topic_len), FAILED_MEM_ALLOC);
        remaining_len += (sizeof(uint16_t) + conn->payload.will_topic_len);
        // Pack will message
        CHECK(pack16(payload_buf, &len, conn->payload.will_message_len), FAILED_MEM_ALLOC);
        CHECK(pack_str(payload_buf, &len, conn->payload.will_message, conn->payload.will_message_len), FAILED_MEM_ALLOC);
        remaining_len += (sizeof(uint16_t) + conn->payload.will_message_len);
    }
    // Add the fixed header at the start
    uint8_t remaining_len_bytes[4];
    size_t encoded_bytes = encode_remaining_length(remaining_len, remaining_len_bytes);
    // Make space for the fixed header
    memmove(buf_start + 1 + encoded_bytes, *payload_buf, remaining_len);
    // Push the first byte of the fixed header
    CHECK(!header.fixed_header, MALFORMED_PACKET);
    *buf_start = header.fixed_header;
    // Push the encoded remaining length field to the buffer
    memcpy(buf_start + 1, remaining_len_bytes, encoded_bytes);
    size_t total_packet_size = 1 + encoded_bytes + remaining_len;

    return total_packet_size;
}


int pack_publish(mqtt_publish *pub, uint8_t **buf) {
    size_t len = 0;
    
}
