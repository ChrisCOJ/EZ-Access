#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "../include/mqtt_parser.h"

#define DEFAULT_BUF_SIZE        1024    // In bytes
#define MAX_FIXED_HEADER_LEN    5       // In bytes

#define CHECK(x, err, err_out) do { if ((x)) err_out = err; } while (0)
#define CHECK_SIZE() do {} while (0)


uint32_t decode_remaining_length(uint8_t **buf, int *accumulated_size) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    uint8_t encoded_byte;

    do {
        encoded_byte = **buf;
        ++(*buf);
        ++(*accumulated_size);
        value += (encoded_byte & 127) * multiplier;
        if (multiplier > (128 * 128 * 128)) {
            // Malformed Remaining Length (greater than 4 bytes)
            return 0xFFFFFFFF; // error
        }
        multiplier *= 128;
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


int unpack_uint8(uint8_t **buf, size_t buf_len, int *accumulated_size) {
    if (*accumulated_size + sizeof(uint8_t) > buf_len) {
        return -1;
    }
    *accumulated_size += sizeof(uint8_t);

    uint8_t value = **buf;
    (*buf)++;
    return value;
}

int unpack_uint16(uint8_t **buf, size_t buf_len, int *accumulated_size) {
    if (*accumulated_size + sizeof(uint16_t) > buf_len) {
        return -1;
    }
    *accumulated_size += sizeof(uint16_t);

    uint16_t value;
    memcpy(&value, *buf, sizeof(uint16_t));
    (*buf) += sizeof(uint16_t);
    return ntohs(value);
}

int unpack_str(uint8_t **buf, char **str, uint16_t str_len, size_t buf_len, int *accumulated_size) {
    if ((*accumulated_size + str_len) > (int)buf_len) {
        return OUT_OF_BOUNDS;
    }
    *accumulated_size += str_len;

    *str = malloc(str_len + 1);
    if (!*str) return FAILED_MEM_ALLOC;

    memcpy(*str, *buf, str_len);
    (*str)[str_len] = '\0';
    *buf += str_len;
    return 0;
}


int unpack_connect(mqtt_connect *conn, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int rc;

    // Protocol name length
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    conn->protocol_name.len = (uint16_t)rc;
    // Protocol name
    rc = unpack_str(buf, &conn->protocol_name.name, conn->protocol_name.len, buf_size, &accumulated_size);
    if (rc) return rc;
    // Protocol level
    rc = unpack_uint8(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    conn->protocol_level = (uint8_t)rc;
    // Connect flags
    rc = unpack_uint8(buf, buf_size, &accumulated_size);
    if ((rc & 1) == 1) return MALFORMED_PACKET;   // LSB MUST be 0;
    if (rc < 0) return OUT_OF_BOUNDS;
    conn->connect_flags = (uint8_t)rc;
    // Keep alive
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    conn->keep_alive = (uint16_t)rc;
    // Client ID
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    conn->payload.client_id_len = (uint16_t)rc;
    
    rc = unpack_str(buf, &conn->payload.client_id, conn->payload.client_id_len, buf_size, &accumulated_size);
    if (rc) return rc;

    // Will
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {  // if will flag is set
        // Will topic length
        rc = unpack_uint16(buf, buf_size, &accumulated_size);
        if (rc < 0) return OUT_OF_BOUNDS;
        conn->payload.will_topic_len = (uint16_t)rc;
        // Will topic name
        if (conn->payload.will_topic_len) {
            rc = unpack_str(buf, &conn->payload.will_topic, conn->payload.will_topic_len, buf_size, &accumulated_size);
            if (rc) return rc;
        }

        // Will message length
        rc = unpack_uint16(buf, buf_size, &accumulated_size);
        if (rc < 0) return OUT_OF_BOUNDS;
        conn->payload.will_message_len = (uint16_t)rc;
        // Will message
        if (conn->payload.will_message_len) {
            rc = unpack_str(buf, &conn->payload.will_message, conn->payload.will_message_len, buf_size, &accumulated_size);
            if (rc) return rc;
        }
    }
    return MQTT_CONNECT;
}


int unpack_connack(mqtt_connack *connack, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int rc;

    // Connack flags
    rc = unpack_uint8(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    // Only the LSB in connack flags may be set
    if ((rc & 0b11111110) != 0) return MALFORMED_PACKET;
    connack->session_present_flag = (uint8_t)rc;

    // Connack return code
    rc = unpack_uint8(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    connack->return_code = (uint8_t)rc;

    return MQTT_CONNACK;
}


int unpack_publish(mqtt_publish *publish, mqtt_header header, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int rc;
    int variable_header_size = 0;

    // Topic length
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    publish->topic_len = (uint16_t)rc;
    variable_header_size += sizeof(uint16_t);
    // Topic name
    rc = unpack_str(buf, &publish->topic, publish->topic_len, buf_size, &accumulated_size);
    if (rc) return rc;
    variable_header_size += publish->topic_len;

    // Packet ID
    if ((header.fixed_header & PUBLISH_QOS_FLAG_MASK) != PUBLISH_QOS_0) {
        rc = unpack_uint16(buf, buf_size, &accumulated_size);
        if (rc == 0) return PACKET_ID_NOT_ALLOWED;
        if (rc < 0) return OUT_OF_BOUNDS;
        publish->pkt_id = (uint16_t)rc;
        variable_header_size += sizeof(uint16_t);
    }

    // Payload
    if (variable_header_size > (int)header.remaining_length) return MALFORMED_PACKET;

    publish->payload_len = header.remaining_length - variable_header_size;
    rc = unpack_str(buf, &publish->payload, publish->payload_len, buf_size, &accumulated_size);
    if (rc) return rc;

    return MQTT_PUBLISH;
}


int unpack_subscribe(mqtt_subscribe *subscribe, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int rc;
    int subscribe_global_failure = 0;  // Flag set in case of global subscribe packet failures

    // Packet ID
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc <= 0) subscribe_global_failure = 1;
    subscribe->pkt_id = (uint16_t)rc;

    // Payload
    int i = 0;
    while (accumulated_size < (int)buf_size) {
        if (subscribe_global_failure) {
            subscribe->tuples[i].suback_status = SUBACK_FAIL;
            continue;
        }
        // Topic len
        void *tmp = realloc(subscribe->tuples, (i + 1) * sizeof(*subscribe->tuples));
        if (!tmp) {
            subscribe->tuples[i].suback_status = SUBACK_FAIL;
            continue;
        }
        subscribe->tuples = tmp;
        rc = unpack_uint16(buf, buf_size, &accumulated_size);
        if (rc <= 0) {
            subscribe->tuples[i].suback_status = SUBACK_FAIL;
            continue;
        }
        subscribe->tuples[i].topic_len = (uint16_t)rc;

        // Topic name
        rc = unpack_str(buf, &subscribe->tuples[i].topic, subscribe->tuples[i].topic_len, buf_size, &accumulated_size);
        if (rc) {
            subscribe->tuples[i].suback_status = SUBACK_FAIL;
            continue;
        }
        // Topic qos
        rc = unpack_uint8(buf, buf_size, &accumulated_size);
        if ((rc < 0) || (rc > 1)) {
            subscribe->tuples[i].suback_status = SUBACK_FAIL;
            continue;
        }
        subscribe->tuples[i].qos = (uint8_t)rc;
        // Final return status for the individual subscription is its requested qos
        if (subscribe->tuples[i].suback_status != SUBACK_FAIL) {
            subscribe->tuples[i].suback_status = subscribe->tuples[i].qos;
        }
        ++i;
    }
    subscribe->tuples_len = i;
    if (subscribe->tuples_len == 0) return MALFORMED_PACKET;
    return MQTT_SUBSCRIBE;
}


int unpack_suback(mqtt_suback *suback, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int rc;

    // Packet ID
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc < 0) return OUT_OF_BOUNDS;
    suback->pkt_id = (uint16_t)rc;

    // Return codes
    suback->rc_len = (uint16_t)buf_size - (uint16_t)accumulated_size;
    if (suback->rc_len <= 0) return MALFORMED_PACKET;
    suback->return_codes = malloc(suback->rc_len);
    int i = 0;
    while (i < suback->rc_len) {
        rc = unpack_uint8(buf, buf_size, &accumulated_size);
        if (rc < 0) return OUT_OF_BOUNDS;
        if (rc != QOS_0 && rc != QOS_1 && rc != QOS_2 && rc != SUBACK_FAIL) {
            return MALFORMED_PACKET;
        }
        suback->return_codes[i] = (uint8_t)rc;
        ++i;
    }
    return MQTT_SUBACK;
}



int unpack_unsubscribe(mqtt_unsubscribe *unsubscribe, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int rc;

    // Packet ID
    rc = unpack_uint16(buf, buf_size, &accumulated_size);
    if (rc == 0) return PACKET_ID_NOT_ALLOWED;
    if (rc < 0) return OUT_OF_BOUNDS;
    unsubscribe->pkt_id = (uint16_t)rc;
    
    // Payload
    int i = 0;
    while (accumulated_size < (int)buf_size) {
        // Allocate or grow the array of topic filter tuples
        // We need space for one more tuple (i + 1 total)
        // sizeof(*unsubscribe->tuples) ensures we allocate space for the actual struct, not just a pointer
        void *tmp = realloc(unsubscribe->tuples, (i + 1) * sizeof(*unsubscribe->tuples));
        if (!tmp) return GENERIC_ERR;
        unsubscribe->tuples = tmp;

        // Topic len
        rc = unpack_uint16(buf, buf_size, &accumulated_size);
        if (rc < 0) return OUT_OF_BOUNDS;
        if (rc == 0) return MALFORMED_PACKET;
        unsubscribe->tuples[i].topic_len = (uint16_t)rc;

        // Topic name
        rc = unpack_str(buf, &unsubscribe->tuples[i].topic, unsubscribe->tuples[i].topic_len, buf_size, &accumulated_size);
        if (rc) return rc;
        ++i;
    }
    unsubscribe->tuples_len = i;
    if (unsubscribe->tuples_len == 0) return MALFORMED_PACKET;
    return MQTT_UNSUBSCRIBE;
}


int unpack(mqtt_packet *packet, uint8_t **buf, size_t buf_size){
    int accumulated_size = 0;
    // Extract the fixed header
    packet->header.fixed_header = **buf;
    ++accumulated_size;
    (*buf)++;
    uint32_t remaining_length = decode_remaining_length(buf, &accumulated_size);
    packet->header.remaining_length = remaining_length;
    
    uint8_t packet_type = packet->header.fixed_header & TYPE_MASK;
    switch (packet_type) {
        case CONNECT_TYPE: {
            return unpack_connect(&packet->type.connect, buf, buf_size, accumulated_size);
        }

        case CONNACK_TYPE: {
            if ((packet->header.fixed_header & FLAG_MASK) != 0) return INCORRECT_FLAGS; 
            if (packet->header.remaining_length != 2) return MALFORMED_PACKET;  // Connack has a fixed size of 2
            return unpack_connack(&packet->type.connack, buf, buf_size, accumulated_size);
        }

        case PUBLISH_TYPE: {
            return unpack_publish(&packet->type.publish, packet->header, buf, buf_size, accumulated_size);
        }

        case PUBACK_TYPE: {
            if (packet->header.remaining_length != 2) return MALFORMED_PACKET;
            int rc = unpack_uint16(buf, buf_size, &accumulated_size);
            if (rc < 0) return OUT_OF_BOUNDS;
            packet->type.puback.pkt_id = (uint16_t)rc;
            return MQTT_PUBACK;
        }

        case SUBSCRIBE_TYPE: {
            if ((packet->header.fixed_header & FLAG_MASK) != SUB_UNSUB_FLAGS) {
                return INCORRECT_FLAGS;
            }
            return unpack_subscribe(&packet->type.subscribe, buf, buf_size, accumulated_size);
        }

        case SUBACK_TYPE: {
            return unpack_suback(&packet->type.suback, buf, buf_size, accumulated_size);
        }

        case UNSUBSCRIBE_TYPE: {
            if ((packet->header.fixed_header & FLAG_MASK) != SUB_UNSUB_FLAGS) {
                return INCORRECT_FLAGS;
            }
            return unpack_unsubscribe(&packet->type.unsubscribe, buf, buf_size, accumulated_size);
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


int pack8(uint8_t **buf, size_t *remaining_buf_len, uint8_t item) {
    uint8_t *tmp = realloc(*buf, *remaining_buf_len + sizeof(uint8_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    (*buf)[*remaining_buf_len] = item;
    (*remaining_buf_len) += sizeof(uint8_t);
    return 0;
}

int pack16(uint8_t **buf, size_t *remaining_buf_len, uint16_t item) {
    uint8_t *tmp = realloc(*buf, *remaining_buf_len + sizeof(uint16_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    uint16_t network_item = htons(item);  // Convert to network byte order
    memcpy(*buf + *remaining_buf_len, &network_item, sizeof(uint16_t));
    (*remaining_buf_len) += sizeof(uint16_t);
    return 0;
}

int pack32(uint8_t **buf, size_t *remaining_buf_len, uint32_t item) {
    uint8_t *tmp = realloc(*buf, *remaining_buf_len + sizeof(uint32_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    uint32_t network_item = htonl(item);  // Convert to network byte order
    memcpy(*buf + *remaining_buf_len, &network_item, sizeof(uint32_t));
    (*remaining_buf_len) += sizeof(uint32_t);
    return 0;
}

int pack_str(uint8_t **buf, size_t *remaining_buf_len, char *str, uint16_t str_len) {
    uint8_t *tmp = realloc(*buf, *remaining_buf_len + str_len);
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    memcpy(*buf + *remaining_buf_len, str, str_len);
    (*remaining_buf_len) += str_len;
    return 0;
}


packing_status finalize_packet(packing_status status, size_t remaining_len, uint8_t header_byte) {
    // Convert remaining_len from an integer to a variable length encoded buffer
    uint8_t remaining_len_encoded[4];
    size_t encoded_len = encode_remaining_length(remaining_len, remaining_len_encoded);

    // Allocate enough space for the entire packet buffer
    status.buf_len = 1 + encoded_len + remaining_len;
    status.buf = realloc(status.buf, status.buf_len);
    CHECK(!(status.buf), FAILED_MEM_ALLOC, status.return_code);
    if (status.return_code) return status;  // Early return if realloc fails to prevent undefined behaviour

    // Shift buffer to the right to make space for the fixed header
    memmove(status.buf + 1 + encoded_len, status.buf, remaining_len);
    
    // Push the fixed header at the start of the buffer
    status.buf[0] = header_byte;
    memcpy(status.buf + 1, remaining_len_encoded, encoded_len);

    return status;
}


packing_status pack_connect(mqtt_connect *conn) {
    packing_status status = {
        .buf = NULL,
        .buf_len = 0,
        .return_code = 0,
    };

    /* --- Sanity Checks --- */
    CHECK(!conn->protocol_name.len, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->protocol_name.name, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->payload.client_id_len, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->payload.client_id, MALFORMED_PACKET, status.return_code);
    if (status.return_code) return status;  // early return

    /* Variable Header */
    // Pack protocol name
    CHECK(pack16(&status.buf, &status.buf_len, conn->protocol_name.len), FAILED_MEM_ALLOC, status.return_code);
    CHECK(pack_str(&status.buf, &status.buf_len, conn->protocol_name.name, conn->protocol_name.len), FAILED_MEM_ALLOC, status.return_code);
    // Pack protocol level
    CHECK(pack8(&status.buf, &status.buf_len, conn->protocol_level), FAILED_MEM_ALLOC, status.return_code);
    // Pack connect flags
    CHECK(pack8(&status.buf, &status.buf_len, conn->connect_flags), FAILED_MEM_ALLOC, status.return_code);
    // Pack keep alive
    CHECK(pack16(&status.buf, &status.buf_len, conn->keep_alive), FAILED_MEM_ALLOC, status.return_code);

    /* Payload */
    // Pack client ID
    CHECK(pack16(&status.buf, &status.buf_len, conn->payload.client_id_len), FAILED_MEM_ALLOC, status.return_code);
    CHECK(pack_str(&status.buf, &status.buf_len, conn->payload.client_id, conn->payload.client_id_len), FAILED_MEM_ALLOC, status.return_code);

    // Pack will topic + will message if will flag is set
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {
        // Check if will message/topic aren't empty
        CHECK(!conn->payload.will_topic_len, MALFORMED_PACKET, status.return_code);
        CHECK(!conn->payload.will_topic, MALFORMED_PACKET, status.return_code);
        CHECK(!conn->payload.will_message_len, MALFORMED_PACKET, status.return_code);
        CHECK(!conn->payload.will_message, MALFORMED_PACKET, status.return_code);
        // Pack will topic
        CHECK(pack16(&status.buf, &status.buf_len, conn->payload.will_topic_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&status.buf, &status.buf_len, conn->payload.will_topic, conn->payload.will_topic_len), FAILED_MEM_ALLOC, status.return_code);
        // Pack will message
        CHECK(pack16(&status.buf, &status.buf_len, conn->payload.will_message_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&status.buf, &status.buf_len, conn->payload.will_message, conn->payload.will_message_len), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = CONNECT_TYPE;
    return finalize_packet(status, status.buf_len, header_byte);
}


packing_status pack_connack(mqtt_connack connack) {
    packing_status status = {
        .buf = NULL,
        .buf_len = CONNACK_PACKET_SIZE,
        .return_code = 0,
    };

    status.buf = malloc(status.buf_len);
    if (!status.buf) {
        status.return_code = FAILED_MEM_ALLOC;
        return status;
    }
    /* 
    * Size of connack is constant via the mqtt protocol and each element is exactly 
    * 1 byte long so we can just push every element sequentially.
    */
    status.buf[0] = CONNACK_TYPE;                       // Flags must be 0
    status.buf[1] = 0x02;                               // Remaining len for connack = 2 (constant)
    status.buf[2] = connack.session_present_flag;
    status.buf[3] = connack.return_code;

    return status;
}


packing_status pack_publish(mqtt_publish *pub, uint8_t flags) {
    packing_status status = {
        .buf = NULL,
        .buf_len = 0,
        .return_code = 0,
    };

    /* --- Sanity checks --- */
    // Packet ID may be null if qos = 0
    CHECK(!pub->topic_len, MALFORMED_PACKET, status.return_code);
    CHECK(!pub->topic, MALFORMED_PACKET, status.return_code);
    // Payload can have a 0 length
    if (status.return_code) return status;

    /* Variable Header */
    // Topic Name
    CHECK(pack16(&status.buf, &status.buf_len, pub->topic_len), FAILED_MEM_ALLOC, status.return_code);
    CHECK(pack_str(&status.buf, &status.buf_len, pub->topic, pub->topic_len), FAILED_MEM_ALLOC, status.return_code);
    // Packet ID
    CHECK(pack16(&status.buf, &status.buf_len, pub->pkt_id), FAILED_MEM_ALLOC, status.return_code);

    /* Payload */
    if (pub->payload_len > 0) CHECK(pack_str(&status.buf, &status.buf_len, pub->payload, pub->payload_len), FAILED_MEM_ALLOC, status.return_code);

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = PUBLISH_TYPE | flags;
    return finalize_packet(status, status.buf_len, header_byte);
}


packing_status pack_puback(mqtt_puback puback) {
    packing_status status = {
        .buf = NULL,
        .buf_len = 0,
        .return_code = 0,
    };

    /* --- Sanity checks --- */
    CHECK(!puback.pkt_id, MALFORMED_PACKET, status.return_code);
    if (status.return_code) return status;

    // Pack packet ID
    CHECK(pack16(&status.buf, &status.buf_len, puback.pkt_id), FAILED_MEM_ALLOC, status.return_code);

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = PUBACK_TYPE;  // Flags: 0
    return finalize_packet(status, status.buf_len, header_byte);
}


packing_status pack_subscribe(mqtt_subscribe *sub) {
    packing_status status = {
        .buf = NULL,
        .buf_len = 0,
        .return_code = 0,
    };
    
    /* --- Sanity checks --- */
    CHECK(!sub->pkt_id, MALFORMED_PACKET, status.return_code);
    CHECK(!sub->tuples_len, MALFORMED_PACKET, status.return_code);
    for (int i = 0; i < sub->tuples_len; ++i) {
        CHECK(!sub->tuples->qos, MALFORMED_PACKET, status.return_code);
        CHECK(!sub->tuples->topic, MALFORMED_PACKET, status.return_code);
        CHECK(!sub->tuples->topic_len, MALFORMED_PACKET, status.return_code);
    }
    if (status.return_code) return status;

    // Pack packet ID
    CHECK(pack16(&status.buf, &status.buf_len, sub->pkt_id), FAILED_MEM_ALLOC, status.return_code);
    // Pack Topics 
    for (int i = 0; i < sub->tuples_len; ++i) {
        // Topic Name
        CHECK(pack16(&status.buf, &status.buf_len, sub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&status.buf, &status.buf_len, sub->tuples[i].topic, sub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
        // QOS
        CHECK(pack8(&status.buf, &status.buf_len, sub->tuples[i].qos), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = SUBSCRIBE_TYPE | SUB_UNSUB_FLAGS;
    return finalize_packet(status, status.buf_len, header_byte);
}


packing_status pack_suback(mqtt_suback suback) {
    packing_status status = {
        .buf = NULL,
        .buf_len = 0,
        .return_code = 0,
    };

    /* --- Sanity checks --- */
    CHECK(!suback.pkt_id, MALFORMED_PACKET, status.return_code);
    CHECK(!suback.rc_len, MALFORMED_PACKET, status.return_code);
    if (status.return_code) return status;

    // Pack packet ID
    CHECK(pack16(&status.buf, &status.buf_len, suback.pkt_id), FAILED_MEM_ALLOC, status.return_code);
    // Pack return codes
    for (int i = 0; i < suback.rc_len; ++i) {
        CHECK(pack8(&status.buf, &status.buf_len, suback.return_codes[i]), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = SUBACK_TYPE;  // Flags: 0
    return finalize_packet(status, status.buf_len, header_byte);
}


packing_status pack_unsubscribe(mqtt_subscribe *unsub) {
    packing_status status = {
        .buf = NULL,
        .buf_len = 0,
        .return_code = 0,
    };

    /* --- Sanity checks --- */
    CHECK(!unsub->pkt_id, MALFORMED_PACKET, status.return_code);
    CHECK(!unsub->tuples_len, MALFORMED_PACKET, status.return_code);
    for (int i = 0; i < unsub->tuples_len; ++i) {
        CHECK(!unsub->tuples->qos, MALFORMED_PACKET, status.return_code);
        CHECK(!unsub->tuples->topic, MALFORMED_PACKET, status.return_code);
        CHECK(!unsub->tuples->topic_len, MALFORMED_PACKET, status.return_code);
    }
    if (status.return_code) return status;

    // Pack packet ID
    CHECK(pack16(&status.buf, &status.buf_len, unsub->pkt_id), FAILED_MEM_ALLOC, status.return_code);

    // Pack topics 
    for (int i = 0; i < unsub->tuples_len; ++i) {
        // Topic Name
        CHECK(pack16(&status.buf, &status.buf_len, unsub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&status.buf, &status.buf_len, unsub->tuples[i].topic, unsub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = UNSUBSCRIBE_TYPE | SUB_UNSUB_FLAGS;
    return finalize_packet(status, status.buf_len, header_byte);
}


packing_status pack_disconnect() {
    packing_status status = {
        .buf = NULL,
        .buf_len = 2,
        .return_code = 0,
    };

    status.buf = malloc(status.buf_len);
    if (!status.buf) {
        status.return_code = FAILED_MEM_ALLOC;
        return status;
    }

    status.buf[0] = DISCONNECT_TYPE;    // Flags = 0
    status.buf[1] = 0x00;
    return status;
}


void free_connect(mqtt_connect *conn) {
    if (conn->protocol_name.name) free(conn->protocol_name.name);
    if (conn->payload.client_id) free(conn->payload.client_id);
    if (conn->payload.will_topic) free(conn->payload.will_topic);
    if (conn->payload.will_message) free(conn->payload.will_message);
}

void free_publish(mqtt_publish *pub) {
    if (pub->topic) free(pub->topic);
    if (pub->payload) free(pub->payload);
}

void free_subscribe(mqtt_subscribe *sub) {
    if (sub->tuples) {
        for (int i = 0; i < sub->tuples_len; i++) {
            if (sub->tuples[i].topic) free(sub->tuples[i].topic);
        }
        free(sub->tuples);
    }
    sub->tuples = NULL;
    sub->tuples_len = 0;
}

void free_unsubscribe(mqtt_unsubscribe *unsub) {
    if (unsub->tuples) {
        for (int i = 0; i < unsub->tuples_len; i++) {
            if (unsub->tuples[i].topic) free(unsub->tuples[i].topic);
        }
        free(unsub->tuples);
    }
    unsub->tuples = NULL;
    unsub->tuples_len = 0;
}

void free_packet(mqtt_packet *packet) {
    switch (packet->header.fixed_header & TYPE_MASK) {
        case CONNECT_TYPE:
            free_connect(&packet->type.connect);
            break;
        case PUBLISH_TYPE:
            free_publish(&packet->type.publish);
            break;
        case SUBSCRIBE_TYPE:
            free_subscribe(&packet->type.subscribe);
            break;
        case UNSUBSCRIBE_TYPE:
            free_unsubscribe(&packet->type.unsubscribe);
            break;
        // PUBACK and DISCONNECT do not allocate dynamic memory
        default:
            break;
    }
}


mqtt_connect default_init_connect(char *client_id, size_t client_id_len) {
    mqtt_connect conn = {
        .protocol_name.len = 4,
        .protocol_name.name = "MQTT",
        .protocol_level = 4,
        .connect_flags = CLEAN_SESSION_FLAG,
        .keep_alive = 0,
        .payload.client_id = client_id,
        .payload.client_id_len = client_id_len,
        .payload.will_message_len = 0,
        .payload.will_message = 0,
        .payload.will_topic_len = 0,
        .payload.will_topic = 0,
    };

    return conn;
}
