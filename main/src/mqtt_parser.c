#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "../include/mqtt_parser.h"

#define DEFAULT_BUF_SIZE        1024    // In bytes
#define MAX_FIXED_HEADER_LEN    5       // In bytes

#define CHECK(x, err, err_out) do { if ((x)) err_out = err; } while (0)


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
    int err;
    // Protocol name length
    conn->protocol_name.len = unpack_uint16(buf);
    // Protocol name
    err = unpack_str(buf, &conn->protocol_name.name, conn->protocol_name.len);
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
    err = unpack_str(buf, &conn->payload.client_id, conn->payload.client_id_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    // Will
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {
        conn->payload.will_topic_len = unpack_uint16(buf);
        if (conn->payload.will_topic_len) {
            err = unpack_str(buf, &conn->payload.will_topic, conn->payload.will_topic_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
        conn->payload.will_message_len = unpack_uint16(buf);
        if (conn->payload.will_message_len) {
            err = unpack_str(buf, &conn->payload.will_message, conn->payload.will_message_len);
            if (err) {
                return FAILED_MEM_ALLOC;
            }
        }
    }
    return MQTT_CONNECT;
}


int unpack_publish(mqtt_publish *publish, mqtt_header header, uint8_t **buf) {
    uint32_t variable_header_len = 0;
    int err;
    // Topic
    publish->topic_len = unpack_uint16(buf);
    variable_header_len += sizeof(uint16_t);
    err = unpack_str(buf, &publish->topic, publish->topic_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }
    variable_header_len += publish->topic_len;
    // Packet ID
    if ((header.fixed_header & QOS_FLAG_MASK) != QOS_AMO_FLAG) {
        publish->pkt_id = unpack_uint16(buf);
        variable_header_len += sizeof(uint16_t);
    }
    // Payload
    publish->payload_len = header.remaining_length - variable_header_len;
    err = unpack_str(buf, &publish->payload, publish->payload_len);
    if (err) {
        return FAILED_MEM_ALLOC;
    }

    return MQTT_PUBLISH;
}


int unpack_subscribe(mqtt_subscribe *subscribe, mqtt_header header, uint8_t **buf) {
    uint32_t remaining_len = header.remaining_length;
    int err;
    if ((header.fixed_header & FLAG_MASK) != SUB_UNSUB_FLAGS) {
        return INCORRECT_FLAGS;
    }
    // Packet ID
    if (remaining_len >= sizeof(uint16_t)) {
        subscribe->pkt_id = unpack_uint16(buf);
        remaining_len -= sizeof(uint16_t);
    }
    int i = 0;
    // Payload
    while (remaining_len > 0) {
        if (remaining_len < sizeof(uint16_t)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= (sizeof(uint16_t));
        void *tmp = realloc(subscribe->tuples, (i + 1) * sizeof(*subscribe->tuples));
        if (!tmp) return GENERIC_ERR;
        subscribe->tuples = tmp;
        subscribe->tuples[i].topic_len = unpack_uint16(buf);

        if ((remaining_len < subscribe->tuples[i].topic_len) || (subscribe->tuples[i].topic_len == 0)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= subscribe->tuples[i].topic_len;
        err = unpack_str(buf, &subscribe->tuples[i].topic, subscribe->tuples[i].topic_len);
        if (err) {
            return FAILED_MEM_ALLOC;
        }

        if (remaining_len < sizeof(uint8_t)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= sizeof(uint8_t);
        subscribe->tuples[i].qos = unpack_uint8(buf);
        i++;
    }
    subscribe->tuples_len = i;
    return MQTT_SUBSCRIBE;
}


int unpack_unsubscribe(mqtt_unsubscribe *unsubscribe, mqtt_header header, uint8_t **buf) {
    uint32_t remaining_len = header.remaining_length;
    int err;
    if ((header.fixed_header & FLAG_MASK) != SUB_UNSUB_FLAGS) {
        return INCORRECT_FLAGS;
    }
    // Packet ID
    if (remaining_len >= sizeof(uint16_t)) {
        unsubscribe->pkt_id = unpack_uint16(buf);
        remaining_len -= sizeof(uint16_t);
    }
    int i = 0;
    // Payload
    while (remaining_len > 0) {
        if (remaining_len < sizeof(uint16_t)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= (sizeof(uint16_t));

        // Allocate or grow the array of topic filter tuples
        // We need space for one more tuple (i + 1 total)
        // sizeof(*unsubscribe->tuples) ensures we allocate space for the actual struct, not just a pointer
        void *tmp = realloc(unsubscribe->tuples, (i + 1) * sizeof(*unsubscribe->tuples));
        if (!tmp) return GENERIC_ERR;
        unsubscribe->tuples = tmp;

        // Unpack topic len
        unsubscribe->tuples[i].topic_len = unpack_uint16(buf);
        if ((remaining_len < unsubscribe->tuples[i].topic_len) || (unsubscribe->tuples[i].topic_len == 0)) {
            return MALFORMED_PACKET;
        }
        remaining_len -= unsubscribe->tuples[i].topic_len;

        // Unpack topic name
        err = unpack_str(buf, unsubscribe->tuples[i].topic, unsubscribe->tuples[i].topic_len);
        if (err) {
            return FAILED_MEM_ALLOC;
        }
        ++i;
    }

    unsubscribe->tuples_len = i;
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
            mqtt_connect conn = packet->type.connect;
            return unpack_connect(&conn, buf);
        }

        case PUBLISH_TYPE: {
            mqtt_publish pub = packet->type.publish;
            return unpack_publish(&pub, packet->header, buf);
        }

        case PUBACK_TYPE: {
            if (packet->header.remaining_length >= 2) {
                packet->type.puback.pkt_id = unpack_uint16(buf);
            }
            return MQTT_PUBACK;
        }

        case SUBSCRIBE_TYPE: {
            mqtt_subscribe sub = packet->type.subscribe;
            return unpack_subscribe(&sub, packet->header, buf);
        }

        case UNSUBSCRIBE_TYPE: {
            mqtt_unsubscribe unsub = packet->type.unsubscribe;
            return unpack_unsubscribe(&unsub, packet->header, buf);
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


int pack8(uint8_t **buf, size_t *buf_len, uint8_t item) {
    uint8_t *tmp = realloc(*buf, *buf_len + sizeof(uint8_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    (*buf)[*buf_len] = item;
    (*buf_len) += sizeof(uint8_t);
    return 0;
}

int pack16(uint8_t **buf, size_t *buf_len, uint16_t item) {
    uint16_t *tmp = realloc(*buf, *buf_len + sizeof(uint16_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    uint16_t network_item = htons(item);  // Convert to network byte order
    memcpy(*buf + *buf_len, &network_item, sizeof(uint16_t));
    (*buf_len) += sizeof(uint16_t);
    return 0;
}

int pack32(uint8_t **buf, size_t *buf_len, uint32_t item) {
    uint32_t *tmp = realloc(*buf, *buf_len + sizeof(uint32_t));
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    uint32_t network_item = htonl(item);  // Convert to network byte order
    memcpy(*buf + *buf_len, &network_item, sizeof(uint32_t));
    (*buf_len) += sizeof(uint32_t);
    return 0;
}

int pack_str(uint8_t **buf, size_t *buf_len, char *str, uint16_t str_len) {
    char *tmp = realloc(*buf, *buf_len + str_len);
    if (!tmp) return FAILED_MEM_ALLOC;
    *buf = tmp;
    memcpy(*buf + *buf_len, str, str_len);
    (*buf_len) += str_len;
    return 0;
}


packing_status finalize_packet(uint8_t *remaining_len_buf, size_t remaining_len, uint8_t header_byte, packing_status *status) {
    // Convert remaining_len from an integer to a variable length encoded buffer
    uint8_t remaining_len_encoded[4];
    size_t encoded_len = encode_remaining_length(remaining_len, remaining_len_encoded);

    // Allocate enough space for the entire packet buffer
    status->buf_len = 1 + encoded_len + remaining_len;
    status->buf = realloc(status->buf, status->buf_len);
    CHECK(!(status->buf), FAILED_MEM_ALLOC, status->return_code);
    if (status->return_code) return *status;  // Early return if realloc fails to prevent undefined behaviour
    
    // Push the first byte of the fixed header
    status->buf[0] = header_byte;
    // Push the encoded remaining length field to the buffer
    memcpy(status->buf + 1, remaining_len_encoded, encoded_len);
    // Push the remaining buffer after the fixed headers
    memmove(status->buf + 1 + encoded_len, remaining_len_buf, remaining_len);
    return *status;
}


packing_status pack_connect(mqtt_connect *conn) {
    packing_status status;
    // Malloc an initial size for the buffer
    uint8_t *tmp = malloc(MAX_FIXED_HEADER_LEN);
    if (!tmp) {
        // Early return if malloc fails to avoid undefined behaviour when trying to dereference a null pointer
        status.return_code = FAILED_MEM_ALLOC;
        return status;
    }
    status.buf = tmp;
    status.return_code = 0;
    size_t buf_len = 0; 

    /* --- Sanity Checks --- */
    CHECK(!conn->protocol_name.len, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->protocol_name.name, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->keep_alive, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->payload.client_id_len, MALFORMED_PACKET, status.return_code);
    CHECK(!conn->payload.client_id, MALFORMED_PACKET, status.return_code);
    if (status.return_code) return status;  // early return

    // Reserve space for the fixed header
    uint8_t *remaining_len_buf = status.buf + MAX_FIXED_HEADER_LEN;

    /* Variable Header */
    // Pack protocol name
    CHECK(pack16(&remaining_len_buf, &buf_len, conn->protocol_name.len), FAILED_MEM_ALLOC, status.return_code);
    CHECK(pack_str(&remaining_len_buf, &buf_len, conn->protocol_name.name, conn->protocol_name.len), FAILED_MEM_ALLOC, status.return_code);
    // Pack protocol level
    CHECK(pack8(&remaining_len_buf, &buf_len, conn->protocol_level), FAILED_MEM_ALLOC, status.return_code);
    // Pack connect flags
    CHECK(pack8(&remaining_len_buf, &buf_len, conn->connect_flags), FAILED_MEM_ALLOC, status.return_code);
    // Pack keep alive
    CHECK(pack16(&remaining_len_buf, &buf_len, conn->keep_alive), FAILED_MEM_ALLOC, status.return_code);

    /* Payload */
    // Pack client ID
    CHECK(pack16(&remaining_len_buf, &buf_len, conn->payload.client_id_len), FAILED_MEM_ALLOC, status.return_code);
    CHECK(pack_str(&remaining_len_buf, &buf_len, conn->payload.client_id, conn->payload.client_id_len), FAILED_MEM_ALLOC, status.return_code);

    // Pack will topic + will message if will flag is set
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {
        // Check if will message/topic aren't empty
        CHECK(!conn->payload.will_topic_len, MALFORMED_PACKET, status.return_code);
        CHECK(!conn->payload.will_topic, MALFORMED_PACKET, status.return_code);
        CHECK(!conn->payload.will_message_len, MALFORMED_PACKET, status.return_code);
        CHECK(!conn->payload.will_message, MALFORMED_PACKET, status.return_code);
        // Pack will topic
        CHECK(pack16(&remaining_len_buf, &buf_len, conn->payload.will_topic_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&remaining_len_buf, &buf_len, conn->payload.will_topic, conn->payload.will_topic_len), FAILED_MEM_ALLOC, status.return_code);
        // Pack will message
        CHECK(pack16(&remaining_len_buf, &buf_len, conn->payload.will_message_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&remaining_len_buf, &buf_len, conn->payload.will_message, conn->payload.will_message_len), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = CONNECT_TYPE;
    return finalize_packet(remaining_len_buf, buf_len, header_byte, &status);
}


packing_status pack_connack(mqtt_connack connack) {
    uint8_t buf[CONNACK_PACKET_SIZE];
    packing_status status = {
        .buf = buf,
        .buf_len = CONNACK_PACKET_SIZE,
        .return_code = 0,
    };

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
    packing_status status;
    // Malloc an initial size for the buffer
    uint8_t *tmp = malloc(MAX_FIXED_HEADER_LEN);
    if (!tmp) {
        // Early return if malloc fails to avoid undefined behaviour when trying to dereference a null pointer
        status.return_code = FAILED_MEM_ALLOC;
        return status;
    }
    status.buf = tmp;
    status.return_code = 0;
    size_t buf_len = 0; 

    /* --- Sanity checks --- */
    // Packet ID may be null if qos = 0
    CHECK(!pub->topic_len, MALFORMED_PACKET, status.return_code);
    CHECK(!pub->topic, MALFORMED_PACKET, status.return_code);
    // Payload can have a 0 length
    if (status.return_code) return status;

    // Reserve space for the fixed header
    uint8_t *remaining_len_buf = status.buf + MAX_FIXED_HEADER_LEN;

    /* Variable Header */
    // Topic Name
    CHECK(pack16(&remaining_len_buf, &buf_len, pub->topic_len), FAILED_MEM_ALLOC, status.return_code);
    CHECK(pack_str(&remaining_len_buf, &buf_len, pub->topic, pub->topic_len), FAILED_MEM_ALLOC, status.return_code);
    // Packet ID
    CHECK(pack16(&remaining_len_buf, &buf_len, pub->pkt_id), FAILED_MEM_ALLOC, status.return_code);

    /* Payload */
    if (pub->payload_len > 0) CHECK(pack_str(&remaining_len_buf, &buf_len, pub->payload, pub->payload_len), FAILED_MEM_ALLOC, status.return_code);

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = PUBLISH_TYPE | flags;
    return finalize_packet(&remaining_len_buf, buf_len, header_byte, &status);
}


packing_status pack_subscribe(mqtt_subscribe *sub) {
    packing_status status;
    // Malloc an initial size for the buffer
    uint8_t *tmp = malloc(MAX_FIXED_HEADER_LEN);
    if (!tmp) {
        // Early return if malloc fails to avoid undefined behaviour when trying to dereference a null pointer
        status.return_code = FAILED_MEM_ALLOC;
        return status;
    }
    status.buf = tmp;
    status.return_code = 0;
    size_t buf_len = 0; 
    
    /* --- Sanity checks --- */
    CHECK(!sub->pkt_id, MALFORMED_PACKET, status.return_code);
    CHECK(!sub->tuples_len, MALFORMED_PACKET, status.return_code);
    CHECK(!sub->tuples->qos, MALFORMED_PACKET, status.return_code);
    CHECK(!sub->tuples->topic, MALFORMED_PACKET, status.return_code);
    CHECK(!sub->tuples->topic_len, MALFORMED_PACKET, status.return_code);
    if (status.return_code) return status;

    // Reserve space for the fixed header
    uint8_t *remaining_len_buf = status.buf + MAX_FIXED_HEADER_LEN;

    // Pack packet ID
    CHECK(pack16(&remaining_len_buf, &buf_len, sub->pkt_id), FAILED_MEM_ALLOC, status.return_code);
    // Pack Topics 
    for (int i = 0; i < sub->tuples_len; ++i) {
        // Topic Name
        CHECK(pack16(&remaining_len_buf, &buf_len, sub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&remaining_len_buf, &buf_len, sub->tuples[i].topic, sub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
        // QOS
        CHECK(pack8(&remaining_len_buf, &buf_len, sub->tuples[i].qos), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = SUBSCRIBE_TYPE | SUB_UNSUB_FLAGS;
    return finalize_packet(&remaining_len_buf, buf_len, header_byte, &status);
}


packing_status pack_unsubscribe(mqtt_subscribe *unsub) {
    packing_status status;
    // Malloc an initial size for the buffer
    uint8_t *tmp = malloc(MAX_FIXED_HEADER_LEN);
    if (!tmp) {
        // Early return if malloc fails to avoid undefined behaviour when trying to dereference a null pointer
        status.return_code = FAILED_MEM_ALLOC;
        return status;
    }
    status.buf = tmp;
    status.return_code = 0;
    size_t buf_len = 0; 

    /* --- Sanity checks --- */
    CHECK(!unsub->pkt_id, MALFORMED_PACKET, status.return_code);
    CHECK(!unsub->tuples_len, MALFORMED_PACKET, status.return_code);
    CHECK(!unsub->tuples->qos, MALFORMED_PACKET, status.return_code);
    CHECK(!unsub->tuples->topic, MALFORMED_PACKET, status.return_code);
    CHECK(!unsub->tuples->topic_len, MALFORMED_PACKET, status.return_code);
    if (status.return_code) return status;

    // Reserve space for the fixed header
    uint8_t *remaining_len_buf = status.buf + MAX_FIXED_HEADER_LEN;

    // Pack packet ID
    CHECK(pack16(&remaining_len_buf, &buf_len, unsub->pkt_id), FAILED_MEM_ALLOC, status.return_code);

    // Pack topics 
    for (int i = 0; i < unsub->tuples_len; ++i) {
        // Topic Name
        CHECK(pack16(&remaining_len_buf, &buf_len, unsub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
        CHECK(pack_str(&remaining_len_buf, &buf_len, unsub->tuples[i].topic, unsub->tuples[i].topic_len), FAILED_MEM_ALLOC, status.return_code);
    }

    /* --- Add the fixed header at the start --- */
    uint8_t header_byte = UNSUBSCRIBE_TYPE | SUB_UNSUB_FLAGS;
    return finalize_packet(&remaining_len_buf, buf_len, header_byte, &status);
}


packing_status pack_disconnect() {
    packing_status status;
    status.buf_len = 2;
    uint8_t buf[status.buf_len];
    
    status.buf = buf;
    status.buf[0] = DISCONNECT_TYPE;    // Flags = 0
    status.buf[1] = 0x00;
    status.return_code = 0;
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
