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
    int err;

    // Protocol name length
    conn->protocol_name.len = unpack_uint16(buf, buf_size, &accumulated_size);
    if (conn->protocol_name.len < 0) return OUT_OF_BOUNDS;
    // Protocol name
    err = unpack_str(buf, &conn->protocol_name.name, conn->protocol_name.len, buf_size, &accumulated_size);
    if (err) return err;
    // Protocol level
    conn->protocol_level = unpack_uint8(buf, buf_size, &accumulated_size);
    if (conn->protocol_level < 0) return OUT_OF_BOUNDS;
    // Connect flags
    conn->connect_flags = unpack_uint8(buf, buf_size, &accumulated_size);
    if ((conn->connect_flags & 1) == 1) return MALFORMED_PACKET;   // LSB MUST be 0;
    if (conn->connect_flags < 0) return OUT_OF_BOUNDS;
    // Keep alive
    conn->keep_alive = unpack_uint16(buf, buf_size, &accumulated_size);
    if (conn->keep_alive < 0) return OUT_OF_BOUNDS;
    // Client ID
    conn->payload.client_id_len = unpack_uint16(buf, buf_size, &accumulated_size);
    if (conn->payload.client_id_len < 0) return OUT_OF_BOUNDS;
    
    err = unpack_str(buf, &conn->payload.client_id, conn->payload.client_id_len, buf_size, &accumulated_size);
    if (err) return err;

    // Will
    if ((conn->connect_flags & WILL_FLAG) == WILL_FLAG) {  // if will flag is set
        conn->payload.will_topic_len = unpack_uint16(buf, buf_size, &accumulated_size);
        if (conn->payload.will_topic_len < 0) return OUT_OF_BOUNDS;
        if (conn->payload.will_topic_len) {
            err = unpack_str(buf, &conn->payload.will_topic, conn->payload.will_topic_len, buf_size, &accumulated_size);
            if (err) return err;
        }

        conn->payload.will_message_len = unpack_uint16(buf, buf_size, &accumulated_size);
        if (conn->payload.will_message_len < 0) return OUT_OF_BOUNDS;
        if (conn->payload.will_message_len) {
            err = unpack_str(buf, &conn->payload.will_message, conn->payload.will_message_len, buf_size, &accumulated_size);
            if (err) return err;
        }
    }
    return MQTT_CONNECT;
}


int unpack_connack(mqtt_connack *connack, uint8_t **buf, size_t buf_size, int accumulated_size) {
    connack->session_present_flag = unpack_uint8(buf, buf_size, &accumulated_size);
    if (connack->session_present_flag < 0) return OUT_OF_BOUNDS;
    // Only the LSB in connack flags may be set
    if ((connack->session_present_flag & 0b11111110) != 0) return MALFORMED_PACKET;

    connack->return_code = unpack_uint8(buf, buf_size, &accumulated_size);
    if (connack->return_code < 0) return OUT_OF_BOUNDS;

    return MQTT_CONNACK;
}


int unpack_publish(mqtt_publish *publish, mqtt_header header, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int err;
    int variable_header_size = 0;

    // Topic
    publish->topic_len = unpack_uint16(buf, buf_size, &accumulated_size);
    if (publish->topic_len < 0) return OUT_OF_BOUNDS;
    variable_header_size += sizeof(uint16_t);

    err = unpack_str(buf, &publish->topic, publish->topic_len, buf_size, &accumulated_size);
    if (err) return err;
    variable_header_size += publish->topic_len;

    // Packet ID
    if ((header.fixed_header & QOS_FLAG_MASK) != QOS_AMO_FLAG) {
        publish->pkt_id = unpack_uint16(buf, buf_size, &accumulated_size);
        if (publish->pkt_id < 0) return OUT_OF_BOUNDS;
        variable_header_size += sizeof(uint16_t);
    }

    // Payload
    if (variable_header_size > (int)header.remaining_length) return MALFORMED_PACKET;

    publish->payload_len = header.remaining_length - variable_header_size;
    err = unpack_str(buf, &publish->payload, publish->payload_len, buf_size, &accumulated_size);
    if (err) return err;

    return MQTT_PUBLISH;
}


int unpack_subscribe(mqtt_subscribe *subscribe, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int err;

    // Packet ID
    subscribe->pkt_id = unpack_uint16(buf, buf_size, &accumulated_size);
    if (subscribe->pkt_id < 0) return OUT_OF_BOUNDS;

    // Payload
    int i = 0;
    while (accumulated_size < (int)buf_size) {
        // Topic len
        void *tmp = realloc(subscribe->tuples, (i + 1) * sizeof(*subscribe->tuples));
        if (!tmp) return GENERIC_ERR;
        subscribe->tuples = tmp;
        subscribe->tuples[i].topic_len = unpack_uint16(buf, buf_size, &accumulated_size);
        if (subscribe->tuples[i].topic_len < 0) return OUT_OF_BOUNDS;
        if (subscribe->tuples[i].topic_len == 0) return MALFORMED_PACKET;

        // Topic name
        err = unpack_str(buf, &subscribe->tuples[i].topic, subscribe->tuples[i].topic_len, buf_size, &accumulated_size);
        if (err) return err;

        // Topic qos
        subscribe->tuples[i].qos = unpack_uint8(buf, buf_size, &accumulated_size);
        if (subscribe->tuples[i].qos < 0) return OUT_OF_BOUNDS;
        ++i;
    }
    subscribe->tuples_len = i;
    return MQTT_SUBSCRIBE;
}


int unpack_unsubscribe(mqtt_unsubscribe *unsubscribe, uint8_t **buf, size_t buf_size, int accumulated_size) {
    int err;

    // Packet ID
    unsubscribe->pkt_id = unpack_uint16(buf, buf_size, &accumulated_size);
    if (unsubscribe->pkt_id < 0) return OUT_OF_BOUNDS;
    
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
        unsubscribe->tuples[i].topic_len = unpack_uint16(buf, buf_size, &accumulated_size);
        if (unsubscribe->tuples[i].topic_len < 0) return OUT_OF_BOUNDS;
        if (unsubscribe->tuples[i].topic_len == 0) return MALFORMED_PACKET;

        // Topic name
        err = unpack_str(buf, &unsubscribe->tuples[i].topic, unsubscribe->tuples[i].topic_len, buf_size, &accumulated_size);
        if (err) return err;
        ++i;
    }
    unsubscribe->tuples_len = i;
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
            if (packet->header.remaining_length >= 2) {
                packet->type.puback.pkt_id = unpack_uint16(buf, buf_size, &accumulated_size);
                if (packet->type.puback.pkt_id < 0) return OUT_OF_BOUNDS;
            }
            return MQTT_PUBACK;
        }

        case SUBSCRIBE_TYPE: {
            if ((packet->header.fixed_header & FLAG_MASK) != SUB_UNSUB_FLAGS) {
                return INCORRECT_FLAGS;
            }
            return unpack_subscribe(&packet->type.subscribe, buf, buf_size, accumulated_size);
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
