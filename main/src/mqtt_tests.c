#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "../include/mqtt_parser.h"


#define ASSERT_VERBOSE_INT(actual, expected) \
    do { \
        if ((actual) != (expected)) { \
            printf("ASSERT FAILED: expected %d, got %d\\n", (expected), (actual)); \
        } \
        assert((actual) == (expected)); \
    } while (0)


void test_encode_decode_remaining_length() {
    uint8_t buf[4];
    int sizes[] = {0, 127, 128, 16383, 2097151, 268435455, 1000000000};
    for (int i = 0; i < 7; ++i) {
        encode_remaining_length(sizes[i], buf);
        // printf("REMAINING LEN BUFFER for %d:\n", sizes[i]);
        // for (int i = 0; i < 4; ++i) { 
        //     printf("%02X\n", buf[i]);
        // }
        uint8_t *ptr = buf;
        int acc_size = 0;
        uint32_t decoded = decode_remaining_length(&ptr, &acc_size);
        if (i < 6) {
            ASSERT_VERBOSE_INT(decoded, sizes[i]);
        }
        else {
            ASSERT_VERBOSE_INT(decoded, 0xFFFFFFFF);
        }
    }
}


void test_pack_unpack_connect() {
    char *client_id = "test123";
    mqtt_connect orig = default_init_connect(client_id, strlen(client_id));
    orig.keep_alive = 30;

    packing_status packed = pack_connect(&orig);
    ASSERT_VERBOSE_INT(packed.return_code, 0);

    mqtt_packet pkt = {0};
    uint8_t *ptr = packed.buf;
    int result = unpack(&pkt, &ptr, packed.buf_len);
    ASSERT_VERBOSE_INT(result, MQTT_CONNECT);
    ASSERT_VERBOSE_INT(strcmp(pkt.type.connect.payload.client_id, "test123"), 0);
    ASSERT_VERBOSE_INT(strcmp(pkt.type.connect.protocol_name.name, "MQTT"), 0);
    ASSERT_VERBOSE_INT(pkt.type.connect.protocol_level, 4);
    ASSERT_VERBOSE_INT(pkt.type.connect.keep_alive, 30);

    free_packet(&pkt);
    free(packed.buf);
}


void test_pack_unpack_publish() {
    mqtt_publish pub = {
        .topic = "topic",
        .topic_len = 5,
        .pkt_id = 42,
        .payload = "hello",
        .payload_len = 5,
    };

    packing_status packed = pack_publish(&pub, QOS_ALO_FLAG);  // QoS 1
    ASSERT_VERBOSE_INT(packed.return_code, 0);

    mqtt_packet pkt = {0};
    uint8_t *ptr = packed.buf;
    int result = unpack(&pkt, &ptr, packed.buf_len);
    ASSERT_VERBOSE_INT(result, MQTT_PUBLISH);
    ASSERT_VERBOSE_INT(pkt.type.publish.pkt_id, 42);
    ASSERT_VERBOSE_INT(strcmp(pkt.type.publish.topic, "topic"), 0);
    ASSERT_VERBOSE_INT(strcmp(pkt.type.publish.payload, "hello"), 0);

    free_packet(&pkt);
    free(packed.buf);
}


void test_pack_unpack_connack() {
    mqtt_connack connack = { .session_present_flag = 0, .return_code = 0 };
    packing_status packed = pack_connack(connack);
    ASSERT_VERBOSE_INT(packed.return_code, 0);
    ASSERT_VERBOSE_INT(packed.buf_len, 4);

    mqtt_packet pkt = {0};
    uint8_t *ptr = packed.buf;
    int result = unpack(&pkt, &ptr, packed.buf_len);
    ASSERT_VERBOSE_INT(result, MQTT_CONNACK);
    ASSERT_VERBOSE_INT(pkt.header.remaining_length, 0x02);
    ASSERT_VERBOSE_INT(pkt.type.connack.session_present_flag, 0);
    ASSERT_VERBOSE_INT(pkt.type.connack.return_code, 0);

    free(packed.buf);
}


void test_pack_unpack_disconnect() {
    packing_status packed = pack_disconnect();
    ASSERT_VERBOSE_INT(packed.return_code, 0);
    ASSERT_VERBOSE_INT(packed.buf_len, 2);

    mqtt_packet pkt = {0};
    uint8_t *ptr = packed.buf;
    int result = unpack(&pkt, &ptr, packed.buf_len);
    ASSERT_VERBOSE_INT(result, MQTT_DISCONNECT);
    ASSERT_VERBOSE_INT(pkt.header.remaining_length, 0);

    free(packed.buf);
}

int main() {
    test_encode_decode_remaining_length();
    test_pack_unpack_connect();
    test_pack_unpack_publish();
    test_pack_unpack_connack();
    test_pack_unpack_disconnect();
    printf("All tests passed!\n");
    return 0;
}
