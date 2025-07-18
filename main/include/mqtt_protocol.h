#ifndef mqtt_protocol_h
#define mqtt_protocol_h

/* 
 ?MQTT Documentation:
 https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/errata01/os/mqtt-v3.1.1-errata01-os-complete.html#_Toc385349205 
*/

#include <stdio.h>
#include <stdint.h>


#define DEFAULT_BUFF_SIZE       1024
#define HEADER_SIZE             2

/* First byte in the fixed header represents the type of message */
#define CONNECT_TYPE            0x10
#define CONNACK_TYPE            0x20
#define PUBLISH_TYPE            0x30
#define PUBACK_TYPE             0x40
#define PUBREC_TYPE             0x50
#define PUBREL_TYPE             0x60
#define PUBCOMP_TYPE            0x70
#define SUBSCRIBE_TYPE          0x80
#define SUBACK_TYPE             0x90
#define UNSUBSCRIBE_TYPE        0xA0
#define UNSUBACK_TYPE           0xB0
#define PINGREQ_TYPE            0xC0
#define PINGRESP_TYPE           0xD0
#define DISCONNECT_TYPE         0xE0

// Constant packet sizes
#define CONNACK_PACKET_SIZE     4

// Fixed header masks
#define TYPE_MASK               0xF0
#define FLAG_MASK               0x0F

/* Publish flags */
#define RETAIN_FLAG             (1 << 0)
#define QOS_FLAG_MASK           0b00000110
#define DUP_FLAG                (1 << 3)

/* QOS */
#define QOS_0                   0x00            // At most once
#define QOS_1                   (1 << 1)        // At least once
#define QOS_2                   (1 << 2)        // Exactly once

/* Subscribe/Unsubscribe constant flags */
#define SUB_UNSUB_FLAGS         0x02

/* Suback */
#define SUBACK_FAIL             0x80

/* Disconnect constant flags */
#define DISCONNECT_FLAGS        0x00

/* Connack return codes */
#define CONNACK_UNACCEPTABLE_PROTOCOL_VERSION       0x01
#define CONNACK_ID_REJECTED                         0x02
#define CONNACK_SERVER_UNAVAILABLE                  0x03
#define CONNACK_BAD_USERNAME_OR_PASSWORD            0x04
#define CONNACK_NOT_AUTHORIZED                      0x05

/* Connect flags */
#define CLEAN_SESSION_FLAG      (1 << 1)    
#define WILL_FLAG               (1 << 2)
#define WILL_QOS_FLAG_MASK      0b00011000
#define WILL_QOS_AMO            0x00
#define WILL_QOS_ALO            (1 << 3)
#define WILL_QOS_EO             (1 << 4)
#define WILL_RETAIN             (1 << 5)
#define PASSWORD_FLAG           (1 << 6)
#define USERNAME_FLAG           (1 << 7)


/* 
 * Union detailing the structure of an mqtt header. The 'qos', 'dup', and 'retain' flags only apply to PUBLISH type messages.
 * From the LSB to MSB it goes:
 - Retain flag (1 bit)
 - QOS flag (2 bits)
 - Duplicate flag (1 bit)
 - Type of message (4 bits)
*/
typedef struct {
    uint32_t remaining_length;
    uint8_t fixed_header;
} mqtt_header;


/* 
 * Connect packet contains:
 - Fixed header.
 - Variable header that includes a protocol name length (4),
   protocol name ('MQTT'), protocol level (4), connect flags, 
   and 2 bytes of keep alive (MSB then LSB).
 - Payload
*/
typedef struct {
    // Variable Header
    struct {
        uint16_t len;   // MSB then LSB
        char *name;
    } protocol_name;
    uint16_t keep_alive;    // Maximum acceptable time in seconds between the end of one control packet and the start of another
    uint8_t protocol_level; // (4)
    uint8_t connect_flags;
    // Payload (Messages MUST appear in the order below from top to bottom!)
    struct {
        char *client_id;
        char *will_topic;
        char *will_message;
        uint16_t client_id_len;
        uint16_t will_topic_len;
        uint16_t will_message_len;
    } payload;
} mqtt_connect;


typedef struct {
    uint8_t session_present_flag;   // 1 = session present flag set, 0 = session present flag unset
    uint8_t return_code;
} mqtt_connack;


typedef struct {
    char *topic;
    uint16_t topic_len;
    uint8_t qos;
} subscribe_tuples;

typedef struct {
    uint16_t pkt_id;
    uint16_t tuples_len;
    subscribe_tuples *tuples;
} mqtt_subscribe;


typedef struct {
    char *topic;
    uint16_t topic_len;
} unsubscribe_tuples;

typedef struct {
    uint16_t pkt_id;
    uint16_t tuples_len;
    unsubscribe_tuples *tuples;
} mqtt_unsubscribe;


typedef struct {
    uint16_t  pkt_id;
    uint8_t return_code;
} mqtt_suback;


typedef struct {
    uint16_t pkt_id;
    uint16_t topic_len;
    uint32_t payload_len;
    char *topic;
    char *payload;
} mqtt_publish;


typedef struct {
    uint16_t pkt_id;
} mqtt_ack;


/* The rest of message types have the same structure as mqtt_ack or mqtt_header */
typedef mqtt_ack mqtt_puback;
// typedef mqtt_ack mqtt_pubrec;
// typedef mqtt_ack mqtt_pubrel;
// typedef mqtt_ack mqtt_pubcomp;
typedef mqtt_ack mqtt_unsuback;


typedef struct {
    mqtt_header header;
    union {
        mqtt_connect connect;
        mqtt_connack connack;
        mqtt_publish publish;
        mqtt_puback puback;
        mqtt_subscribe subscribe;
        mqtt_suback suback;
        mqtt_unsubscribe unsubscribe;
    } type;
} mqtt_packet;


#endif