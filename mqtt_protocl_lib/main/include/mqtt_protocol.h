#ifndef mqtt_protocol_h
#define mqtt_protocol_h

/**
 * @file mqtt_protocol.h
 * @brief Defines MQTT protocol constants, packet structures, and message formats for MQTT v3.1.1.
 *
 * MQTT Specification Reference:
 * https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/errata01/os/mqtt-v3.1.1-errata01-os-complete.html
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
#define PUBLISH_RETAIN_FLAG     (1 << 0)
#define PUBLISH_QOS_FLAG_MASK   0b00000110
#define PUBLISH_DUP_FLAG        (1 << 3)
#define PUBLISH_QOS_0           0
#define PUBLISH_QOS_1           (1 << 1)
#define PUBLISH_QOS_2           (1 << 2)

/* QOS */
#define QOS_0                   0               // At most once
#define QOS_1                   1               // At least once
#define QOS_2                   (1 << 1)        // Exactly once

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



/**
 * @brief MQTT fixed header representation.
 *
 * - Retain flag (1 bit)  
 * - QoS flag (2 bits)  
 * - Duplicate flag (1 bit)  
 * - Type of message (4 bits)  
 *
 * @note The `qos`, `dup`, and `retain` flags only apply to PUBLISH messages.
 */
typedef struct {
    uint32_t remaining_length;                  /**< Remaining length of packet (variable header + payload). */
    uint8_t fixed_header;                       /**< Fixed header byte containing packet type and flags. */
} mqtt_header;


/**
 * @brief MQTT CONNECT packet structure.
 */
typedef struct {
    /** @brief Variable header fields. */
    struct {
        uint16_t len;                           /**< Protocol name length (MSB then LSB). */
        char *name;                             /**< Protocol name string ("MQTT"). */
    } protocol_name;

    uint16_t keep_alive;                        /**< Keep alive time in seconds. */
    uint8_t protocol_level;                     /**< MQTT protocol level (4 for v3.1.1). */
    uint8_t connect_flags;                      /**< Connect flags bitfield (clean session, will, etc.). */

    /** @brief Payload fields (appear in strict order). */
    struct {
        char *client_id;                        /**< Client identifier string. */
        char *will_topic;                       /**< Will topic string (if will flag set). */
        char *will_message;                     /**< Will message string (if will flag set). */
        uint16_t client_id_len;                 /**< Length of client_id string. */
        uint16_t will_topic_len;                /**< Length of will_topic string. */
        uint16_t will_message_len;              /**< Length of will_message string. */
    } payload;
} mqtt_connect;


/**
 * @brief MQTT CONNACK packet structure.
 */
typedef struct {
    uint8_t session_present_flag;               /**< 1 = session present, 0 = new session. */
    uint8_t return_code;                        /**< Return code (0 = success, otherwise error). */
} mqtt_connack;


/**
 * @brief Tuple representing a single topic and QoS in a SUBSCRIBE request.
 */
typedef struct {
    char *topic;                                /**< Topic filter string. */
    uint8_t qos;                                /**< Requested QoS level for this subscription. */
    uint16_t topic_len;                         /**< Length of topic string. */
    uint8_t suback_status;                      /**< SUBACK return code after subscription. */
} subscribe_tuples;

/**
 * @brief MQTT SUBSCRIBE packet structure.
 */
typedef struct {
    uint16_t pkt_id;                            /**< Packet identifier for this SUBSCRIBE. */
    uint16_t tuples_len;                        /**< Number of subscription tuples. */
    subscribe_tuples *tuples;                   /**< Array of subscription tuples. */
} mqtt_subscribe;


/**
 * @brief Tuple representing a single topic in an UNSUBSCRIBE request.
 */
typedef struct {
    char *topic;                                /**< Topic filter string. */
    uint16_t topic_len;                         /**< Length of topic string. */
} unsubscribe_tuples;

/**
 * @brief MQTT UNSUBSCRIBE packet structure.
 */
typedef struct {
    uint16_t pkt_id;                            /**< Packet identifier for this UNSUBSCRIBE. */
    uint16_t tuples_len;                        /**< Number of unsubscribe tuples. */
    unsubscribe_tuples *tuples;                 /**< Array of unsubscribe tuples. */
} mqtt_unsubscribe;


/**
 * @brief MQTT SUBACK packet structure.
 */
typedef struct {
    uint16_t pkt_id;                            /**< Packet identifier of original SUBSCRIBE. */
    uint8_t *return_codes;                      /**< Granted QoS levels for each topic or failure codes. */
    uint16_t rc_len;                            /**< Length of return_codes array. */
} mqtt_suback;



/**
 * @brief MQTT PUBLISH packet structure.
 */
typedef struct {
    uint16_t pkt_id;                            /**< Packet identifier (QoS 1/2 only). */
    uint16_t topic_len;                         /**< Length of topic string. */
    uint32_t payload_len;                       /**< Length of payload data. */
    char *topic;                                /**< Topic string. */
    char *payload;                              /**< Payload message. */
} mqtt_publish;

/**
 * @brief Generic MQTT ACK packet structure (PUBACK, UNSUBACK, etc.).
 */
typedef struct {
    uint16_t pkt_id;                            /**< Packet identifier of acknowledged message. */
} mqtt_ack;

typedef mqtt_ack mqtt_puback;
typedef mqtt_ack mqtt_unsuback;

/**
 * @brief Generic MQTT packet structure containing header and variant payload types.
 */
typedef struct {
    mqtt_header header;                         /**< Fixed header for all MQTT packets. */
    union {
        mqtt_connect connect;
        mqtt_connack connack;
        mqtt_publish publish;
        mqtt_puback puback;
        mqtt_subscribe subscribe;
        mqtt_suback suback;
        mqtt_unsubscribe unsubscribe;
    } type; /**< Union of all possible packet types. */
} mqtt_packet;

#endif