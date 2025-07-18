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
    OUT_OF_BOUNDS           = -6,
    QOS_LEVEL_NOT_SUPPORTED = -7,
    PACKET_ID_NOT_ALLOWED   = -8,
};


typedef struct {
    uint8_t *buf;
    size_t buf_len;
    int return_code;
} packing_status;

/**
 * @brief Encodes the MQTT Remaining Length field using variable-length encoding.
 *
 * @param[in] remaining_length The length value to encode.
 * @param[out] remaining_len_bytes Output buffer to write the encoded bytes (max 4 bytes).
 * @return Number of bytes written to the output buffer.
 */
int encode_remaining_length(size_t remaining_length, uint8_t *remaining_len_bytes);


/**
 * @brief Decodes a variable-length MQTT Remaining Length field from the buffer.
 *
 * @param[in,out] buf Pointer to the buffer pointer (advances the pointer).
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return Decoded value, or 0xFFFFFFFF on error.
 */
uint32_t decode_remaining_length(uint8_t **buf, int *accumulated_size);


/**
 * @brief Unpacks a uint8_t value from the buffer and advances the buffer pointer.
 *
 * @param[in,out] buf Pointer to the buffer pointer. It will be advanced after reading.
 * @param[in] buf_len Total available length of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return The unpacked uint8_t value as an int, or -1 if out-of-bounds.
 */
int unpack_uint8(uint8_t **buf, size_t buf_len, int *accumulated_size);

/**
 * @brief Unpacks a big-endian uint16_t value from the buffer and advances the buffer pointer.
 *
 * @param[in,out] buf Pointer to the buffer pointer. It will be advanced after reading.
 * @param[in] buf_len Total available length of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return The unpacked uint16_t value as an int, or -1 if out-of-bounds.
 */
int unpack_uint16(uint8_t **buf, size_t buf_len, int *accumulated_size);

/**
 * @brief Allocates memory and unpacks a string from the buffer.
 *
 * @param[in,out] buf Pointer to the buffer pointer. It will be advanced after reading.
 * @param[out] str Output pointer to hold the allocated null-terminated string.
 * @param[in] str_len Length of the string to unpack (not including null terminator).
 * @param[in] buf_len Total available length of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return 0 on success, -1 on memory allocation failure or out-of-bounds access.
 */
int unpack_str(uint8_t **buf, char **str, uint16_t str_len, size_t buf_len, int *accumulated_size);


/**
 * @brief Packs a uint8_t into the buffer and updates the length.
 *
 * @param[in,out] buf Pointer to the buffer pointer (may be reallocated).
 * @param[in,out] len Pointer to current length of buffer (is incremented).
 * @param[in] item The value to pack.
 * @return 0 on success, error code on failure.
 */
int pack8(uint8_t **buf, size_t *len, uint8_t item);

/**
 * @brief Packs a big-endian uint16_t into the buffer and updates the length.
 *
 * @param[in,out] buf Pointer to the buffer pointer (may be reallocated).
 * @param[in,out] len Pointer to current length of buffer (is incremented).
 * @param[in] item The value to pack.
 * @return 0 on success, error code on failure.
 */
int pack16(uint8_t **buf, size_t *len, uint16_t item);

/**
 * @brief Packs a big-endian uint32_t into the buffer and updates the length.
 *
 * @param[in,out] buf Pointer to the buffer pointer (may be reallocated).
 * @param[in,out] len Pointer to current length of buffer (is incremented).
 * @param[in] item The value to pack.
 * @return 0 on success, error code on failure.
 */
int pack32(uint8_t **buf, size_t *len, uint32_t item);

/**
 * @brief Packs a string of fixed length into the buffer.
 *
 * @param[in,out] buf Pointer to the buffer pointer (may be reallocated).
 * @param[in,out] len Pointer to current length of buffer (is incremented).
 * @param[in] str The string to copy into the buffer.
 * @param[in] str_len The number of bytes from the string to copy.
 * @return 0 on success, error code on failure.
 */
int pack_str(uint8_t **buf, size_t *len, char *str, uint16_t str_len);

/**
 * @brief Finalizes the MQTT packet by prepending the fixed header and encoding the remaining length.
 *
 * @param[out] status result struct which contains the final buffer and error codes (if applicable)
 * @param[in] remaining_len Length of the remaining packet (variable header + payload).
 * @param[in] header_byte Fixed header byte (packet type and flags).
 * @return packing_status struct which contains a return code, the final buffer (if no error occured) and it's length.
 */
packing_status finalize_packet(packing_status status, size_t remaining_len, uint8_t header_byte);

/**
 * @brief Packs an MQTT CONNECT packet into a binary buffer.
 *
 * @param[in] conn Pointer to the connect data structure holding connection details.
 * @return packing_status struct containing the final packet buffer, its length and error code (0 = success, otherwise failure).
 */
packing_status pack_connect(mqtt_connect *conn);

packing_status pack_connack(mqtt_connack connack);

/**
 * @brief Packs an MQTT PUBLISH packet into a binary buffer.
 *
 * @param[in] pub Pointer to the publish data structure holding topic, payload, and QoS info.
 * @param[in] flags Publish specific flags represented by the lower nibble of the header byte
 * @return packing_status struct containing the final packet buffer, its length and error code (0 = success, otherwise failure).
 */
packing_status pack_publish(mqtt_publish *pub, uint8_t flags);

/**
 * 
 */
packing_status pack_puback(mqtt_puback puback);

/**
 * @brief Packs an MQTT SUBSCRIBE packet into a binary buffer.
 *
 * @param[in] sub Pointer to the subscribe structure containing topic filters and QoS levels.
 * @return packing_status struct containing the final packet buffer, its length and error code (0 = success, otherwise failure).
 */
packing_status pack_subscribe(mqtt_subscribe *sub);

/**
 * 
 */
packing_status pack_suback(mqtt_suback suback);

/**
 * @brief Packs an MQTT UNSUBSCRIBE packet into a binary buffer.
 *
 * @param[in] unsub Pointer to the unsubscribe structure containing topic filters to remove.
 * @return packing_status struct containing the final packet buffer, its length and error code (0 = success, otherwise failure).
 */
packing_status pack_unsubscribe(mqtt_subscribe *unsub);

/**
 * 
 */
packing_status pack_disconnect();

/**
 * @brief Unpacks a CONNECT packet from the buffer into a mqtt_connect structure.
 *
 * @param[out] conn Pointer to the connect struct to fill.
 * @param[in,out] buf Pointer to the buffer pointer.
 * @param[in] buf_size Size of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return MQTT_CONNECT on success, or an error code on failure.
 */
int unpack_connect(mqtt_connect *conn, uint8_t **buf, size_t buf_size, int accumulated_size);


int unpack_connack(mqtt_connack *connack, uint8_t **buf, size_t buf_size, int accumulated_size);


/**
 * @brief Unpacks a PUBLISH packet from the buffer into a mqtt_publish structure.
 *
 * @param[out] publish Pointer to the publish struct to fill.
 * @param[in] header The MQTT fixed header.
 * @param[in,out] buf Pointer to the buffer pointer.
 * @param[in] buf_size Size of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return MQTT_PUBLISH on success, or an error code on failure.
 */
int unpack_publish(mqtt_publish *publish, mqtt_header header, uint8_t **buf, size_t buf_size, int accumulated_size);

/**
 * @brief Unpacks a SUBSCRIBE packet from the buffer into a mqtt_subscribe structure.
 *
 * @param[out] subscribe Pointer to the subscribe struct to fill.
 * @param[in,out] buf Pointer to the buffer pointer.
 * @param[in] buf_size Size of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return MQTT_SUBSCRIBE on success, or an error code on failure.
 */
int unpack_subscribe(mqtt_subscribe *subscribe, uint8_t **buf, size_t buf_size, int accumulated_size);

/**
 * 
 */
int unpack_suback(mqtt_suback *suback, uint8_t **buf, size_t buf_size, int accumulated_size);

/**
 * @brief Unpacks an UNSUBSCRIBE packet from the buffer into a mqtt_unsubscribe structure.
 *
 * @param[out] unsubscribe Pointer to the unsubscribe struct to fill.
 * @param[in,out] buf Pointer to the buffer pointer.
 * @param[in] buf_size Size of the buffer.
 * @param[in,out] accumulated_size Pointer to a counter tracking the total bytes read so far.
 * @return MQTT_UNSUBSCRIBE on success, or an error code on failure.
 */
int unpack_unsubscribe(mqtt_unsubscribe *unsubscribe, uint8_t **buf, size_t buf_size, int accumulated_size);

/**
 * @brief Dispatches MQTT packet unpacking based on its type.
 *
 * @param[out] packet Pointer to the packet structure to populate.
 * @param[in,out] buf Pointer to the buffer pointer.
 * @param[in] buf_size Size of the buffer.
 * @return MQTT_<TYPE> constant on success, or an error code.
 */
int unpack(mqtt_packet *packet, uint8_t **buf, size_t buf_size);

/**
 * @brief Frees all heap-allocated memory inside a CONNECT packet.
 *
 * @param[in,out] conn Pointer to the mqtt_connect structure.
 */
void free_connect(mqtt_connect *conn);

/**
 * @brief Frees all heap-allocated memory inside a PUBLISH packet.
 *
 * @param[in,out] pub Pointer to the mqtt_publish structure.
 */
void free_publish(mqtt_publish *pub);

/**
 * @brief Frees all heap-allocated memory inside a SUBSCRIBE packet.
 *
 * @param[in,out] sub Pointer to the mqtt_subscribe structure.
 */
void free_subscribe(mqtt_subscribe *sub);

/**
 * @brief Frees all heap-allocated memory inside an UNSUBSCRIBE packet.
 *
 * @param[in,out] unsub Pointer to the mqtt_unsubscribe structure.
 */
void free_unsubscribe(mqtt_unsubscribe *unsub);

/**
 * @brief Frees memory inside an MQTT packet based on its type.
 *
 * @param[in,out] packet Pointer to the mqtt_packet structure.
 */
void free_packet(mqtt_packet *packet);


mqtt_connect default_init_connect(char *client_id, size_t client_id_len);

#endif // mqtt_parser_h
