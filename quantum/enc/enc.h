#pragma once

#include "quantum.h"

#include <stdint.h>

#define CBC 1

#define ENC_ERR_OK          0x00
#define ENC_ERR_EMPTY_BUF   0x01
#define ENC_ERR_NO_CTX      0x02
#define ENC_ERR_NOT_ALLOWED 0x03
#define ENC_ERR_INVALID     0x04
#define ENC_ERR_RETRY       0x05
#define ENC_ERR_HW_SUPPORT  0x06
#define ENC_ERR_MORE_DATA   0x07

#define ENC_CMD_RESET           0x00
#define ENC_CMD_ENCRYPT         0x01
#define ENC_CMD_DECRYPT         0x02
#define ENC_CMD_MORE_DATA       0x03
#define ENC_CMD_UNLOCK          0x04
#define ENC_CMD_LOCK            0x05
#define ENC_CMD_SET_CFG         0x06
#define ENC_CMD_GET_MODE        0x07
#define ENC_CMD_GET_BUFFER      0x08
#define ENC_CMD_GET_KEYS        0x09
#define ENC_CMD_GET_BUFSIZE     0x0A
#define ENC_CMD_SET_KEYS        0x0B
#define ENC_CMD_GET_CFG         0x0C
#define ENC_CMD_INITIALIZE      0x0D
#define ENC_CMD_NONE            0x0E
#define ENC_CMD_SET_BUFFER      0x0F

#define ENC_MODE_CLOSED     0x00
#define ENC_MODE_OPEN       0x01
#define ENC_MODE_LOAD       0x02
#define ENC_MODE_INIT       0x03
#define ENC_MODE_KEY        0x04

#define ENC_SUB_MODE_NONE               0x00
#define ENC_SUB_MODE_SEED               0x01
#define ENC_SUB_MODE_PASSWORD           0x02
#define ENC_SUB_MODE_VERIFY_PASSWORD    0x03
#define ENC_SUB_MODE_REQUEST            0x04
#define ENC_SUB_MODE_REQUEST_ALLOW      0x05
#define ENC_SUB_MODE_REQUEST_DENY       0x06
#define ENC_SUB_MODE_KEY                0x07

#define ENC_CFG_PARANOIA    0x00
#define ENC_CFG_SECURE      0x01
#define ENC_CFG_MAX_ERROR   0x02
#define ENC_CFG_TIMEOUT     0x03

#define ENC_FALSE           0x00
#define ENC_TRUE            0x01

#define ENC_EEPROM_SIZE     123

#ifdef VIA_ENABLE
#   include "via.h"
#   define ENC_EEPROM_ADDR (VIA_EEPROM_CUSTOM_CONFIG_ADDR - ENC_EEPROM_SIZE)
#else
#   include "eeconfig.h"
#   define ENC_EEPROM_ADDR (EECONFIG_SIZE)
#endif

typedef struct __attribute__((packed)) {
    unsigned int max_error:4;
    unsigned int error_count:4;
    unsigned int paranoia_mode:1;
    unsigned int secure_mode:1;
    unsigned int timeout:6;
    unsigned int initialized:1;
    unsigned int reserved:7;
} enc_config_flags_t;

typedef struct __attribute__((packed)) {
    enc_config_flags_t flags;
    uint8_t identifier[8];
    uint8_t salt[16];
    uint8_t validate[32];
    uint8_t key_store[64];
} enc_config_t;

typedef struct __attribute__((packed)) {
    uint32_t seed;
    uint8_t key[32];
} enc_keys_t;

typedef struct {
    uint8_t mode;
    uint8_t sub_mode;
    uint32_t pw_timeout;
    bool pw_timeout_enabled;
    uint8_t req_cmd;
    uint32_t req_timeout;
    bool req_timeout_enabled;
} enc_mode_t;

typedef struct {
    uint16_t     pw[32];
    uint16_t     pw_check[32];
    uint16_t     pw_size;
    uint16_t     pw_check_size;
    bool         pw_ready;
    bool         pw_check_ready;
    uint8_t      key[64];
    uint16_t     key_size;
    bool         key_ready;
    uint32_t     seed;
    bool         seed_ready;
    uint32_t     pw_timer;
    uint32_t     req_timer;
    bool         cfg_ready;
} enc_state_t;

typedef struct {
    enc_mode_t mode;
    enc_config_t cnf;
    enc_keys_t keys;
    enc_state_t state;
} ENC_CTX;

#define ENC_REQUEST_HEADER_LEN       9

#define ENC_RESPONSE_HEADER_POS_SIZE 1
#define ENC_RESPONSE_HEADER_LEN      3

typedef struct __attribute__((packed)) {
    uint8_t magic[2];
    uint8_t cmd;
    uint16_t size;
    uint32_t id;
} enc_request_header_t;

typedef struct {
    uint8_t *data;
    uint16_t dsize;
    uint16_t dpos;
} enc_data_buffer_t;

typedef struct {
    enc_request_header_t req_header;
    enc_data_buffer_t data;
    uint8_t req_cmd;
    uint32_t req_id;
    uint8_t state_cmd;
    uint8_t state_cmd_old;
    uint8_t *res_data;
    uint32_t req_timer;
} enc_request_state_t;

#define ENC_HID_REQUEST_TIMEOUT     30

// Called by QMK core to process ENC-specific keycodes.
bool process_record_enc(uint16_t keycode, keyrecord_t *record);

// called to allow having config ready instantly
void pre_init_enc(void);
void eeconfig_init_enc(void);

enc_config_flags_t enc_get_config_flags(void);
void enc_set_config_flags(enc_config_flags_t);
enc_mode_t enc_get_mode(void);
void enc_set_mode(enc_mode_t);

const char* enc_mode_to_str(uint8_t mode);
const char* enc_sub_mode_to_str(uint8_t mode);
const char* enc_cmd_to_str(uint8_t cmd);
void enc_write_oled(bool invert);
