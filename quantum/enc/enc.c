#include "aes.h"
#include "pkcs7_padding.h"
#include "pbkdf2-sha256.h"
#include "enc.h"
#include "enc_boards.h"

#include "raw_hid.h"
#include "eeprom.h"
#include "usb_descriptor.h"

// TEMP -> need to be customized
#include "sendstring_german.h"
#include "keymap_german.h"

#include <string.h>
#include <stdbool.h>

static ENC_CTX         enc_ctx;
static enc_request_state_t enc_request;

#ifdef ENC_HW_RND_STM32F4
#    include "stm32f4xx.h"

#    ifndef ENC_HW_RND
#        define ENC_HW_RND 0x01
#    endif

#    ifndef RNG_NVIC_PREEMPTION_PRIORITY
#        define RNG_NVIC_PREEMPTION_PRIORITY 0x02
#    endif

#    ifndef RNG_NVIC_SUBPRIORITY
#        define RNG_NVIC_SUBPRIORITY 0x00
#    endif
#endif

#ifdef ENC_HW_RND_STM32F4
void enc_rnd_init(void) {
    /* Enable RNG clock source */
    RCC->AHB2ENR |= RCC_AHB2ENR_RNGEN;

    /* RNG Peripheral enable */
    RNG->CR |= RNG_CR_RNGEN;
}

void enc_rnd_deinit(void) {
    /* Disable RNG peripheral */
    RNG->CR &= ~RNG_CR_RNGEN;

    /* Disable RNG clock source */
    RCC->AHB2ENR &= ~RCC_AHB2ENR_RNGEN;
}

uint32_t enc_rnd_get(void) {
    /* Wait until one RNG number is ready */
    while (!(RNG->SR & (RNG_SR_DRDY)))
        ;

    /* Get a 32-bit Random number */
    return RNG->DR;
}
#else
void enc_rnd_init(void) {
    srand(enc_ctx.state.seed);
}

void enc_rnd_deinit(void) {
    return;
}

uint32_t enc_rnd_get(void) {
    uint32_t ret;
    uint8_t *v = (uint8_t *)&ret;

    for (int i = 0; i < 4; i++, v++) {
        *v = rand() % 256;
    }
    return ret;
}
#endif

uint8_t *encrypt_cbc(int size, uint8_t *data, uint8_t *key, uint16_t *osize) {
    if (size <= 0) {
        return NULL;
    }

    int dsize = size;
    // Proper Length of report
    if (size % 16) {
        dsize += 16 - (size % 16);
    }

    // Make the uint8_t arrays
    uint8_t hexarray[dsize];

    // Initialize them with zeros
    memset(hexarray, 0, dsize);

    // Fill the uint8_t arrays
    for (int i = 0; i < size; i++) {
        hexarray[i] = (uint8_t)data[i];
    }

    pkcs7_padding_pad_buffer(hexarray, size, sizeof(hexarray), 16);

    uint8_t enchexarray[dsize + 16];
    memset(enchexarray, 0, dsize + 16);
    for (int i = 0; i < dsize; i++) {
        enchexarray[i + 16] = hexarray[i];
    }

    enc_rnd_init();
    for (int i = 0; i < 16;) {
        uint32_t rnd = enc_rnd_get();
        uint8_t *v   = (uint8_t *)&rnd;
        for (int j = 0; j < 4; j++, v++, i++) {
            enchexarray[i] = *v;
        }
    }
    enc_rnd_deinit();
    // start the encryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, enchexarray);

    // encrypt
    AES_CBC_encrypt_buffer(&ctx, enchexarray + 16, dsize);

    uint8_t *ret = malloc((dsize + 16) * sizeof(uint8_t));
    if (!ret) {
        return ret;
    }
    memcpy(ret, enchexarray, (dsize + 16) * sizeof(uint8_t));
    *osize = dsize + 16;

    return ret;
}

uint8_t *decrypt_cbc(int size, uint8_t *data, uint8_t *key, uint16_t *osize) {
    if (size <= 16) {
        return NULL;
    }

    // Make the uint8_t arrays
    uint8_t hexarray[size - 16];

    // Initialize them with zeros
    memset(hexarray, 0, size - 16);

    // Fill the uint8_t arrays
    for (int i = 0; i < size - 16; i++) {
        hexarray[i] = (uint8_t)data[i + 16];
    }

    // start the decryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, data);

    // decrypt
    AES_CBC_decrypt_buffer(&ctx, hexarray, size - 16);

    size_t dsize = pkcs7_padding_data_length(hexarray, size - 16, 16);
    if (dsize == 0) {
        dsize = size - 16;
    }

    uint8_t *ret = malloc(dsize * sizeof(uint8_t));
    if (!ret) {
        return ret;
    }
    memcpy(ret, hexarray, dsize * sizeof(uint8_t));
    *osize = dsize;

    return ret;
}

void enc_clear_ctx(void) {
    memset(enc_ctx.state.pw, 0, 32 * sizeof(uint16_t));
    memset(enc_ctx.state.pw_check, 0, 32 * sizeof(uint16_t));
    memset(enc_ctx.state.key, 0, 64 * sizeof(uint8_t));

    enc_ctx.state.pw_ready          = false;
    enc_ctx.state.pw_check_ready    = false;
    enc_ctx.state.key_ready         = false;
    enc_ctx.state.pw_size           = 0;
    enc_ctx.state.pw_check_size     = 0;
    enc_ctx.state.key_size          = 0;
    enc_ctx.state.seed              = 0;
#ifdef ENC_HW_RND
    enc_ctx.state.seed_ready = true;
#else
    enc_ctx.state.seed_ready = false;
#endif
    enc_ctx.mode.sub_mode            = ENC_SUB_MODE_NONE;
    enc_ctx.mode.pw_timeout_enabled  = false;
    enc_ctx.mode.req_timeout_enabled = false;

    memset(&enc_ctx.keys, 0x00, 36 * sizeof(uint8_t));
}

void enc_switch_mode(uint8_t mode) {
    enc_ctx.mode.sub_mode = ENC_SUB_MODE_NONE;

    switch (mode) {
        case ENC_MODE_CLOSED:
            enc_clear_ctx();
            break;
        case ENC_MODE_INIT:
            enc_ctx.mode.sub_mode = ENC_SUB_MODE_SEED;
            break;
    }
    enc_ctx.mode.mode = mode;
}

void enc_config_store(void) {
    eeprom_write_block(&enc_ctx.cnf, (uint8_t *)ENC_EEPROM_ADDR, ENC_EEPROM_SIZE);
}

int enc_config_load(void) {
    if (enc_ctx.state.cfg_ready) {
        return 0;
    }
    memset(&enc_ctx.cnf, 0x00, sizeof(enc_config_t));

    eeprom_read_block(&enc_ctx.cnf, (uint8_t *)ENC_EEPROM_ADDR, ENC_EEPROM_SIZE);

    // validating paranoia mode -> need hw support for read data protection
    if (enc_ctx.cnf.flags.paranoia_mode == ENC_TRUE) {
#ifdef ENC_OPTLOCK
        enc_ctx.cnf.flags.paranoia_mode = enc_is_flash_locked();
#else // paranoia mode not supported
        enc_ctx.cnf.flags.paranoia_mode = ENC_FALSE;
#endif
    }

    enc_ctx.state.cfg_ready = true;

    return 0;
}

int enc_unlock(void) {
    enc_config_load();

    if (!enc_ctx.state.pw_ready) {
        return -1;
    }

    eeprom_read_block(&enc_ctx.cnf, (uint8_t *)ENC_EEPROM_ADDR, ENC_EEPROM_SIZE);

    unsigned char pw_hash[32];
    memset(pw_hash, 0x00, 32);

    PKCS5_PBKDF2_HMAC((unsigned char *)enc_ctx.state.pw, enc_ctx.state.pw_size * 2, (unsigned char *)enc_ctx.cnf.salt, 16, 2000, 32, pw_hash);

    int      size  = 32;
    uint8_t *vsalt = decrypt_cbc(size, enc_ctx.cnf.validate, pw_hash, (uint16_t *)&size);
    if (!vsalt) {
        return -1;
    }

    if (memcmp(vsalt, enc_ctx.cnf.salt, 16 * sizeof(uint8_t)) != 0) {
        free(vsalt);
        if (enc_ctx.cnf.flags.paranoia_mode == ENC_TRUE) {
            if ((enc_ctx.cnf.flags.error_count >= enc_ctx.cnf.flags.max_error) && enc_ctx.cnf.flags.max_error > 0) {
                memset(&enc_ctx.cnf, 0x00, ENC_EEPROM_SIZE);
                enc_config_store();
                return -1;
            }
            enc_ctx.cnf.flags.error_count++;
            enc_config_store();
        }
        return -1;
    }
    free(vsalt);

    if (enc_ctx.cnf.flags.paranoia_mode == ENC_TRUE) {
        enc_ctx.cnf.flags.error_count = 0;
        enc_config_store();
    }

    size          = 52;
    uint8_t *keys = decrypt_cbc(size, enc_ctx.cnf.key_store, pw_hash, (uint16_t *)&size);
    if (!keys) {
        return -1;
    }
    memcpy(&enc_ctx.keys, keys, 36 * sizeof(uint8_t));
    enc_ctx.state.seed       = enc_ctx.keys.seed;
    enc_ctx.state.seed_ready = true;

    if (enc_ctx.cnf.flags.timeout > 0) {
        enc_ctx.state.pw_timer          = timer_read32();
        enc_ctx.mode.pw_timeout_enabled = true;
        enc_ctx.mode.pw_timeout         = ((enc_ctx.cnf.flags.timeout * 60000) - timer_elapsed32(enc_ctx.state.pw_timer)) / 1000;
    }

    return 0;
}

void encrypt_keys(void) {
    if (!enc_ctx.state.pw_ready) {
        return;
    }

    unsigned char pw_hash[32];
    memset(pw_hash, 0x00, 32);

    PKCS5_PBKDF2_HMAC((unsigned char *)enc_ctx.state.pw, enc_ctx.state.pw_size * 2, (unsigned char *)enc_ctx.cnf.salt, 16, 2000, 32, pw_hash);

    int      size = 36;
    uint8_t *keys = encrypt_cbc(size, (uint8_t *)&enc_ctx.keys, pw_hash, (uint16_t *)&size);
    if (!keys) {
        return;
    }
    memcpy(enc_ctx.cnf.key_store, keys, size * sizeof(uint8_t));
    free(keys);

    size              = 16;
    uint8_t *validate = encrypt_cbc(size, (uint8_t *)&enc_ctx.cnf.salt, pw_hash, (uint16_t *)&size);
    if (!validate) {
        return;
    }
    memcpy(enc_ctx.cnf.validate, validate, size * sizeof(uint8_t));
    free(validate);

    /*memset(enc_ctx.cnf.keys.s, 0x00, 64*sizeof(uint8_t));*/
}

int initialize_enc(uint8_t *key, uint8_t *iv, bool use_state_key) {
    enc_ctx.cnf.flags.max_error      = 0;
    enc_ctx.cnf.flags.error_count    = 0;
    enc_ctx.cnf.flags.paranoia_mode  = ENC_FALSE;
    enc_ctx.cnf.flags.secure_mode    = ENC_FALSE;
    enc_ctx.cnf.flags.timeout        = 0;
    enc_ctx.mode.pw_timeout_enabled  = false;
    enc_ctx.mode.req_timeout_enabled = false;
    enc_ctx.cnf.flags.initialized    = ENC_TRUE;

    // set to zero
    memset(enc_ctx.cnf.identifier, 0x00, 8 * sizeof(uint8_t));
    memset(enc_ctx.cnf.salt, 0x00, 16 * sizeof(uint8_t));
    memset(enc_ctx.cnf.validate, 0x00, 32 * sizeof(uint8_t));
    memset(&enc_ctx.keys, 0x00, 36 * sizeof(uint8_t));

    if (key && iv) {
        // todo restore
        return -1;
    }

    enc_rnd_init();
    for (int i = 0; i < 8;) {
        uint32_t rnd = enc_rnd_get();
        uint8_t *v   = (uint8_t *)&rnd;
        for (int j = 0; j < 4; j++, v++, i++) {
            enc_ctx.cnf.identifier[i] = *v;
        }
    }
    for (int i = 0; i < 16;) {
        uint32_t rnd = enc_rnd_get();
        uint8_t *v   = (uint8_t *)&rnd;
        for (int j = 0; j < 4; j++, v++, i++) {
            enc_ctx.cnf.salt[i] = *v;
        }
    }
    if (!use_state_key) {
        for (int i = 0; i < 32;) {
            uint32_t rnd = enc_rnd_get();
            uint8_t *v   = (uint8_t *)&rnd;
            for (int j = 0; j < 4; j++, v++, i++) {
                enc_ctx.keys.key[i] = *v;
            }
        }
    } else {
        char hex[2];
        int ki = 0;
        char *ptr;
        for (int i = 0; i < 64; i+=2, ki++) {
            hex[0] = enc_ctx.state.key[i];
            hex[1] = enc_ctx.state.key[i+1];
            enc_ctx.keys.key[ki] = (uint8_t) strtol(hex, &ptr, 16);
        }
    }
    enc_ctx.keys.seed = enc_ctx.state.seed;
    enc_rnd_deinit();

    encrypt_keys();
    enc_config_store();

    return 0;
}

void _enc_clear_request(void) {
    if (enc_request.data.data) free(enc_request.data.data);
    enc_request.req_header.magic[0] = 0;
    enc_request.req_header.magic[1] = 0;
    enc_request.req_header.size = 0;
    enc_request.req_header.cmd = ENC_CMD_NONE;
    enc_request.req_header.id = 0;
    enc_request.req_cmd = ENC_CMD_NONE;
    enc_request.req_id = 0;
    enc_request.state_cmd = ENC_CMD_NONE;
    enc_request.state_cmd_old = ENC_CMD_NONE;
    // res_data must be only a pointer to usb hid data -> free is never needed
    enc_request.res_data = NULL;
    enc_request.req_timer = 0;
}

void _enc_set_response_data_status(uint8_t status, uint8_t *data, bool zero) {
    if (zero && data) memset(data, 0x00, RAW_EPSIZE * sizeof(uint8_t));
    data[0] = status;
}

void _enc_set_response_status(uint8_t status, bool zero) {
    _enc_set_response_data_status(status, enc_request.res_data, zero);
    if ((status != ENC_ERR_OK) && (status != ENC_ERR_RETRY) && (status != ENC_ERR_MORE_DATA)) {
        // reset request on errors
        _enc_clear_request();
    }
}

int _enc_init_request(uint8_t *data) {
    _enc_clear_request();
    memcpy(&enc_request.req_header, data, ENC_REQUEST_HEADER_LEN);
    if ((enc_request.req_header.magic[0] != 0x03) || (enc_request.req_header.magic[1] != 0xFF)) {
        // magic number not matching -> calling custom raw_hid_receive function
        return -66;
    }
    // get keys has a fixed size of 32
    if (enc_request.req_header.cmd == ENC_CMD_GET_KEYS) enc_request.req_header.size = 32;

    enc_request.res_data = data;
    enc_request.data.dpos = 0;
    enc_request.data.dsize = enc_request.req_header.size;
    enc_request.data.data = malloc(enc_request.data.dsize * sizeof(uint8_t));
    if (!enc_request.data.data) {
        _enc_set_response_status(ENC_ERR_EMPTY_BUF, true);
        return -1;
    }
    enc_request.req_cmd = enc_request.req_header.cmd;
    enc_request.req_id = enc_request.req_header.id;
    enc_request.req_timer = timer_read32();
    return 0;
}

bool _enc_request_verification(void) {
    if (enc_request.req_header.id != enc_request.req_id) {
        _enc_set_response_status(ENC_ERR_NOT_ALLOWED, true);
        return false;
    }
    // set timeout if no response is received
    enc_request.req_timer = timer_read32();
    return true;
}

bool _enc_request_approval(void) {
    if (enc_ctx.cnf.flags.secure_mode) {
        if (enc_ctx.mode.req_cmd != enc_request.req_cmd) {
            enc_ctx.mode.sub_mode = ENC_SUB_MODE_NONE;
            enc_ctx.mode.req_timeout_enabled = false;
        }
        switch (enc_ctx.mode.sub_mode) {
            case ENC_SUB_MODE_NONE:
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_REQUEST;
                enc_ctx.mode.req_cmd = enc_request.req_cmd;
                enc_ctx.state.req_timer = timer_read32();
                enc_ctx.mode.req_timeout_enabled = true;
                enc_ctx.mode.req_timeout         = ((15 * 1000) - timer_elapsed32(enc_ctx.state.req_timer)) / 1000;
                _enc_set_response_status(ENC_ERR_RETRY, true);
                uint16_t size = 5;
                memcpy(enc_request.res_data + 1, &size, sizeof(uint16_t));
                enc_request.res_data[4] = enc_ctx.mode.req_cmd;
                memcpy(enc_request.res_data + 5, &enc_ctx.mode.req_timeout, sizeof(uint32_t));
                return false;
            case ENC_SUB_MODE_REQUEST:
                _enc_set_response_status(ENC_ERR_RETRY, true);
                size = 5;
                memcpy(enc_request.res_data + ENC_RESPONSE_HEADER_POS_SIZE, &size, sizeof(uint16_t));
                enc_request.res_data[ENC_RESPONSE_HEADER_LEN + 1] = enc_ctx.mode.req_cmd;
                memcpy(enc_request.res_data + ENC_RESPONSE_HEADER_LEN + 2, &enc_ctx.mode.req_timeout, sizeof(uint32_t));
                return false;
            case ENC_SUB_MODE_REQUEST_DENY:
                enc_ctx.mode.sub_mode            = ENC_SUB_MODE_NONE;
                enc_ctx.mode.req_timeout_enabled = false;
                _enc_set_response_status(ENC_ERR_NOT_ALLOWED, true);
                return false;
            case ENC_SUB_MODE_REQUEST_ALLOW:
                enc_ctx.mode.sub_mode            = ENC_SUB_MODE_NONE;
                enc_ctx.mode.req_timeout_enabled = false;
                return true;
        }
    }
    return true;
}

void _enc_cmd_get_mode(uint8_t*);
void _enc_cmd_get_bufsize(uint8_t*);
void _enc_cmd_get_cfg(uint8_t*);

int _enc_handle_request(uint8_t *data) {
    enc_request_header_t enc_request_header;
    memcpy(&enc_request_header, data, ENC_REQUEST_HEADER_LEN);
    if ((enc_request_header.magic[0] != 0x03) || (enc_request_header.magic[1] != 0xFF)) {
        // magic number not matching -> calling custom raw_hid_receive function
        return -66;
    }
    switch (enc_request_header.cmd) {
        case ENC_CMD_GET_MODE:
            _enc_cmd_get_mode(data);
            return 0;
        case ENC_CMD_GET_BUFSIZE:
            _enc_cmd_get_bufsize(data);
            return 0;
        case ENC_CMD_GET_CFG:
            _enc_cmd_get_cfg(data);
            return 0;
        default:
            if (enc_ctx.mode.mode == ENC_MODE_KEY || enc_ctx.mode.mode == ENC_MODE_INIT || enc_ctx.mode.mode == ENC_MODE_LOAD) {
                _enc_set_response_status(ENC_ERR_NOT_ALLOWED, true);
                return -1;
            }
            break;
    }

    if (enc_request.req_cmd == ENC_CMD_NONE) {
        int ret = _enc_init_request(data);
        if (ret) return ret;
    }

    switch (enc_request.req_cmd) {
        case ENC_CMD_UNLOCK:
        case ENC_CMD_LOCK:
        case ENC_CMD_RESET:
        case ENC_CMD_ENCRYPT:
        case ENC_CMD_DECRYPT:
        case ENC_CMD_SET_KEYS:
        case ENC_CMD_GET_KEYS:
        case ENC_CMD_SET_CFG:
        case ENC_CMD_INITIALIZE:
            break;
        default:
            _enc_set_response_status(ENC_ERR_INVALID, true);
            return -1;
    }

    // approval needed for some requests
    if (enc_request.state_cmd == ENC_CMD_NONE) {
        if (!_enc_request_approval()) return -1;
        enc_request.state_cmd = enc_request.req_cmd;
    }

    // verify request origin
    if (!_enc_request_verification()) return -1;

    switch (enc_request.req_cmd) {
        case ENC_CMD_ENCRYPT:
        case ENC_CMD_DECRYPT:
        case ENC_CMD_SET_KEYS:
            if (enc_request.state_cmd == enc_request.req_cmd) enc_request.state_cmd = ENC_CMD_SET_BUFFER;
            break;
        case ENC_CMD_GET_KEYS:
            if (enc_request.state_cmd == enc_request.req_cmd) enc_request.state_cmd = ENC_CMD_GET_BUFFER;
            break;
    }
    return 0;
}

void _enc_cmd_get_buffer(void) {
    _enc_set_response_status(ENC_ERR_MORE_DATA, true);
    int      boundary      = RAW_EPSIZE - ENC_RESPONSE_HEADER_LEN;
    int      data_boundary = enc_request.data.dsize - enc_request.data.dpos;
    uint16_t size          = data_boundary;
    if (size > boundary) {
        size = boundary;
    }

    memcpy(enc_request.res_data + ENC_RESPONSE_HEADER_POS_SIZE, &size, sizeof(uint16_t));
    memcpy(enc_request.res_data + ENC_RESPONSE_HEADER_LEN, enc_request.data.data + enc_request.data.dpos, size * sizeof(uint8_t));

    if (data_boundary <= boundary) {
        _enc_set_response_status(ENC_ERR_OK, false);
        _enc_clear_request();
        return;
    }
    enc_request.data.dpos += boundary;
}

void _enc_cmd_set_buffer(void) {
    bool fin      = false;
    int  boundary = RAW_EPSIZE - ENC_REQUEST_HEADER_LEN;

    if ((enc_request.data.dsize - enc_request.data.dpos) <= boundary) {
        fin      = true;
        boundary = enc_request.data.dsize - enc_request.data.dpos;
    }

    memcpy(enc_request.data.data + enc_request.data.dpos, enc_request.res_data + ENC_REQUEST_HEADER_LEN, boundary);
    enc_request.data.dpos += boundary;

    if (fin) {
        enc_request.data.dpos     = 0;
        enc_request.state_cmd = ENC_CMD_GET_BUFFER;
        _enc_set_response_status(ENC_ERR_MORE_DATA, true);
        return;
    }
    _enc_set_response_status(ENC_ERR_OK, true);
}

void _enc_cmd_reset(void) {
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        _enc_set_response_status(ENC_ERR_NO_CTX, true);
        return;
    }

    memset(&enc_ctx.cnf, 0x00, ENC_EEPROM_SIZE);
    memset(&enc_ctx.state, 0x00, sizeof(enc_state_t));
    enc_config_store();
    enc_switch_mode(ENC_MODE_CLOSED);
    _enc_set_response_status(ENC_ERR_OK, true);
    _enc_clear_request();
}

bool _enc_cmd_encrypt(void) {
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        _enc_set_response_status(ENC_ERR_NO_CTX, true);
        return false;
    }

    // already encrypted
    if (enc_request.data.dpos != 0) return true;

    uint8_t *enc_data = encrypt_cbc(enc_request.data.dsize, enc_request.data.data, enc_ctx.keys.key, &enc_request.data.dsize);
    if (!enc_data) {
        _enc_set_response_status(ENC_ERR_EMPTY_BUF, true);
        return false;
    }
    if (enc_request.data.data) {
        free(enc_request.data.data);
    }
    enc_request.data.data = malloc(enc_request.data.dsize * sizeof(uint8_t));
    if (!enc_request.data.data) {
        free(enc_data);
        _enc_set_response_status(ENC_ERR_EMPTY_BUF, true);
        return false;
    }
    memcpy(enc_request.data.data, enc_data, enc_request.data.dsize * sizeof(uint8_t));
    free(enc_data);
    return true;
}

bool _enc_cmd_decrypt(void) {
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        _enc_set_response_status(ENC_ERR_NO_CTX, true);
        return false;
    }

    // already decrypted
    if (enc_request.data.dpos != 0) return true;

    uint8_t *dec_data = decrypt_cbc(enc_request.data.dsize, enc_request.data.data, enc_ctx.keys.key, &enc_request.data.dsize);
    if (!dec_data) {
        _enc_set_response_status(ENC_ERR_EMPTY_BUF, true);
        return false;
    }
    if (enc_request.data.data) {
        free(enc_request.data.data);
    }

    enc_request.data.data = malloc(enc_request.data.dsize * sizeof(uint8_t));
    if (!enc_request.data.data) {
        free(dec_data);
        _enc_set_response_status(ENC_ERR_EMPTY_BUF, true);
        return false;
    }
    memcpy(enc_request.data.data, dec_data, enc_request.data.dsize * sizeof(uint8_t));
    free(dec_data);
    return true;
}

void _enc_cmd_unlock(void) {
    if (enc_ctx.mode.mode == ENC_MODE_OPEN) return;

    enc_switch_mode(ENC_MODE_LOAD);
    _enc_set_response_status(ENC_ERR_OK, true);
    _enc_clear_request();
}

void _enc_cmd_lock(void) {
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) return;

    enc_switch_mode(ENC_MODE_CLOSED);
    _enc_set_response_status(ENC_ERR_OK, true);
    _enc_clear_request();
}

void _enc_cmd_set_cfg(void) {
    if (enc_request.req_header.size != 2) {
        _enc_set_response_status(ENC_ERR_INVALID, true);
        return;
    }
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        _enc_set_response_status(ENC_ERR_NO_CTX, true);
        return;
    }

    uint8_t cfg = enc_request.res_data[ENC_REQUEST_HEADER_LEN];
    uint8_t val = enc_request.res_data[ENC_REQUEST_HEADER_LEN+1];

    switch (cfg) {
        case ENC_CFG_PARANOIA:
            if (val != ENC_TRUE && val != ENC_FALSE) {
                _enc_set_response_status(ENC_ERR_INVALID, true);
                return;
            }
            if (enc_ctx.cnf.flags.paranoia_mode == ENC_TRUE) {
                _enc_set_response_status(ENC_ERR_NOT_ALLOWED, true);
                return;
            }
#ifdef ENC_OPTLOCK
            enc_flash_lock();
            if (enc_is_flash_locked() != ENC_TRUE) {
                _enc_set_response_status(ENC_ERR_INVALID, true);
                return;
            }
#else
            _enc_set_response_status(ENC_ERR_HW_SUPPORT, true);
            return;
#endif
            enc_ctx.cnf.flags.paranoia_mode = val;
            break;
        case ENC_CFG_SECURE:
            if (val != ENC_TRUE && val != ENC_FALSE) {
                _enc_set_response_status(ENC_ERR_INVALID, true);
                return;
            }
            enc_ctx.cnf.flags.secure_mode = val;
            break;
        case ENC_CFG_MAX_ERROR:
            if (val < 0 || val > 15) {
                _enc_set_response_status(ENC_ERR_INVALID, true);
                return;
            }
            enc_ctx.cnf.flags.max_error = val;
            break;
        case ENC_CFG_TIMEOUT:
            if (val < 0 || val > 60) {
                _enc_set_response_status(ENC_ERR_INVALID, true);
                return;
            }
            if (val != enc_ctx.cnf.flags.timeout) {
                enc_ctx.cnf.flags.timeout = val;
                if (val > 0) {
                    enc_ctx.state.pw_timer          = timer_read32();
                    enc_ctx.mode.pw_timeout_enabled = true;
                    enc_ctx.mode.pw_timeout         = ((enc_ctx.cnf.flags.timeout * 60000) - timer_elapsed32(enc_ctx.state.pw_timer)) / 1000;
                } else {
                    enc_ctx.mode.pw_timeout_enabled = false;
                }
            }
            break;
        default:
            _enc_set_response_status(ENC_ERR_INVALID, true);
            return;
    }
    enc_config_store();
    _enc_set_response_status(ENC_ERR_OK, true);
}

void _enc_cmd_get_mode(uint8_t *data) {
    _enc_set_response_data_status(ENC_ERR_OK, data, true);

    uint16_t size = 2;
    memcpy(data + 1, &size, sizeof(uint16_t));
    data[3]                  = enc_ctx.mode.mode;
    data[4]                  = enc_ctx.mode.sub_mode;
}

void _enc_cmd_get_cfg(uint8_t *data) {
    _enc_set_response_data_status(ENC_ERR_OK, data, true);

    uint16_t size = 6;
    memcpy(data + 1, &size, sizeof(uint16_t));
    data[3]                  = enc_ctx.cnf.flags.max_error;
    data[4]                  = enc_ctx.cnf.flags.error_count;
    data[5]                  = enc_ctx.cnf.flags.paranoia_mode;
    data[6]                  = enc_ctx.cnf.flags.secure_mode;
    data[7]                  = enc_ctx.cnf.flags.timeout;
    data[8]                  = enc_ctx.cnf.flags.initialized;
}

void _enc_cmd_get_bufsize(uint8_t *data) {
    _enc_set_response_data_status(ENC_ERR_OK, data, true);

    uint16_t size = 1;
    memcpy(data + 1, &size, sizeof(uint16_t));
    data[3]                  = RAW_EPSIZE;
}

bool _enc_cmd_get_keys(void) {
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        _enc_set_response_status(ENC_ERR_NO_CTX, true);
        return false;
    }

    // already copied 
    if (enc_request.data.dpos != 0) return true;

    memcpy(enc_request.data.data, enc_ctx.keys.key, 32 * sizeof(uint8_t));
    return true;
}

bool _enc_cmd_set_keys(void) {
    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        _enc_set_response_status(ENC_ERR_NO_CTX, true);
        return false;
    }

    // already copied 
    if (enc_request.data.dpos != 0) return true;

    if (enc_request.data.dsize != 32) {
        _enc_set_response_status(ENC_ERR_INVALID, true);
        return false;
    }
    memcpy(enc_ctx.keys.key, enc_request.data.data, enc_request.data.dsize * sizeof(uint8_t));
    encrypt_keys();
    enc_config_store();
    return true;
}

void _enc_cmd_initialize(void) {
    _enc_set_response_status(ENC_ERR_OK, true);

    memset(&enc_ctx.cnf, 0x00, sizeof(enc_config_t));
    enc_config_store();
    _enc_clear_request();
}

void housekeeping_task_kb(void) {
    if (enc_request.req_cmd != ENC_CMD_NONE) {
        if (timer_elapsed32(enc_request.req_timer) >= (ENC_HID_REQUEST_TIMEOUT * 1000)) _enc_clear_request();
    }
    if (enc_ctx.mode.sub_mode == ENC_SUB_MODE_REQUEST) {
        if (timer_elapsed32(enc_ctx.state.req_timer) >= (15 * 1000)) {
            enc_ctx.mode.sub_mode = ENC_SUB_MODE_NONE;
        } else {
            enc_ctx.mode.req_timeout = ((15 * 1000) - timer_elapsed32(enc_ctx.state.req_timer)) / 1000;
        }
    }

    if (enc_ctx.mode.mode != ENC_MODE_OPEN) {
        return;
    }

    if (timer_elapsed32(enc_ctx.state.pw_timer) >= (enc_ctx.cnf.flags.timeout * 60000)) {
        if (!enc_ctx.mode.pw_timeout_enabled) {
            return;
        }

        enc_switch_mode(ENC_MODE_CLOSED);
        return;
    }
    enc_ctx.mode.pw_timeout = ((enc_ctx.cnf.flags.timeout * 60000) - timer_elapsed32(enc_ctx.state.pw_timer)) / 1000;
}

void enc_read_seed(uint16_t keycode) {
    if (!enc_ctx.state.seed_ready) {
        if (keycode != KC_ENT) {
            uint8_t *_keycode  = (uint8_t *)&keycode;
            enc_ctx.state.seed = enc_ctx.state.seed + _keycode[0];
            enc_ctx.state.seed = enc_ctx.state.seed + _keycode[1];
        } else {
            enc_ctx.state.seed_ready = true;
        }
    }
}

int enc_read_pw(uint16_t keycode) {
    if (!enc_ctx.state.pw_ready) {
        if (keycode != KC_ENT) {
            if (enc_ctx.state.pw_size >= 32) {
                return -1;
            }
            enc_ctx.state.pw[enc_ctx.state.pw_size] = keycode;
            enc_ctx.state.pw_size++;
         } else {
            enc_ctx.state.pw_ready = true;
            return 0;
        }
    }
    return 0;
}

int enc_read_pw_check(uint16_t keycode) {
    if (!enc_ctx.state.pw_check_ready) {
        if (keycode != KC_ENT) {
            if (enc_ctx.state.pw_check_size >= 32) {
                return -1;
            }
            enc_ctx.state.pw_check[enc_ctx.state.pw_check_size] = keycode;
            enc_ctx.state.pw_check_size++;
        } else {
            if (enc_ctx.state.pw_check_size != enc_ctx.state.pw_size) {
                return -1;
            }
            if (memcmp(enc_ctx.state.pw, enc_ctx.state.pw_check, enc_ctx.state.pw_size * sizeof(uint16_t)) == 0) {
                enc_ctx.state.pw_check_ready = true;
                return 0;
            } else {
                return -1;
            }
        }
    }
    return 0;
}

int enc_read_key(uint16_t keycode) {
    if (!enc_ctx.state.key_ready) {
        if (keycode != KC_ENT) {
            if (enc_ctx.state.key_size >= 64) {
                return -1;
            }
            switch (keycode) {
                case KC_A:
                    enc_ctx.state.key[enc_ctx.state.key_size] = 'a';
                    break;
                case KC_B:
                    enc_ctx.state.key[enc_ctx.state.key_size] = 'b';
                    break;
                case KC_C:
                    enc_ctx.state.key[enc_ctx.state.key_size] = 'c';
                    break;
                case KC_D:
                    enc_ctx.state.key[enc_ctx.state.key_size] = 'd';
                    break;
                case KC_E:
                    enc_ctx.state.key[enc_ctx.state.key_size] = 'e';
                    break;
                case KC_F:
                    enc_ctx.state.key[enc_ctx.state.key_size] = 'f';
                    break;
                case KC_0:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '0';
                    break;
                case KC_1:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '1';
                    break;
                case KC_2:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '2';
                    break;
                case KC_3:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '3';
                    break;
                case KC_4:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '4';
                    break;
                case KC_5:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '5';
                    break;
                case KC_6:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '6';
                    break;
                case KC_7:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '7';
                    break;
                case KC_8:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '8';
                    break;
                case KC_9:
                    enc_ctx.state.key[enc_ctx.state.key_size] = '9';
                    break;
                default:
                    return -1;
                    
            }
            enc_ctx.state.key[enc_ctx.state.key_size] = keycode;
            enc_ctx.state.key_size++;
        } else {
            if (enc_ctx.state.key_size != 64) {
                return -1;
            }
            enc_ctx.state.key_ready = true;
            return 0;
        }
    }
    return 0;
}

void pre_init_enc(void) {
    enc_config_load();
    _enc_clear_request();
}

void eeconfig_init_enc() {
    memset(&enc_ctx.cnf, 0x00, sizeof(enc_config_t));
    enc_config_store();
}

bool process_record_enc(uint16_t keycode, keyrecord_t *record) {
    switch (enc_ctx.mode.mode) {
        case ENC_MODE_INIT:
            if (!enc_ctx.state.seed_ready) {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_SEED;
            } else if (!enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_PASSWORD;
            } else {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_VERIFY_PASSWORD;
            }
            if (!record->event.pressed) {
                return true;
            }
            if (!enc_ctx.state.seed_ready) {
                enc_read_seed(keycode);
                return false;
            }

            if (!enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                int ret = enc_read_pw(keycode);
                if (ret != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                }
                return false;
            } 

            if (!enc_ctx.state.pw_check_ready &&  enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                int ret = enc_read_pw_check(keycode);
                if (ret != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                }
                return false;
            } else {
                if (initialize_enc(NULL, NULL, false) != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                } else {
                    enc_switch_mode(ENC_MODE_OPEN);
                }
            }
            return false;
            break;
        case ENC_MODE_LOAD:
            if (!record->event.pressed) {
                return true;
            }
            enc_read_pw(keycode);
            if (enc_ctx.state.pw_ready) {
                if (enc_unlock() != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                } else {
                    enc_switch_mode(ENC_MODE_OPEN);
                }
            }
            return false;
            break;
        case ENC_MODE_KEY:
            if (!enc_ctx.state.seed_ready) {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_SEED;
            } else if (!enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_PASSWORD;
            } else if (!enc_ctx.state.pw_check_ready &&  enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_VERIFY_PASSWORD;
            } else {
                enc_ctx.mode.sub_mode = ENC_SUB_MODE_KEY;
            }
            if (!record->event.pressed) {
                return true;
            }
            if (!enc_ctx.state.seed_ready) {
                enc_read_seed(keycode);
                return false;
            }

            if (!enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                int ret = enc_read_pw(keycode);
                if (ret != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                }
                return false;
            } 

            if (!enc_ctx.state.pw_check_ready &&  enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                int ret = enc_read_pw_check(keycode);
                if (ret != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                }
                return false;
             }

             if (!enc_ctx.state.key_ready && enc_ctx.state.pw_check_ready &&  enc_ctx.state.pw_ready && enc_ctx.state.seed_ready) {
                int ret = enc_read_key(keycode);
                if (ret != 0) {
                    enc_switch_mode(ENC_MODE_CLOSED);
                }
                return false;
             } else {
                 if (initialize_enc(NULL, NULL, true) != 0) {
                     enc_switch_mode(ENC_MODE_CLOSED);
                 } else {
                     enc_switch_mode(ENC_MODE_OPEN);
                 }
             }
             return false;
             break;
    }

    switch (keycode) {
        case ENC_INIT:
            if (record->event.pressed) {
                enc_clear_ctx();
                enc_switch_mode(ENC_MODE_INIT);
            }
            return false;
            break;
        case ENC_LOAD:
            if (record->event.pressed) {
                enc_clear_ctx();
                enc_switch_mode(ENC_MODE_LOAD);
            }
            return false;
            break;
        case ENC_CLOSE:
            if (record->event.pressed) {
                enc_clear_ctx();
                enc_switch_mode(ENC_MODE_CLOSED);
            }
            return false;
            break;
        case ENC_PASTE:
            if (record->event.pressed) {
                if (!enc_request.data.data) {
                    return true;
                }
                uint8_t paste_buf[enc_request.data.dsize + 1];
                memset(paste_buf, 0x00, enc_request.data.dsize + 1 * sizeof(uint8_t));
                memcpy(paste_buf, enc_request.data.data, enc_request.data.dsize * sizeof(uint8_t));

                send_string((const char *)paste_buf);
                /*send_unicode_string((const char *) paste_buf);*/
                return false;
            }
            break;
        case ENC_KEYSPASTE:
            if (record->event.pressed) {
                if (enc_ctx.mode.mode != ENC_MODE_OPEN || enc_ctx.cnf.flags.paranoia_mode == ENC_TRUE) {
                    return true;
                }
                char paste_buf[129];
                memset(paste_buf, 0x00, 129 * sizeof(uint8_t));
                char *buf_ptr = paste_buf;
                for (int i = 0; i < 64; i++, buf_ptr += 2) {
                    sprintf(buf_ptr, "%02x", ((uint8_t *)&enc_ctx.keys)[i]);
                }
                send_string((const char *)paste_buf);
                /*send_unicode_string((const char *) paste_buf);*/
                return false;
            }
            break;
    }

    /*uint8_t *_keycode = (uint8_t *) &keycode;*/
    /*enc_ctx.state.seed = enc_ctx.state.seed + _keycode[0];*/
    /*enc_ctx.state.seed = enc_ctx.state.seed + _keycode[1];*/
    /*enc_ctx.keys.seed = enc_ctx.state.seed;*/

    if (enc_ctx.mode.sub_mode == ENC_SUB_MODE_REQUEST) {
        if (record->event.pressed) {
            switch (keycode) {
                case ENC_REQ_ALLOW:
                    enc_ctx.mode.sub_mode = ENC_SUB_MODE_REQUEST_ALLOW;
                    break;
                case ENC_REQ_DENY:
                    enc_ctx.mode.sub_mode = ENC_SUB_MODE_REQUEST_DENY;
                    break;
                default:
                    return true;
            }
            return false;
        }
    }

    return true;
}

// Keyboard level code can override this to handle custom messages from ENC.
// See raw_hid_receive() implementation.
// DO NOT call raw_hid_send() in the override function.
__attribute__((weak)) void raw_hid_receive_enc_kb(uint8_t *data, uint8_t length) {}

void raw_hid_receive_enc(uint8_t *data, uint8_t length) {
    /*uint8_t cmd = data[2];*/
    /*uint16_t size = 0;*/

    int res = _enc_handle_request(data);
    if (res == -66) {
        return raw_hid_receive_enc_kb(data, length);
    }
    if (res) {
        return;
    }

    switch (enc_request.state_cmd) {
        case ENC_CMD_RESET:
            _enc_cmd_reset();
            break;
        case ENC_CMD_UNLOCK:
            _enc_cmd_unlock();
            break;
        case ENC_CMD_LOCK:
            _enc_cmd_lock();
            break;
        case ENC_CMD_SET_CFG:
            _enc_cmd_set_cfg();
            _enc_clear_request();
            break;
        case ENC_CMD_GET_BUFFER:
            bool error = false;
            switch (enc_request.req_cmd) {
                case ENC_CMD_ENCRYPT:
                    if (!_enc_cmd_encrypt()) error = true;
                    break;
                case ENC_CMD_DECRYPT:
                    if (!_enc_cmd_decrypt()) error = true;
                    break;
                case ENC_CMD_GET_KEYS:
                    if (!_enc_cmd_get_keys()) error = true;
                    break;
                case ENC_CMD_SET_KEYS:
                    if (!_enc_cmd_set_keys()) error = true;
                    break;
            }
            if (error) {
                _enc_clear_request();
                break;
            }
            _enc_cmd_get_buffer();
            break;
        case ENC_CMD_SET_BUFFER:
            _enc_cmd_set_buffer();
            break;
        case ENC_CMD_INITIALIZE:
            _enc_cmd_initialize();
            break;
        case ENC_CMD_NONE:
            break;
        default:
            raw_hid_receive_enc_kb(data, length);
            break;
    }
}

#ifndef VIA_ENABLE
void raw_hid_receive(uint8_t *data, uint8_t length) {
    raw_hid_receive_enc(data, length);
    raw_hid_send(data, length);
}
#else
void raw_hid_receive_kb(uint8_t *data, uint8_t length) {
    raw_hid_receive_enc(data, length);
}
#endif

enc_config_flags_t enc_get_config_flags(void) {
    return enc_ctx.cnf.flags;
}

void enc_set_config_flags(enc_config_flags_t flags) {
    memcpy(&enc_ctx.cnf.flags, &flags, sizeof(enc_config_flags_t));
}

enc_mode_t enc_get_mode(void) {
    return enc_ctx.mode;
}

void enc_set_mode(enc_mode_t mode) {
    memcpy(&enc_ctx.mode, &mode, sizeof(enc_mode_t));
}

const char *enc_mode_to_str(uint8_t mode) {
    switch (mode) {
        case ENC_MODE_CLOSED:
            return "CLOSED";
        case ENC_MODE_OPEN:
            return "OPEN";
        case ENC_MODE_LOAD:
            return "LOAD";
        case ENC_MODE_INIT:
            return "INIT";
    }
    return "UNKNOWN";
}

const char *enc_sub_mode_to_str(uint8_t mode) {
    switch (mode) {
        case ENC_SUB_MODE_NONE:
            return "NONE";
        case ENC_SUB_MODE_SEED:
            return "SEED";
        case ENC_SUB_MODE_PASSWORD:
            return "PASSWORD";
        case ENC_SUB_MODE_VERIFY_PASSWORD:
            return "VERIFY PASSWORD";
        case ENC_SUB_MODE_REQUEST:
            return "REQUEST";
        case ENC_SUB_MODE_REQUEST_ALLOW:
            return "REQUEST ALLOW";
        case ENC_SUB_MODE_REQUEST_DENY:
            return "REQUEST DENY";
        case ENC_SUB_MODE_KEY:
            return "KEY";
    }
    return "UNKNOWN";
}

const char *enc_cmd_to_str(uint8_t cmd) {
    switch (cmd) {
        case ENC_CMD_RESET:
            return "Reset";
        case ENC_CMD_ENCRYPT:
            return "Encrypt";
        case ENC_CMD_DECRYPT:
            return "Decrypt";
        case ENC_CMD_MORE_DATA:
            return "More Data";
        case ENC_CMD_UNLOCK:
            return "Unlock";
        case ENC_CMD_LOCK:
            return "Lock";
        case ENC_CMD_SET_CFG:
            return "Set Config";
        case ENC_CMD_GET_MODE:
            return "Get Mode";
        case ENC_CMD_GET_BUFFER:
            return "Get Buffer";
        case ENC_CMD_GET_KEYS:
            return "Get Keys";
        case ENC_CMD_GET_BUFSIZE:
            return "Get Bufsize";
        case ENC_CMD_SET_KEYS:
            return "Set Keys";
        case ENC_CMD_GET_CFG:
            return "Get Config";
        case ENC_CMD_INITIALIZE:
            return "Initialize";
        default:
            return "Unknown";
    }
}

const char *enc_bool_to_str(int val) {
    if (val == ENC_TRUE) {
        return "X";
    }
    return "-";
}

void enc_write_oled(bool invert) {
#ifdef OLED_ENABLE
    for (int i = 0; i < oled_max_lines(); i++) {
        for (int j = 0; j < oled_max_chars(); j++) {
            oled_set_cursor(i, j);
            oled_write_P(PSTR(" "), false);
        }
    }
    oled_set_cursor(0, 0);

    switch (enc_ctx.mode.mode) {
        case ENC_MODE_OPEN:
            oled_write_P(PSTR("E: OPEN"), invert);
            if (enc_ctx.mode.pw_timeout_enabled) {
                oled_write_P(PSTR(" "), invert);
                oled_write(get_u16_str(enc_ctx.mode.pw_timeout, ' '), invert);
                oled_write_P(PSTR("s"), invert);
            }
            oled_write_P(PSTR("\n"), invert);
            break;
        case ENC_MODE_LOAD:
            oled_write_P(PSTR("E: LOAD - Enter Password\n"), invert);
            return;
        case ENC_MODE_INIT:
            oled_write_P(PSTR("E: INIT - "), invert);
            switch (enc_ctx.mode.sub_mode) {
                case ENC_SUB_MODE_SEED:
                    oled_write_P(PSTR("Enter Seed"), invert);
                    break;
                case ENC_SUB_MODE_PASSWORD:
                    oled_write_P(PSTR("Enter Password"), invert);
                    break;
                case ENC_SUB_MODE_VERIFY_PASSWORD:
                    oled_write_P(PSTR("Enter Password again"), invert);
                    break;
                case ENC_SUB_MODE_KEY:
                    oled_write_P(PSTR("Enter Key in hex"), invert);
                    break;
             }
            oled_write_P(PSTR("\n"), invert);
            return;
        default:
            oled_write_P(PSTR("E: CLOSED\n"), invert);
            break;
    }

    if (enc_ctx.mode.sub_mode == ENC_SUB_MODE_REQUEST) {
        oled_write_P(PSTR("E: Allow "), invert);
        oled_write_P(PSTR(enc_cmd_to_str(enc_ctx.mode.req_cmd)), invert);
        oled_write_P(PSTR("?"), invert);
        oled_write(get_u8_str(enc_ctx.mode.req_timeout, ' '), invert);
        oled_write_P(PSTR("s\n"), invert);
        return;
    }

    oled_write_P(PSTR("EF:I P S ME EC TO\n"), invert);
    oled_write_P(PSTR("   "), invert);
    oled_write_P(PSTR(enc_bool_to_str(enc_ctx.cnf.flags.initialized)), invert);
    oled_write_P(PSTR(" "), invert);
    oled_write_P(PSTR(enc_bool_to_str(enc_ctx.cnf.flags.paranoia_mode)), invert);
    oled_write_P(PSTR(" "), invert);
    oled_write_P(PSTR(enc_bool_to_str(enc_ctx.cnf.flags.secure_mode)), invert);
    oled_write(get_u8_str(enc_ctx.cnf.flags.max_error, ' '), invert);
    oled_write(get_u8_str(enc_ctx.cnf.flags.error_count, ' '), invert);
    oled_write(get_u8_str(enc_ctx.cnf.flags.timeout, ' '), invert);
    oled_write_P(PSTR("\n"), invert);
#else
    return;
#endif
}
