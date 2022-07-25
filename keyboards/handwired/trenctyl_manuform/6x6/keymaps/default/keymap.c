#include QMK_KEYBOARD_H

#include "pointing_device.h"

#include "quantum_keycodes.h"
#include "transactions.h"
/*#include "enc.h"*/

#define _QWERTZ 0
#define _CONTROL 1
#define _I3WM 2
#define _MOUSE 3

#define QWERTZ TO(_QWERTZ)
#define CONTROL TT(_CONTROL)
#define I3WM TT(_I3WM)
#define MOUSE TG(_MOUSE)

#ifdef RGB_MATRIX_ENABLE
// clang-format off
led_config_t g_led_config = {{
    {      0,      5,   10,     16,     22,     30,  },
    {      1,      6,   11,     17,     23,     31,  },
    {      2,      7,   12,     18,     24,     32,  },
    {      3,      8,   13,     19,     25,     33,  },
    {      4,      9,   14,     20,     26,     34,  },
    { NO_LED, NO_LED,   15,     21,     27,     35,  },
    { NO_LED, NO_LED,   29,     37,     28,     36,  },
    // RIGHT HALF
    {   38,     45,     52,     58,     64,     69 },
    {   39,     46,     53,     59,     65,     70 },
    {   40,     47,     54,     60,     66,     71 },
    {   41,     48,     55,     61,     67,     72 },
    {   42,     49,     56,     62,     68,     73 },
    {   43,     50,     57,     63, NO_LED, NO_LED },
    {   44,     51, NO_LED, NO_LED, NO_LED, NO_LED },
}, {
    {   0,  0 }, {   0,  8 }, {   0, 19 }, {   0, 30 }, {   0, 41 },
    {  20,  0 }, {  20,  8 }, {  20, 19 }, {  20, 30 }, {  20, 41 },
    {  40,  0 }, {  40,  8 }, {  40, 19 }, {  40, 30 }, {  40, 41 }, {  40, 52 },
    {  60,  0 }, {  60,  8 }, {  60, 19 }, {  60, 30 }, {  60, 41 }, {  60, 52 },
    {  80,  0 }, {  80,  8 }, {  80, 19 }, {  80, 30 }, {  80, 41 }, {  80, 52 }, {  80, 64 },
    {  40, 64 },
    { 100,  0 }, { 100,  8 }, { 100, 19 }, { 100, 30 }, { 100, 41 }, { 100, 52 }, { 100, 64 },
    {  60, 64 },
    // RIGHT HALF
    { 120,  0 }, { 120,  8 }, { 120, 19 }, { 120, 30 }, { 120, 41 }, { 120, 52 }, { 120, 64 },
    { 140,  0 }, { 140,  8 }, { 140, 19 }, { 140, 30 }, { 140, 41 }, { 140, 52 }, { 140, 64 },
    { 160,  0 }, { 160,  8 }, { 160, 19 }, { 160, 30 }, { 160, 41 }, { 160, 52 },
    { 180,  0 }, { 180,  8 }, { 180, 19 }, { 180, 30 }, { 180, 41 }, { 180, 52 },
    { 200,  0 }, { 200,  8 }, { 200, 19 }, { 200, 30 }, { 200, 41 },
    { 224,  0 }, { 224,  8 }, { 224, 19 }, { 224, 30 }, { 224, 41 }
 }, {
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
          4, 4,
                4, 4,
                4, 4,
                4, 4,
    /*4, 4, 4, 4, 4, 4,*/
    // RIGHT HALF
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
          4, 4,
    4, 4,
    4, 4,
    /*4, 4, 4, 4, 4, 4,*/
}};
#endif

enum my_keycodes {
    CPI_NEXT = SAFE_RANGE,
    CPI_PREV,
    VIS_VAD,
    VIS_VAI
};

const uint16_t PROGMEM keymaps[][MATRIX_ROWS][MATRIX_COLS] = {
    [_QWERTZ] = LAYOUT_6x6(
        KC_F1  , KC_F2 , KC_F3 , KC_F4 , KC_F5 , KC_F6 ,                         KC_F7 , KC_F8 , KC_F9 ,KC_F10 ,KC_F11 ,KC_F12 ,
        KC_GRV , KC_1  , KC_2  , KC_3  , KC_4  , KC_5  ,                         KC_6  , KC_7  , KC_8  , KC_9  , KC_0  ,KC_BSPC,
        KC_TAB , KC_Q  , KC_W  , KC_E  , KC_R  , KC_T  ,                         KC_Y  , KC_U  , KC_I  , KC_O  , KC_P  ,KC_LBRC,
        KC_LCTL, KC_A  , KC_S  , KC_D  , KC_F  , KC_G  ,                         KC_H  , KC_J  , KC_K  , KC_L  ,KC_SCLN,KC_QUOT,
        OSM(MOD_LSFT), KC_Z  , KC_X  , KC_C  , KC_V  , KC_B  ,                   KC_N  , KC_M  ,KC_DOT,KC_COMM ,KC_SLSH,KC_BSLASH,
                 KC_MUTE,KC_RBRC,KC_MINS,                                                       KC_NUBS, KC_EQL,
                                         KC_LALT,KC_ENT,                        KC_SPC, KC_RALT,
                                         KC_ESC,I3WM,                           KC_LGUI,MOUSE,
                                         MOUSE,CONTROL
    ),

    [_CONTROL] = LAYOUT_6x6(
        ENC_INIT,ENC_LOAD,ENC_CLOSE,ENC_KEY,_______,_______,                   ENC_REQ_ALLOW,ENC_REQ_DENY,_______,_______,_______,EEP_RST,
        _______,_______,_______,_______,_______,_______,                     _______,_______,_______,_______,_______,KC_DEL,
        _______,_______,KC_PGDN,KC_UP,KC_PGUP,_______,                       _______,KC_7,KC_8,KC_9,_______,_______,
        _______,_______,KC_LEFT,KC_DOWN,KC_RGHT,_______,                     KC_HOME,KC_4,KC_5,KC_6,KC_END,_______,
        _______,_______,_______,_______,_______,_______,                     _______,KC_1,KC_2,KC_3,VIS_VAD,_______,
                _______,VIS_VAI,_______,                                               KC_0,_______,
                                                RGB_MOD,RGB_RMOD,           KC_ENT,RGB_VAI,
                                                RGB_SPD,RGB_SPI,            RGB_VAD,RGB_TOG,
                                                QWERTZ,_______
    ),

    [_I3WM] = LAYOUT_6x6(
        _______,_______,_______,_______,_______,_______,                        _______,_______,_______,_______,_______,_______,
        _______,LGUI(KC_1),LGUI(KC_2),LGUI(KC_3),LGUI(KC_4),LGUI(KC_5),         LGUI(KC_6),LGUI(KC_7),LGUI(KC_8),LGUI(KC_9),LGUI(KC_0),_______,
        _______,SGUI(KC_C),LGUI(KC_W),LGUI(KC_E),_______,_______,               LGUI(KC_Y),_______,LGUI(KC_I),_______,LGUI(KC_P),_______,
        _______,LGUI(KC_ENT),LGUI(KC_S),LGUI(KC_D),_______,_______,             LGUI(KC_H),LGUI(KC_J),LGUI(KC_K),LGUI(KC_L),_______,_______,
        _______,_______,_______,LGUI(KC_C),_______,_______,                     LAG(KC_N),_______,_______,_______,_______,_______,
                _______,_______,_______,                                                       _______,_______,
                                        _______,_______,                        LGUI(KC_ENT),_______,
                                        _______,_______,                        _______,_______,
                                        QWERTZ,_______
    ),

    [_MOUSE] = LAYOUT_6x6(
        _______,_______,_______,_______,_______,_______,                       _______,_______,_______,_______,_______,_______,
        _______,_______,_______,_______,_______,_______,                       _______,_______,_______,_______,_______,_______,
        _______,_______,_______,_______,_______,_______,                       _______,_______,_______,_______,_______,_______,
        _______,_______,KC_MS_BTN2,KC_MS_BTN3,KC_MS_BTN1,_______,                       _______,_______,_______,_______,_______,_______,
        _______,_______,_______,_______,_______,_______,                       _______,KC_MS_BTN1,KC_MS_BTN3,KC_MS_BTN2,_______,_______,
                _______,_______,_______,                                               KC_MS_WH_DOWN,KC_MS_WH_UP,
                                                _______,_______,               KC_SPC,CPI_NEXT,
                                                _______,_______,               CPI_PREV,QWERTZ,
                                                _______,QWERTZ
    ),

};

#ifdef OLED_ENABLE

#include <stdio.h>

int get_val_percent(void) {
#ifdef RGB_MATRIX_MAXIMUM_BRIGHTNESS
    uint8_t maxVal = RGB_MATRIX_MAXIMUM_BRIGHTNESS;
#else
    uint8_t maxVal = 255;
#endif
    uint8_t actVal = rgb_matrix_get_val();

    float ret = ((float) 100)/((float) maxVal)*((float)actVal);

    return ((int) ret);
}

int get_speed_percent(void) {
    uint8_t maxVal = 255;
    uint8_t actVal = rgb_matrix_get_speed();

    float ret = ((float) 100)/((float) maxVal)*((float)actVal);

    return ((int) ret);
}

#ifdef POINTING_DEVICE_ENABLE
static uint16_t _cpi;
#endif

static uint8_t _vis_timeout_sec;
static uint32_t _vis_timer;
static bool _vis_status;

bool oled_task_user(void) {
    // Host Keyboard Layer Status
    if(is_keyboard_master()) {
        uint32_t _oled_timeout = ((_vis_timeout_sec * 1000) - timer_elapsed32(_vis_timer)) / 1000;
        if (!_vis_status) {
            // turn displays off
            oled_off();
            return true;
        }

        oled_write_P(PSTR("L: "), false);

        switch (get_highest_layer(layer_state)) {
            case _QWERTZ:
                oled_write_P(PSTR("Quertz\n"), false);
                break;
            case _CONTROL:
                oled_write_P(PSTR("Control\n"), false);
                break;
            case _I3WM:
                oled_write_P(PSTR("I3WM\n"), false);
                break;
            case _MOUSE:
                oled_write_P(PSTR("MOUSE\n"), false);
                break;
            default:
                oled_write_P(PSTR("Undefined\n"), false);
        }

        char brightness[100];
        memset(brightness, 0x00, 100);
        if (rgb_matrix_is_enabled()) {
            snprintf(brightness, 100, "B: %d%% S: %d%%\n", get_val_percent(), get_speed_percent());
        } else {
            snprintf(brightness, 100, "B: OFF\n");
        }
        oled_write_P(PSTR(brightness), false);

#ifdef POINTING_DEVICE_ENABLE
        switch(_cpi) {
            case 100:
                oled_write_P(PSTR("M: >\n"), false);
                break;
            case 200:
                oled_write_P(PSTR("M: >>\n"), false);
                break;
            case 400:
                oled_write_P(PSTR("M: >>>\n"), false);
                break;
            case 500:
                oled_write_P(PSTR("M: >>>>\n"), false);
                break;
            case 600:
                oled_write_P(PSTR("M: >>>>>\n"), false);
                break;
        }
#endif

        oled_write_P(PSTR("V: "), false);
        oled_write_P(get_u8_str(_oled_timeout, ' '), false);
        oled_write_P(PSTR("s\n"), false);
    } else {
#ifdef ENC_ENABLE
        enc_write_oled(false);
#endif
        oled_write_P(PSTR("L: "), false);

        switch (get_highest_layer(layer_state)) {
            case _QWERTZ:
                oled_write_P(PSTR("Quertz\n"), false);
                break;
            case _CONTROL:
                oled_write_P(PSTR("Control\n"), false);
                break;
            case _I3WM:
                oled_write_P(PSTR("I3WM\n"), false);
                break;
            case _MOUSE:
                oled_write_P(PSTR("MOUSE\n"), false);
                break;
            default:
                oled_write_P(PSTR("Undefined\n"), false);
        }
    }

    return true;
}
#endif


#ifdef POINTING_DEVICE_ENABLE

void pointing_device_init_user(void) {
    _cpi = 400;

    pointing_device_set_cpi(_cpi);
}

void _cpi_next(void) {
    switch(_cpi) {
        case 100:
            _cpi = 200;
            break;
        case 200:
            _cpi = 400;
            break;
        case 400:
            _cpi = 500;
            break;
        case 500:
            _cpi = 600;
            break;
        case 600:
            _cpi = 100;
            break;
    }

    pointing_device_set_cpi(_cpi);
}

void _cpi_prev(void) {
    switch(_cpi) {
        case 100:
            _cpi = 600;
            break;
        case 200:
            _cpi = 100;
            break;
        case 400:
            _cpi = 200;
            break;
        case 500:
            _cpi = 400;
            break;
        case 600:
            _cpi = 500;
            break;
    }

    pointing_device_set_cpi(_cpi);
}

report_mouse_t pointing_device_task_user(report_mouse_t mouse_report) {
    if (!layer_state_is(_MOUSE)) {
        mouse_report.h = 0;
        mouse_report.v = 0;
        mouse_report.x = 0;
        mouse_report.y = 0;
    }
    return mouse_report;
}
#endif

void rgb_matrix_indicators_advanced_user(uint8_t led_min, uint8_t led_max) {
    if (!_vis_status) {
        return;
    }

    HSV hsv = (HSV){0, 0, 0};
    HSV hsv_alt = (HSV){0, 0, 0};
    bool led_off = false;
    bool led_alt = false;

    switch(get_highest_layer(layer_state)) {  // special handling per layer
        case _CONTROL:
            hsv = (HSV){0, 255, 255};
            break;
        case _I3WM:
            hsv = (HSV){85, 255, 255};
            break;
        case _MOUSE:
            hsv = (HSV){170, 255, 255};
            led_off = true;
            break;
        default:
            return;
    }

    hsv.v = rgb_matrix_get_val();
    RGB rgb = hsv_to_rgb(hsv);
    hsv_alt.v = rgb_matrix_get_val();
    RGB rgb_alt = hsv_to_rgb(hsv_alt);

    for (uint8_t row=0; row<MATRIX_ROWS; ++row) {
        for (uint8_t col=0; col<MATRIX_COLS; ++col) {
            uint8_t index = g_led_config.matrix_co[row][col];

            if (index >= led_min && index <= led_max && index != NO_LED) {
                if (keymap_key_to_keycode(get_highest_layer(layer_state), (keypos_t){col, row}) > KC_TRNS) {
                    rgb_matrix_set_color(index, rgb.r, rgb.g, rgb.b);
                } else {
                    if (led_alt) {
                        rgb_matrix_set_color(index, rgb_alt.r, rgb_alt.g, rgb_alt.b);
                        continue;
                    }
                    if (led_off) {
                        rgb_matrix_set_color(index, 0, 0, 0);
                    }
                }
            }
        }
    }
}

typedef struct _vis_status {
    bool m2s_data;
} vis_status_t;

void user_sync_vis_status_slave_handler(uint8_t in_buflen, const void* in_data, uint8_t out_buflen, void* out_data) {
    const vis_status_t *m2s = (const vis_status_t*)in_data;
    _vis_status = m2s->m2s_data;
}

bool process_record_user(uint16_t keycode, keyrecord_t *record) {
    if (is_keyboard_master()) {
        _vis_timer = timer_read32();
    }

    switch (keycode) {
#ifdef POINTING_DEVICE_ENABLE
        case CPI_PREV:
            if (record->event.pressed) {
                _cpi_prev();
            }
            return false;
        case CPI_NEXT:
            if (record->event.pressed) {
                _cpi_next();
            }
            return false;
#endif
        case VIS_VAD:
            if (record->event.pressed) {
                _vis_timeout_sec -= 10;
            }
            return false;
        case VIS_VAI:
            if (record->event.pressed) {
                _vis_timeout_sec += 10;
            }
            return false;
        default:
            return true;
    }
}

bool encoder_update_user(uint8_t index, bool clockwise) {
    switch(index) {
        case 0:
            if(clockwise) {
                tap_code_delay(KC_VOLU, 10);
            } else {
                tap_code_delay(KC_VOLD, 10);
            }
            break;
    }
    return false;
}

void keyboard_pre_init_user(void) {
    _vis_status = true;
    _vis_timeout_sec = 120;
    _vis_timer = timer_read32();
    pre_init_enc();
}

void eeconfig_init_user(void) {
    eeconfig_init_enc();
}

void keyboard_post_init_user(void) {
    transaction_register_rpc(USER_SYNC_VIS_STATUS, user_sync_vis_status_slave_handler);
}

void housekeeping_task_user(void) {
    if (is_keyboard_master()) {
        if (timer_elapsed32(_vis_timer) >= (_vis_timeout_sec * 1000)) {
            _vis_status = false;
        } else {
            _vis_status = true;
        }
        static uint32_t last_sync = 0;
        if (timer_elapsed32(last_sync) > 500) {
            vis_status_t m2s = {_vis_status};
            if (transaction_rpc_send(USER_SYNC_VIS_STATUS, sizeof(m2s), &m2s)) {
                last_sync = timer_read32();
            }
        }
    }

    if (!_vis_status) {
        rgb_matrix_set_color_all(0, 0, 0);
    }
}
