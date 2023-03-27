/*
Copyright 2012 Jun Wako <wakojun@gmail.com>
Copyright 2015 Jack Humbert

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "config_common.h"

// #define PRODUCT_ID 0x3836
// #define DEVICE_VER 0x0001
// #define PRODUCT Trenctyl Manuform(6x6) BlackPill F01

#define MATRIX_ROW_PINS \
    { A15, B13, B14, B15, A8, B6, B7 }
#define MATRIX_COL_PINS \
    { B10, B0, A1, A0, B4, C14 }

#define MATRIX_ROW_PINS_RIGHT \
    { A15, B13, B14, B15, A8, B6, B7 }
#define MATRIX_COL_PINS_RIGHT \
    { B1, B0, A1, A0, B4, C14 }

#define DIODE_DIRECTION ROW2COL

#define RGB_DI_PIN B3
#define RGBLED_NUM 74
#define DRIVER_LED_TOTAL 74
#define RGB_MATRIX_LED_COUNT 74

#define RGBLIGHT_SPLIT
#define RGBLED_SPLIT \
    { 38, 36 }
#define RGBLIGHT_LIMIT_VAL 200
#define RGB_MATRIX_MAXIMUM_BRIGHTNESS 200
#define RGB_MATRIX_SPLIT \
    { 38, 36 }
#define RGB_MATRIX_CENTER \
    { 110, 19 }

#define SERIAL_USART_RX_PIN A2
#define SELECT_SOFT_SERIAL_SPEED 1
#define FORCED_SYNC_THROTTLE_MS 200
#define SERIAL_USART_DRIVER SD2
#define SERIAL_USART_TX_PAL_MODE 7
#define SERIAL_USART_RX_PAL_MODE 7
#define SERIAL_USART_TIMEOUT 10
#define I2C1_SCL_PIN B8
#define I2C1_SDA_PIN B9

#define PMW33XX_CS_PIN A4

#define SPI_DRIVER SPID1
#define SPI_SCK_PIN A5
#define SPI_SCK_PAL_MODE 5
#define SPI_MOSI_PIN A7
#define SPI_MOSI_PAL_MODE 5
#define SPI_MISO_PIN A6
#define SPI_MISO_PAL_MODE 5

#define ENCODERS_PAD_A \
    { C13 }
#define ENCODERS_PAD_B \
    { C15 }

#define WS2812_PWM_DRIVER PWMD2
#define WS2812_PWM_CHANNEL 2
#define WS2812_DMA_STREAM STM32_DMA1_STREAM7
#define WS2812_DMA_CHANNEL 3
#define WS2812_PWM_PAL_MODE 1

// hw rnd generator
// #define ENC_HW_RND_STM32F4
