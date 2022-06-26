ifneq ($(filter %_STM32F401xC %_STM32F401xE %_STM32F405xG %_STM32F411xE, %_STM32F412xB, $(MCU_SERIES)_$(MCU_LDSCRIPT)),)
  SRC += enc_stm32f40xx_stm32f41xx.c
endif
