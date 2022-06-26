#include "hal.h"
#include "enc.h"

#define FLASH_OPTKEY1 0x08192A3B
#define FLASH_OPTKEY2 0x4C5D6E7F

static inline void OPT_WaitNotBusy(void) {
    uint32_t sr = 0;
    for (sr = FLASH->SR; sr & FLASH_SR_BSY; sr = FLASH->SR) {
        __WFI();
    }
}

static inline void OPT_Unlock(void) {
    OPT_WaitNotBusy();
    if (FLASH->OPTCR & FLASH_OPTCR_OPTLOCK) {
        FLASH->OPTKEYR = FLASH_OPTKEY1;
        FLASH->OPTKEYR = FLASH_OPTKEY2;
    }
}

static inline void OPT_Lock(void) {
    OPT_WaitNotBusy();
    FLASH->OPTCR |= FLASH_OPTCR_OPTLOCK;
}

static inline void OPT_Set(uint32_t OptionBytes) {
    __IO uint32_t *optionBytes = &(FLASH->OPTCR);
    if (*optionBytes != OptionBytes) {
        OPT_Unlock();
        *optionBytes = OptionBytes;
        FLASH->OPTCR |= FLASH_OPTCR_OPTSTRT;
        OPT_Lock();
        /*NVIC_SystemReset();*/
    }
}

bool enc_is_flash_locked(void) {
    if (FLASH->OPTCR & FLASH_OPTCR_RDP) {
        return ENC_TRUE;
    }
    return ENC_FALSE;
}

void enc_flash_lock(void) {
    OPT_Unlock();
    FLASH->OPTCR |= FLASH_OPTCR_RDP;
    FLASH->OPTCR |= FLASH_OPTCR_OPTSTRT;
    OPT_Lock();
    /*NVIC_SystemReset();*/
}
