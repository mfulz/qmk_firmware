#pragma once

#ifdef ENC_OPTLOCK
#   undef ENC_OPTLOCK
#endif

#if defined(STM32F401xx) || defined(STMF411xx)
#   define ENC_OPTLOCK
#endif

#ifdef ENC_OPTLOCK
    void enc_flash_lock(void);
    int enc_is_flash_locked(void);
#endif
