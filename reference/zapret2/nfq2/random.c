#include "random.h"

#ifdef NEED_GETRANDOM

#include <unistd.h>

#ifndef SYS_getrandom

#if defined(__aarch64__)
    #define SYS_getrandom 278

#elif defined(__arm__)
    /* ARM EABI */
    #define SYS_getrandom 384

#elif defined(__x86_64__)
    #define SYS_getrandom 318

#elif defined(__i386__)
    #define SYS_getrandom 355

#elif defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI32
    #define SYS_getrandom 4353

#else
    #error "Unsupported architecture: SYS_getrandom not defined"
#endif

#endif

ssize_t getrandom(void *ptr, size_t len, unsigned int flags)
{
	return syscall(SYS_getrandom, ptr, len, flags);
}

#endif
