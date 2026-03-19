#pragma once

#include "darkmagic.h"

#include <stdint.h>
#include <stdbool.h>

#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#ifdef __linux__
#define DPI_DESYNC_FWMARK_DEFAULT 0x40000000
#elif defined(SO_USER_COOKIE)
#define DPI_DESYNC_FWMARK_DEFAULT 512
#else
#define DPI_DESYNC_FWMARK_DEFAULT 0
#endif

uint8_t dpi_desync_packet(uint32_t fwmark, const char *ifin, const char *ifout, const uint8_t *data_pkt, size_t len_pkt, uint8_t *mod_pkt, size_t *len_mod_pkt);
