#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

typedef struct
{
	uint16_t from,to;
	bool neg;
} port_filter;
bool pf_match(uint16_t port, const port_filter *pf);
bool pf_parse(const char *s, port_filter *pf);

#define FLTMODE_SKIP 0
#define FLTMODE_ANY 1
#define FLTMODE_FILTER 2
typedef struct
{
	uint8_t mode, type, code;
	bool code_valid;
} icmp_filter;
bool icf_match(uint8_t type, uint8_t code, const icmp_filter *icf);
bool icf_parse(const char *s, icmp_filter *icf);

typedef struct
{
	uint8_t mode, proto;
} ipp_filter;
bool ipp_match(uint8_t proto,  const ipp_filter *ipp);
bool ipp_parse(const char *s, ipp_filter *ipp);

struct packet_pos
{
	char mode; // n - packets, d - data packets, s - relative sequence
	unsigned int pos;
};
struct packet_range
{
	struct packet_pos from, to;
	bool upper_cutoff; // true - do not include upper limit, false - include upper limit
};
#define PACKET_POS_NEVER (struct packet_pos){'x',0}
#define PACKET_POS_ALWAYS (struct packet_pos){'a',0}
#define PACKET_RANGE_NEVER (struct packet_range){PACKET_POS_NEVER,PACKET_POS_NEVER}
#define PACKET_RANGE_ALWAYS (struct packet_range){PACKET_POS_ALWAYS,PACKET_POS_ALWAYS}
bool packet_range_parse(const char *s, struct packet_range *range);

struct cidr4
{
	struct in_addr addr;
	uint8_t	preflen;
};
struct cidr6
{
	struct in6_addr addr;
	uint8_t	preflen;
};
void str_cidr4(char *s, size_t s_len, const struct cidr4 *cidr);
void print_cidr4(const struct cidr4 *cidr);
void str_cidr6(char *s, size_t s_len, const struct cidr6 *cidr);
void print_cidr6(const struct cidr6 *cidr);
bool parse_cidr4(char *s, struct cidr4 *cidr);
bool parse_cidr6(char *s, struct cidr6 *cidr);
