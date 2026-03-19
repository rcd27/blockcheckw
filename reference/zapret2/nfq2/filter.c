#include "filter.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

bool pf_match(uint16_t port, const port_filter *pf)
{
	return port && (((!pf->from && !pf->to) || (port>=pf->from && port<=pf->to)) ^ pf->neg);
}
bool pf_parse(const char *s, port_filter *pf)
{
	unsigned int v1,v2;
	char c;

	if (!s) return false;
	if (*s=='*' && s[1]==0)
	{
		pf->from=1; pf->to=0xFFFF;
		pf->neg=false;
		return true;
	}
	if (*s=='~')
	{
		pf->neg=true;
		s++;
	}
	else
		pf->neg=false;
	if (sscanf(s,"%u-%u%c",&v1,&v2,&c)==2)
	{
		if (v1>65535 || v2>65535 || v1>v2) return false;
		pf->from=(uint16_t)v1;
		pf->to=(uint16_t)v2;
	}
	else if (sscanf(s,"%u%c",&v1,&c)==1)
	{
		if (v1>65535) return false;
		pf->to=pf->from=(uint16_t)v1;
	}
	else
		return false;
	// deny all case
	if (!pf->from && !pf->to) pf->neg=true;
	return true;
}

static bool fltmode_parse(const char *s, uint8_t *mode)
{
	if (*s=='*' && !s[1])
	{
		*mode = FLTMODE_ANY;
		return true;
	}
	else if (*s=='-' && !s[1])
	{
		*mode = FLTMODE_SKIP;
		return true;
	}
	*mode = FLTMODE_SKIP;
	return false;
}

bool icf_match(uint8_t type, uint8_t code, const icmp_filter *icf)
{
	return icf->mode==FLTMODE_ANY || icf->mode==FLTMODE_FILTER && icf->type==type && (!icf->code_valid || icf->code==code);
}
bool icf_parse(const char *s, icmp_filter *icf)
{
	unsigned int u1,u2;
	char c1,c2;

	icf->type = icf->code = 0;
	icf->code_valid = false;
	if (fltmode_parse(s, &icf->mode)) return true;
	switch(sscanf(s,"%u%c%u%c",&u1,&c1,&u2,&c2))
	{
		case 1:
			if (u1>0xFF) return false;
			icf->type = (uint8_t)u1;
			icf->mode = FLTMODE_FILTER;
			break;
		case 3:
			if (c1!=':' || (u1>0xFF) || (u2>0xFF)) return false;
			icf->type = (uint8_t)u1;
			icf->code = (uint8_t)u2;
			icf->code_valid = true;
			icf->mode = FLTMODE_FILTER;
			break;
		default:
			icf->mode = FLTMODE_SKIP;
			return false;
	}
	return true;
}

bool ipp_match(uint8_t proto, const ipp_filter *ipp)
{
	return ipp->mode==FLTMODE_ANY || ipp->mode==FLTMODE_FILTER && ipp->proto==proto;
}
bool ipp_parse(const char *s, ipp_filter *ipp)
{
	unsigned int u1;
	char c;

	ipp->proto = 0xFF;
	if (fltmode_parse(s, &ipp->mode)) return true;
	if (sscanf(s,"%u%c",&u1,&c)!=1 || u1>0xFF) return false;
	ipp->proto = (uint8_t)u1;
	ipp->mode = FLTMODE_FILTER;
	return true;
}

bool packet_pos_parse(const char *s, struct packet_pos *pos)
{
	if (*s!='n' && *s!='d' && *s!='s' && *s!='p' && *s!='b' && *s!='x' && *s!='a') return false;
	pos->mode=*s;
	if (pos->mode=='x' || pos->mode=='a')
	{
		pos->pos=0;
		return true;
	}
	return sscanf(s+1,"%u",&pos->pos)==1;
}
bool packet_range_parse(const char *s, struct packet_range *range)
{
	const char *p;

	range->upper_cutoff = false;
	if (*s=='-' || *s=='<')
	{
		range->from = PACKET_POS_ALWAYS;
		range->upper_cutoff = *s=='<';
	}
	else
	{
		if (!packet_pos_parse(s,&range->from)) return false;
		if (range->from.mode=='x')
		{
			range->to = range->from;
			return true;
		}
		if (!(p = strchr(s,'-')))
			p = strchr(s,'<');
		if (p)
		{
			s = p;
			range->upper_cutoff = *s=='<';
		}
		else
		{
			if (range->from.mode=='a')
			{
				range->to = range->from;
				return true;
			}
			return false;
		}
	}
	s++;
	if (*s)
	{
		return packet_pos_parse(s,&range->to);
	}
	else
	{
		range->to = PACKET_POS_ALWAYS;
		return true;
	}
}


void str_cidr4(char *s, size_t s_len, const struct cidr4 *cidr)
{
	char s_ip[INET_ADDRSTRLEN];
	*s_ip=0;
	inet_ntop(AF_INET, &cidr->addr, s_ip, sizeof(s_ip));
	snprintf(s,s_len,cidr->preflen<32 ? "%s/%u" : "%s", s_ip, cidr->preflen);
}
void print_cidr4(const struct cidr4 *cidr)
{
	char s[INET_ADDRSTRLEN+4];
	str_cidr4(s,sizeof(s),cidr);
	printf("%s",s);
}
void str_cidr6(char *s, size_t s_len, const struct cidr6 *cidr)
{
	char s_ip[INET6_ADDRSTRLEN];
	*s_ip=0;
	inet_ntop(AF_INET6, &cidr->addr, s_ip, sizeof(s_ip));
	snprintf(s,s_len,cidr->preflen<128 ? "%s/%u" : "%s", s_ip, cidr->preflen);
}
void print_cidr6(const struct cidr6 *cidr)
{
	char s[INET6_ADDRSTRLEN+4];
	str_cidr6(s,sizeof(s),cidr);
	printf("%s",s);
}
bool parse_cidr4(char *s, struct cidr4 *cidr)
{
	char *p,d;
	bool b;
	unsigned int plen;

	if ((p = strchr(s, '/')))
	{
		if (sscanf(p + 1, "%u", &plen)!=1 || plen>32)
			return false;
		cidr->preflen = (uint8_t)plen;
		d=*p; *p=0; // backup char
	}
	else
		cidr->preflen = 32;
	b = (inet_pton(AF_INET, s, &cidr->addr)==1);
	if (p) *p=d; // restore char
	return b;
}
bool parse_cidr6(char *s, struct cidr6 *cidr)
{
	char *p,d;
	bool b;
	unsigned int plen;

	if ((p = strchr(s, '/')))
	{
		if (sscanf(p + 1, "%u", &plen)!=1 || plen>128)
			return false;
		cidr->preflen = (uint8_t)plen;
		d=*p; *p=0; // backup char
	}
	else
		cidr->preflen = 128;
	b = (inet_pton(AF_INET6, s, &cidr->addr)==1);
	if (p) *p=d; // restore char
	return b;
}
