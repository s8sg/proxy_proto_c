#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "proxy_ptc.h"

#define GET_NEXT_WORD() \
	word = pp_strtok(NULL, " ", &saveptr); \
	if (!word) { \
		return PPHDRERR; \
	}

/* get_addr_family() : determine addr family and return
 * I/P
 * addr              : sockaddr_storage address (IPv4/IPv6)
 * O/P
 * ret               : AF_INET/AF_INET6, on error 0
 */
uint8_t get_addr_family(struct sockaddr_storage *addr) {
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	sin = (struct sockaddr_in *)addr;
	if(sin->sin_family == AF_INET) {
		return AF_INET;
	}
	sin6 = (struct sockaddr_in6 *)addr;
	if(sin6->sin6_family == AF_INET6) {
		return AF_INET6;
	}
	return 0;
}

struct in_addr get_inet4_ip(struct sockaddr_storage *addr) {
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *)addr;
	return sin->sin_addr;
}

struct in6_addr get_inet6_ip(struct sockaddr_storage *addr) {
	struct sockaddr_in6 *sin6;

	sin6 = (struct sockaddr_in6 *)addr;
	return sin6->sin6_addr;
}

uint8_t get_inet4_port(struct sockaddr_storage *addr) {
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *)addr;
	return sin->sin_port;
}

uint16_t get_inet6_port(struct sockaddr_storage *addr) {
	struct sockaddr_in6 *sin6;

	sin6 = (struct sockaddr_in6 *)addr;
	return sin6->sin6_port;
}

static char * pp_strtok(char *str, const char *sep, char **last) {
	char *token;

	if (!str)           /* subsequent call */
		str = *last;    /* start where we left off */

	/* skip characters in sep (will terminate at '\0') */
	while (*str && strchr(sep, *str))
		++str;

	if (!*str)          /* no more tokens */
		return NULL;

	token = str;

	/* skip valid token characters to terminate token and
	 * prepare for the next call (will terminate at '\0)
	 * */
	*last = token + 1;
	while (**last && !strchr(sep, **last))
		++*last;

	if (**last) {
		**last = '\0';
		++*last;
	}

	return token;
}

/* proxy_ptc_v1_encode() : encode a proxy protocol header based
 *                         on v1 specification
 * I/P     
 * buf                : buffer where encoded header will be
 *                      placed
 * len                : total length of the header
 * src                : src address
 * dst                : dst address
 *
 * O/P
 * return             : 0 if success else errors in pp_ret_t
 */
pp_ret_t proxy_ptc_v1_encode(char *buf, int8_t *len,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst) {
	uint8_t fam;

	fam = get_addr_family(dst);
	switch(fam) {
		case AF_INET: /* TCPv4 */
			sprintf(buf, "PROXY TCP4 %s %s %d %d", inet_ntoa(get_inet4_ip(src)),
							       inet_ntoa(get_inet4_ip(dst)),
							       get_inet4_port(src),
							       get_inet4_port(dst));
			*len = strlen(buf);
			// put terminating char '\r\n'
			buf[*len] = '\r';
			buf[*len + 1] = '\n';
			*len = *len + 2;
			break;
		case AF_INET6: /* TCPv6 */
			*len = 0;
			break;
		default:
			return PPINVALFAM;
	}
	return PPNOERR;
}

/* proxy_ptc_v2_encode() : encode a proxy protocol header based
 *                         on v2 specification
 * I/P     
 * buf                : buffer where encoded header will be
 *                      placed
 * len                : total length of the header
 * src                : src address
 * dst                : dst address
 *
 * O/P
 * return             : 0 if success else errors in pp_ret_t
 */
pp_ret_t proxy_ptc_v2_encode(char *buf, int8_t *len,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst) {
	uint8_t fam;
	pproxy_v2_t *pp_hdr;

	memcpy(pp_hdr->sig, v2sig, sizeof(pp_hdr->sig));
	pp_hdr->ver_cmd = vercmd;

	fam = get_addr_family(dst);
	switch(fam) {
		case AF_INET: /* TCPv4 */
			pp_hdr->fam = 0x11;
			pp_hdr->len = htons(IPV4_ADDR_LEN);
			pp_hdr->addr.ip4.src_addr = (get_inet4_ip(src)).s_addr;
			pp_hdr->addr.ip4.dst_addr = (get_inet4_ip(dst)).s_addr;
			pp_hdr->addr.ip4.src_port = htons(get_inet4_port(src));
			pp_hdr->addr.ip4.dst_port = htons(get_inet4_port(dst));
			*len = V2_HDR_LEN + IPV4_ADDR_LEN;
			break;
		case AF_INET6: /* TCPv6 */
			*len = 0;
			break;
		default:
			return PPINVALFAM;
	}
	return PPNOERR;
}

/* proxy_ptc_decode() : decode a proxy protocol header from
 *                      provided pkt buffer
 * I/P     
 * buf                : buffer where pkt has been received
 * len                : total length of the pkt
 * ppver              : ppver to set the version received
 * src                : src address to fill the src addr
 * dst                : dst address to fill the dest addr
 *
 * O/P
 * return             : total header size if success else 
 *                      errors in pp_ret_t
 */
pp_ret_t proxy_ptc_decode(char *buf, int8_t len,
			  pproxy_ver_t *ppver,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst) {
	int size;
	pproxy_hdr_t *hdr;

	hdr = (pproxy_hdr_t *)hdr;
	if(len >= V2_HDR_LEN && memcmp(hdr->v2.sig, v2sig, 12) == 0 &&
			        (hdr->v2.ver_cmd & 0xF0) == 0x20) {
		*ppver = PPROXY_V2;
		size = 16 + ntohs(hdr->v2.len);
		if (len < size) {
			return PPTRUNCATED;
		}
		switch(hdr->v2.ver_cmd & 0xF) {
			case 0x01: /* PROXY command */
				switch(hdr->v2.fam) {
					case 0x11: /* TCPv4 */
						((struct sockaddr_in *)src)->sin_family = AF_INET;
						((struct sockaddr_in *)src)->sin_addr.s_addr =
							hdr->v2.addr.ip4.src_addr;
						((struct sockaddr_in *)src)->sin_port =
							hdr->v2.addr.ip4.src_port;
						((struct sockaddr_in *)dst)->sin_family = AF_INET;
						((struct sockaddr_in *)dst)->sin_addr.s_addr =
							hdr->v2.addr.ip4.dst_addr;
						((struct sockaddr_in *)dst)->sin_port =
							hdr->v2.addr.ip4.dst_port;
						break;
					case 0x21:  /* TCPv6 */
						((struct sockaddr_in6 *)src)->sin6_family = AF_INET6;
						memcpy(&((struct sockaddr_in6 *)src)->sin6_addr,
							hdr->v2.addr.ip6.src_addr, 16);
						((struct sockaddr_in6 *)src)->sin6_port =
							hdr->v2.addr.ip6.src_port;
						((struct sockaddr_in6 *)dst)->sin6_family = AF_INET6;
						memcpy(&((struct sockaddr_in6 *)dst)->sin6_addr,
								hdr->v2.addr.ip6.dst_addr, 16);
						((struct sockaddr_in6 *)dst)->sin6_port =
							hdr->v2.addr.ip6.dst_port;
						break;
				}
				break;
			case 0x00: /* LOCAL command */
				return PPLOCALCMD; 
			default:
				return PPINVALCMD;
		}
	} else if (len >= 8 && memcmp(hdr->v1.line, "PROXY", 5) == 0) {
		char *end = memchr(hdr->v1.line, '\r', len - 1);
		char buf[sizeof(hdr->v1.line)];
		char *word, *saveptr, *valid_addr_chars, *srcip, *dstip;
		uint16_t srcport, dstport;
		int family;
		

		*ppver = PPROXY_V1;
		if (!end || end[1] != '\n')
			return PPTRUNCATED;
		*end = '\0';
		size = end + 2 - hdr->v1.line;
		strcpy(buf, hdr->v1.line);
		
		pp_strtok(buf, " ", &saveptr);

		GET_NEXT_WORD()
		if (strcmp(word, "UNKNOWN") == 0) { /* LOCAL command */
			return PPLOCALCMD;
		}
		else if (strcmp(word, "TCP4") == 0) {
			family = AF_INET;
			valid_addr_chars = "0123456789.";
		}
		else if (strcmp(word, "TCP6") == 0) {
			family = AF_INET6;
			valid_addr_chars = "0123456789abcdefABCDEF:";
		}
		else {
			return PPHDRERR;
		}

		GET_NEXT_WORD()
		if (strspn(word, valid_addr_chars) != strlen(word)) {
			return PPINVALADDR;
		}
		srcip = word;

		GET_NEXT_WORD()
		if (strspn(word, valid_addr_chars) != strlen(word)) {
			return PPINVALADDR;
		}
		dstip = word;

		GET_NEXT_WORD()
		if (sscanf(word, "%hu", &srcport) != 1) {
			return PPHDRERR;
		}

		GET_NEXT_WORD()
		if (sscanf(word, "%hu", &dstport) != 1) {
			return PPHDRERR;
		}

		switch(family) {
			case AF_INET:
				((struct sockaddr_in *)src)->sin_family = AF_INET;
				inet_pton(AF_INET, srcip, &(((struct sockaddr_in *)src)->sin_addr));
				((struct sockaddr_in *)src)->sin_port = (uint8_t)srcport;
				((struct sockaddr_in *)dst)->sin_family = AF_INET;
				inet_pton(AF_INET, dstip, &(((struct sockaddr_in *)dst)->sin_addr));
				((struct sockaddr_in *)dst)->sin_port = (uint8_t)dstport;
				break;
			case AF_INET6:
				((struct sockaddr_in6 *)src)->sin6_family = AF_INET6;
				inet_pton(AF_INET6, srcip, &(((struct sockaddr_in6 *)src)->sin6_addr));
				((struct sockaddr_in6 *)src)->sin6_port = srcport;
				((struct sockaddr_in6 *)dst)->sin6_family = AF_INET6;
				inet_pton(AF_INET6, dstip, &(((struct sockaddr_in6 *)dst)->sin6_addr));
				((struct sockaddr_in6 *)dst)->sin6_port = dstport;
		}
	} else {
		/* invalid protocol */
		return PPHDRERR; 
	}

	return size;
}

/* proxy_ptc_decode() : read packet and decode a proxy protocol 
 *                      header from provided sock fd
 * I/P     
 * fd                 : the file desc to read from
 * ppver              : ppver to set the version received
 * src                : src address to fill the src addr
 * dst                : dst address to fill the dest addr
 *
 * O/P
 * return             : 0 if success else errors in pp_ret_t
 */
pp_ret_t proxy_ptc_read_decode(int fd,
			       pproxy_ver_t *ppver,
		               struct sockaddr_storage *src,
			       struct sockaddr_storage *dst) {
	int ret;
	pproxy_hdr_t hdr;
	do {
		ret = recv(fd, &hdr, sizeof(hdr), MSG_PEEK);	
	} while (ret == -1 && errno == EINTR);

	if (ret == -1)
		return (errno == EAGAIN) ? EAGAIN : PPREADERR;

	ret = proxy_ptc_decode((char *)&hdr, ret, ppver, src, dst);
	if (ret > 0) {
		do {
			// we need to consume the appropriate 
			// amount of data from the socket 
			ret = recv(fd, &hdr, ret, 0);
		} while (ret == -1 && errno == EINTR);
		return (ret >= 0) ? PPNOERR : PPREADERR;
	}
	return ret;
}
