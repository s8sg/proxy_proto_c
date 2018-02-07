#ifndef _PROXY_PTC_H_
#define _PROXY_PTC_H_

typedef union {
        struct {  /* for TCP/UDP over IPv4, len = 12 */
		uint32_t src_addr;
		uint32_t dst_addr;
		uint16_t src_port;
		uint16_t dst_port;
	} ip4;
	struct {  /* for TCP/UDP over IPv6, len = 36 */
		uint8_t  src_addr[16];
		uint8_t  dst_addr[16];
		uint16_t src_port;
		uint16_t dst_port;
	} ip6;
	struct {  /* for AF_UNIX sockets, len = 216 */
		uint8_t src_addr[108];
		uint8_t dst_addr[108];
	} unx;
} pproxy_v2_addr_t;


typedef struct {
	char line[108];
} pproxy_v1_t;

typedef struct {
	uint8_t  sig[12];  /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
	uint8_t  ver_cmd;  /* protocol version and command (V2/V1) */
	uint8_t  fam;      /* protocol family and address (DGRAM/STREAM) */
	uint16_t len;     /* number of following bytes part of the header */
	pproxy_v2_addr_t addr;
} pproxy_v2_t;

typedef union {
	pproxy_v1_t v1;
	pproxy_v2_t v2;
} pproxy_hdr_t;

typedef enum {
	PPHDRERR = -7,
	PPSENDERR,      // failure to send to sock fd
	PPREADERR,      // failure to read from sock fd
	PPINVALADDR,    // invalid address
	PPINVALFAM,     // invalid family value
	PPTRUNCATED,    // truncated header
	PPINVALCMD,     // invalid cmd
	PPNOERR = 0,    // no error
	PPLOCALCMD,     // local command in vercmd
} pp_ret_t;

typedef enum {
	PPROXY_V1 = 1,
	PPROXY_V2
} pproxy_ver_t;

#define IPV4_ADDR_LEN 12
#define IPV6_ADDR_LEN 36
#define UNX_ADDR_LEN  216
#define V2_HDR_LEN    16
#define MAX_PP_LEN    sizeof(pproxy_hdr_t)

#define SOCKADDR_STORAGE(addr) (struct sockaddr_storage *)addr

static const char v2sig[12] = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
static const uint8_t vercmd = 0x21;

pp_ret_t proxy_ptc_v1_encode(char *buf, int8_t *len,
		             struct sockaddr_storage *src,
		             struct sockaddr_storage *dst);

pp_ret_t proxy_ptc_v2_encode(char *buf, int8_t *len,
		             struct sockaddr_storage *src,
		             struct sockaddr_storage *dst);

pp_ret_t proxy_ptc_send(int fd,
			pproxy_ver_t ppver,
		        struct sockaddr_storage *src,
			struct sockaddr_storage *dst);

pp_ret_t proxy_ptc_decode(char *buf, int len,
			  pproxy_ver_t *ppver,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst);

pp_ret_t proxy_ptc_read(int fd,
			pproxy_ver_t *ppver,
			struct sockaddr_storage *src,
			struct sockaddr_storage *dst);

uint8_t get_addr_family(struct sockaddr_storage *addr);

struct in_addr get_inet4_ip(struct sockaddr_storage *addr);

struct in6_addr get_inet6_ip(struct sockaddr_storage *addr);

uint8_t get_inet4_port(struct sockaddr_storage *addr);

uint16_t get_inet6_port(struct sockaddr_storage *addr);

#endif // _PROXY_PTC_H_
