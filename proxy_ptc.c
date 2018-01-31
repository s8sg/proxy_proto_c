#include "proxy_ptc.h"

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
 * return             : 0 if success else errors in pp_err_t
 */
pp_err_t proxy_ptc_v1_encode(uint8_t *buf, int8_t *len,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst) {
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
 * return             : 0 if success else errors in pp_err_t
 */
pp_err_t proxy_ptc_v2_encode(uint8_t *buf, int8_t *len,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst) {
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
 * return             : 0 if success else errors in pp_err_t
 */
pp_err_t proxy_ptc_decode(uint8_t *buf, int8_t len,
			  pproxy_ver_t *ppver,
		          struct sockaddr_storage *src,
			  struct sockaddr_storage *dst) {
	return PPNOERR;
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
 * return             : 0 if success else errors in pp_err_t
 */
pp_err_t proxy_ptc_read_decode(int fd,
			       pproxy_ver_t *ppver,
		               struct sockaddr_storage *src,
			       struct sockaddr_storage *dst) {
	return PPNOERR;
}
