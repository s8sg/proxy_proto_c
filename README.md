### proxy_proto_c
C library to provide common utility implementation to encode, decode, read and send proxy protocol version 1 and version 2

#### APIs
Static
```c
// Return values
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

// Version type
typedef enum {
        PPROXY_V1 = 1,
        PPROXY_V2
} pproxy_ver_t;

// Max length of a buffer for holding the PP header
#define MAX_PP_LEN    sizeof(pproxy_hdr_t) 

// Cast the sockaddr_in or sockaddr_in6 to sockaddr_storage
#define SOCKADDR_STORAGE(addr) (struct sockaddr_storage *)addr

```
Function
```c
/* get_addr_family() : determine addr family and return
 * I/P
 * addr              : sockaddr_storage address (IPv4/IPv6)
 * O/P
 * ret               : AF_INET/AF_INET6, on error 0
 */
uint8_t get_addr_family(struct sockaddr_storage *addr)

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
                          struct sockaddr_storage *dst)
                          
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
                          struct sockaddr_storage *dst)

/* proxy_ptc_send()   : encode a proxy protocol header based
 *                      on provided version and send into socket
 * I/P
 * fd                 : socket file descriptor
 * ppver              : protocol proxy version
 * src                : src address
 * dst                : dst address
 *
 * O/P
 * return             : 0 if success else errors in pp_ret_t
 */
pp_ret_t proxy_ptc_send(int fd,
			pproxy_ver_t ppver,
		        struct sockaddr_storage *src,
			struct sockaddr_storage *dst) 

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
                          struct sockaddr_storage *dst)

/* proxy_ptc_read()   : read packet and decode a proxy protocol 
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
pp_ret_t proxy_ptc_read(int fd,
			pproxy_ver_t *ppver,
		        struct sockaddr_storage *src,
			struct sockaddr_storage *dst)
```

#### Reference
https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt (proxy protocol by HAProxy)  
https://github.com/roadrunner2/mod-proxy-protocol (proxy protocol for Apache)  
https://github.com/ably/proxy-protocol-v2 (encoder/decoder for proxy protocol v2 js)  
