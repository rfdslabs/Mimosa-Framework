/* Copyright (c) 2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __TCPCHECKSUM_H
#define __TCPCHECKSUM_H
#ifdef __cplusplus
extern "C" {
#endif

unsigned
validate_tcp_checksum(	const unsigned char *px,
						unsigned length,
						unsigned pseudo_ip_src,
						unsigned pseudo_ip_dst);

unsigned
validate_udp_checksum(	const unsigned char *px,
						unsigned length,
						unsigned pseudo_ip_src,
						unsigned pseudo_ip_dst);



#ifdef __cplusplus
}
#endif
#endif /*__TCPCHECKSUM_H*/
