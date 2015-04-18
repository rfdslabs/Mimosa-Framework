/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __PROTOS_H
#define __PROTOS_H
#ifdef __cplusplus
extern "C" {
#endif

	
struct Ferret;
struct FerretEngine;
struct NetFrame;
struct TCPRECORD;
struct TCP_STREAM;

void process_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_wifi_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ethernet_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_802_1x_auth(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_cisco00000c(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_arp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ip(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ipv6(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_udp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_tcp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_igmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_gre(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_icmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_icmpv6(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_atalk_ddp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_atalk_nbp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_novell_ipx(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_pptp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_ppoe_discovery(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_cups(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_dns(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_dhcp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_netbios_dgm(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_smb_dgm(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_ssdp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_callwave_iam(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_snmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_upnp_response(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_srvloc(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_isakmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_bittorrent_XYZ(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_bittorrent_DHT(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_bittorrent_uTP(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_ldap(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_tivo_broadcast(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_dhcpv6(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_rtp_avp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_rtp_rtcp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_dgram_sip_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_dgram_sip_response(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_jpeg_ichat_image(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);



void stream_http_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_http_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void stream_ssl_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_ssl_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void stream_rtsp_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_rtsp_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void stream_ssh_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_ssh_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void stream_bittorrent_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_bittorrent_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void stream_dcerpc_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_dcerpc_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_smb_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_smb_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);


void process_msnms_server_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_simple_msnms_client_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_pop3_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_pop3_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_rdp_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_rdp_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void process_simple_smtp_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_simple_smtp_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void parse_aim_oscar_to_server(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void parse_aim_oscar_from_server(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

void stack_tcp_ymsg_client_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stack_tcp_ymsg_server_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);


unsigned smellslike_bittorrent_XYZ(const unsigned char *px, unsigned length);
unsigned smellslike_bittorrent_DHT(const unsigned char *px, unsigned length);
unsigned smellslike_bittorrent_uTP(const unsigned char *px, unsigned length);
void stream_to_server_unknown(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);
void stream_from_server_unknown(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

unsigned smellslike_bittorrent_udp(const unsigned char *px, unsigned length);

#ifdef __cplusplus
}
#endif
#endif /*__PROTOS_H*/

