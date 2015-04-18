/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __NETFRAME_H
#define __NETFRAME_H
#ifdef __cplusplus
extern "C" {
#endif

enum {
	ADDRESS_IP_v4=0,
	ADDRESS_IP_v6=6,
	ADDRESS_IPX=10,
	ADDRESS_ATALK_EDDP=20
};

enum {
	LAYER3_UNKNOWN,
	LAYER3_IP,
	LAYER3_IPV4FRAG,
	LAYER3_ARP,
	LAYER3_IPV6,
	LAYER3_MGMT,
	LAYER3_STP,
	LAYER3_NETBEUI,
    LAYER3_MULTICAST_UNKNOWN,
	LAYER3_TOTAL
};

enum {
	LAYER4_UNKNOWN,
	LAYER4_TCP,
	LAYER4_UDP,
	LAYER4_ICMP,
	LAYER4_IGMP,
	LAYER4_GRE,
    LAYER4_ESP,
	LAYER4_TCP_CORRUPT,
	LAYER4_TCP_XSUMERR,

	LAYER4_TOTAL
};


enum LAYER7_PROTOCOL {
	LAYER7_UNKNOWN,
	
	LAYER7_UNKNOWN_TCP,
	LAYER7_UNKNOWN_UDP,
	
	LAYER7_HTTP,
	LAYER7_MSNMSGR,
	LAYER7_POP3,
	LAYER7_RDP,
	LAYER7_SMTP,
	LAYER7_YAHOOMSGR,
	LAYER7_AIM,
	LAYER7_SSL,
	LAYER7_DCERPC,
	LAYER7_SMB,
	LAYER7_FTP,
	LAYER7_IMAP,
	LAYER7_ISCSI,
    LAYER7_RTSP,
    LAYER7_SSH,

    LAYER7_BITTORRENT_TCP,
	LAYER7_BITTORRENT_uTP,
	LAYER7_BITTORRENT_DHT,
	LAYER7_BITTORRENT_XYZ,
	LAYER7_CALLWAVE,
	LAYER7_CISCO,
	LAYER7_CUPS,
	LAYER7_DHCP,
	LAYER7_DNS_MCAST,
	LAYER7_DNS_NETBIOS,
	LAYER7_DNS_SRV,
	LAYER7_DNS,
	LAYER7_ISAKMP,
	LAYER7_NETBIOS_DGM,
	LAYER7_PPP,
	LAYER7_SIP,
	LAYER7_SMB_DGM,
	LAYER7_SNMP,
	LAYER7_SRVLOC,
	LAYER7_SSDP,
	LAYER7_TIVO,
	LAYER7_UPNP,
	LAYER7_YMSG,
	LAYER7_LDAP,
	LAYER7_RTP,
	LAYER7_HSRP,

    LAYER7_CLOUD_NIMBUS,

	LAYER7_TOTAL
};
struct TCPRECORD;

struct NetFrame
{
	unsigned ipver;
	unsigned ipttl;
	unsigned is_data; /* On WiFi, if we have data, and true everywhere else */
	unsigned layer2_protocol;
	unsigned layer3_protocol;
	unsigned layer4_protocol;
	enum LAYER7_PROTOCOL layer7_protocol;
	unsigned original_length;
	unsigned captured_length;
	unsigned time_secs;
	unsigned time_usecs;
	unsigned frame_number;
	union {
		struct {
			unsigned bad_fcs:1;
			unsigned filtered:1;
			unsigned repeated:1;
			unsigned ivs:1;
		} found;
		unsigned clear;
	} flags;
	const char *filename;
	const unsigned char *src_mac;
	const unsigned char *dst_mac;
	const unsigned char *bss_mac;
	unsigned			 bss_direction;
	const char *netbios_source;
	const char *netbios_destination;
	unsigned src_ipv4;
	unsigned dst_ipv4;
	unsigned src_port;
	unsigned dst_port;
	unsigned char src_ipv6[16];
	unsigned char dst_ipv6[16];
	int dbm;

	struct TCPRECORD *sess;
};

void FRAMERR(struct NetFrame *frame, const char *msg, ...);

#define FRAMERR_UNKNOWN_UNSIGNED(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_BADVAL(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_TRUNCATED(frame, name) FRAMERR(frame, "%s: truncated\n", name);
#define FRAMERR_UNPARSED(frame, name, value) FRAMERR(frame, "%s: unparsed value: 0x%x (%d)\n", name, value, value);


#ifdef __cplusplus
}
#endif
#endif /*__NETFRAME_H*/
