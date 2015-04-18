#include "ferret.h"
#include "report.h"
#include "stack-netframe.h"
#include <string.h>
#include <stdio.h>

static unsigned count_digits(uint64_t n)
{
	unsigned i=0;
	for (i=0; n; i++)
		n = n/10;

	if (i == 0)
		i = 1;
	return i;
}

static void
print_stats(const char *str1, unsigned stat1, const char *str2, unsigned stat2)
{
	size_t i;
	unsigned digits;
    FILE *fp = stderr;

	/* first number */
	digits = count_digits(stat1);
	fprintf(fp, "%s", str1);
	for (i=strlen(str1); i<16; i++)
		fprintf(fp, ".");
	for (i=digits; i<11; i++)
		fprintf(fp, ".");
	fprintf(fp, "%d", stat1);

	fprintf(fp, " ");

	/* second number */
    if (str2) {
	    digits = count_digits(stat2);
	    fprintf(fp, "%s", str2);
	    for (i=strlen(str2); i<16; i++)
		    fprintf(fp, ".");
	    for (i=digits; i<11; i++)
		    fprintf(fp, ".");
	    fprintf(fp, "%d", stat2);
    }

	fprintf(stderr, "\n");
}

static void
print_stats2(const char *prefix, const char *str1, uint64_t stat1, const char *str2, uint64_t stat2)
{
	size_t i;
	unsigned digits;
    FILE *fp = stdout;

	/* first number */
	digits = count_digits(stat1);
	fprintf(fp, "%s", prefix);
	for (i=strlen(prefix); i<16; i++)
		fprintf(fp, ".");
	for (i=digits; i<11; i++)
		fprintf(fp, ".");
	fprintf(fp, "%llu-%s", stat1, str1);

	fprintf(fp, ".");

	/* second number */
    if (str2) {
	    digits = count_digits(stat2);
	    //fprintf(fp, "%s", prefix);
	    //for (i=strlen(prefix); i<16; i++)
		//    fprintf(fp, ".");
	    for (i=digits; i<12; i++)
		    fprintf(fp, ".");
	    fprintf(fp, "%llu-%s", stat2, str2);
    }

	fprintf(fp, "\n");
}

void
report_stats1(struct Ferret *ferret)
{
	{
		struct tm *tm_first;
		struct tm *tm_last;
		char sz_first[64], sz_last[64];
		int diff = (int)(ferret->now-ferret->first);

		tm_first = localtime(&ferret->first);
		strftime(sz_first, sizeof(sz_first), "%Y-%m-%d %H:%M:%S", tm_first);
		
		tm_last = localtime(&ferret->now);
		strftime(sz_last, sizeof(sz_last), "%Y-%m-%d %H:%M:%S", tm_last);

		fprintf(stderr, "Capture started at %s and ended at %s (%d seconds)\n",
				sz_first, sz_last, diff);

		print_stats("Repeated packets",		ferret->statistics.repeated, 
					"FCS pass",				ferret->statistics.fcs_good);
		print_stats("FCS fail",				ferret->statistics.fcs_bad, 
					"FCS likely.",			ferret->statistics.remaining_4);
		print_stats("WiFi probes",			ferret->statistics.wifi_probes, 
					"WiFi beacons",			ferret->statistics.wifi_beacons);
		print_stats("WiFi unencrypted",		ferret->statistics.unencrypted_data,
					"WEP encrypted",		ferret->statistics.encrypted_data);
		print_stats("IPv4 packets",			ferret->statistics.ipv4,		
					"IPv6 packets",			ferret->statistics.ipv6);
		print_stats("IPX packets",			ferret->statistics.ipx,		
					"Atalk packets",		ferret->statistics.atalk);
		print_stats("ARP packets",			ferret->statistics.arp,
					"ICMP packets",			ferret->statistics.icmp);
		print_stats("TCP packets",			ferret->statistics.tcp,
					"UDP packets",			ferret->statistics.udp);
		print_stats("HTTP packets",			ferret->statistics.http,
					"DNS packets",			ferret->statistics.dns);
		print_stats("IPv4 size   64",		ferret->statistics.ip4size.size64,
					0,			            0);
		print_stats("IPv4 size  128",		ferret->statistics.ip4size.size128,
					0,			            0);
		print_stats("IPv4 size  256",	    ferret->statistics.ip4size.size256,
					0,			            0);
		print_stats("IPv4 size  512",		ferret->statistics.ip4size.size512,
					0,			            0);
		print_stats("IPv4 size 1024",		ferret->statistics.ip4size.size1024,
					0,			            0);
		print_stats("IPv4 size 1500",		ferret->statistics.ip4size.size1500,
					0,			            0);
	}


}

struct NameVal {
	unsigned val;
	const char *name;
};

struct NameVal layer3names[] = {
	{LAYER3_UNKNOWN,	"unknown3"},
	{LAYER3_IP,			"IPv4"},
	{LAYER3_IPV4FRAG,	"IPv4frag"},
	{LAYER3_ARP,		"ARP"},
	{LAYER3_IPV6,		"IPv6"},
	{LAYER3_MGMT,		"MGMT"},
	{LAYER3_STP,		"STP"},
	{LAYER3_NETBEUI,	"NETBEUI"},
	{LAYER3_MULTICAST_UNKNOWN,	"multicast"},
	{LAYER3_TOTAL,		"TOTAL"},
	{0,0}
};

struct NameVal layer4names[] = {
	{LAYER4_UNKNOWN,	"unknown4"},
	{LAYER4_TCP,		"TCP"},
	{LAYER4_UDP,		"UDP"},
	{LAYER4_ICMP,		"ICMP"},
	{LAYER4_IGMP,		"IGMP"},
	{LAYER4_GRE,		"GRE"},
	{LAYER4_ESP,		"ESP"},
	{LAYER4_TCP_CORRUPT,"TCP-corrupt"},
	{LAYER4_TCP_XSUMERR,"TCP-xsumerr"},
	{LAYER4_TOTAL,		"TOTAL"},
	{0,0}
};

struct NameVal layer7names[] = {
	{LAYER7_UNKNOWN,	"unknown7"},
	{LAYER7_UNKNOWN_TCP,"unknown-TCP"},
	{LAYER7_UNKNOWN_UDP,"unknown-UDP"},
	{LAYER7_HTTP,		"HTTP"},
	{LAYER7_MSNMSGR,	"MSNMSGR"},
	{LAYER7_POP3,		"POP3"},
	{LAYER7_RDP,		"RDP"},
	{LAYER7_SMTP,		"SMTP"},
	{LAYER7_YAHOOMSGR,	"YAHOOMSGR"},
	{LAYER7_AIM,		"AIM"},
	{LAYER7_SSL,		"SSL"},
	{LAYER7_DCERPC,		"DCERPC"},
	{LAYER7_SMB,		"SMB"},
	{LAYER7_FTP,		"FTP"},
	{LAYER7_IMAP,		"IMAP"},
	{LAYER7_ISCSI,		"iSCSI"},
	{LAYER7_RTSP,		"RTSP"},
	{LAYER7_SSH,		"SSH"},


	{LAYER7_BITTORRENT_TCP, "BitTorrent-TCP"},
	{LAYER7_BITTORRENT_uTP, "BitTorrent-uTP"},
	{LAYER7_BITTORRENT_DHT, "BitTorrent-DHT"},
	{LAYER7_BITTORRENT_XYZ, "BitTorrent-XYZ"},
	{LAYER7_CALLWAVE, "CALLWAVE"},
	{LAYER7_CISCO, "CISCO"},
	{LAYER7_CUPS, "CUPS"},
	{LAYER7_DHCP, "DHCP"},
	{LAYER7_DNS_MCAST, "DNS_MCAST"},
	{LAYER7_DNS_NETBIOS, "DNS_NETBIOS"},
	{LAYER7_DNS_SRV, "DNS_SRV"},
	{LAYER7_DNS, "DNS"},
	{LAYER7_ISAKMP, "ISAKMP"},
	{LAYER7_NETBIOS_DGM, "NETBIOS_DGM"},
	{LAYER7_PPP, "PPP"},
	{LAYER7_SIP, "SIP"},
	{LAYER7_SMB_DGM, "SMB_DGM"},
	{LAYER7_SNMP, "SNMP"},
	{LAYER7_SRVLOC, "SRVLOC"},
	{LAYER7_SSDP, "SSDP"},
	{LAYER7_TIVO, "TIVO"},
	{LAYER7_UPNP, "UPNP"},
	{LAYER7_YMSG, "YMSG"},
	{LAYER7_LDAP, "LDAP"},
	{LAYER7_RTP, "RTP"},
	{LAYER7_HSRP, "HSRP"},
	{LAYER7_CLOUD_NIMBUS, "Nimbus"},
	{0,0}
};
static int 
lookup(const struct NameVal *nameval, const char *name)
{
	unsigned i;

	for (i=0; nameval[i].name; i++) {
		if (stricmp(nameval[i].name, name)==0)
			return nameval[i].val;
	}
	return -1;
}
static const char *
lookup_name(const struct NameVal *nameval, unsigned proto)
{
	unsigned i;

	for (i=0; nameval[i].name; i++) {
		if (nameval[i].val == proto)
			return nameval[i].name;
	}
	return 0;
}

void filter_lookup_proto(const char *name, unsigned *layer, unsigned *proto)
{
	int x;

	x = lookup(layer3names, name);
	if (x != -1) {
		*layer = 3;
		*proto = (unsigned)x;
		return;
	}

	x = lookup(layer4names, name);
	if (x != -1) {
		*layer = 4;
		*proto = (unsigned)x;
		return;
	}

	x = lookup(layer7names, name);
	if (x != -1) {
		*layer = 7;
		*proto = (unsigned)x;
		return;
	}

	*layer = 0;
	*proto = (unsigned)-1;
}

const char *
filter_lookup_proto_name(unsigned proto, unsigned layer)
{
	switch (layer) {
	case 3: return lookup_name(layer3names, proto);
	case 4: return lookup_name(layer4names, proto);
	case 7: return lookup_name(layer7names, proto);
	default: return 0;
	}
}


void
report_stats2(struct Ferret *ferret)
{
	unsigned i;

	{
		struct tm *tm_first;
		struct tm *tm_last;
		char sz_first[64], sz_last[64];
		int diff = (int)(ferret->now-ferret->first);

		tm_first = localtime(&ferret->first);
		strftime(sz_first, sizeof(sz_first), "%Y-%m-%d %H:%M:%S", tm_first);
		
		tm_last = localtime(&ferret->now);
		strftime(sz_last, sizeof(sz_last), "%Y-%m-%d %H:%M:%S", tm_last);

		fprintf(stdout, "Capture started at %s and ended at %s (%d seconds)\n",
				sz_first, sz_last, diff);
	}
	printf("\n--- Network Layer ----\n");
	for (i=0; i<LAYER3_TOTAL; i++) {
		const char *name;
		if (ferret->stats2.layer3_pkts[i] == 0)
			continue;

		name = filter_lookup_proto_name(i, 3);
		print_stats2(name, 
			"pkts", ferret->stats2.layer3_pkts[i],
			"bytes", ferret->stats2.layer3_bytes[i]);
	}

	printf("\n--- Transport Layer ----\n");
	for (i=0; i<LAYER4_TOTAL; i++) {
		const char *name;
		if (ferret->stats2.layer4_pkts[i] == 0)
			continue;
		name = filter_lookup_proto_name(i, 4);
		print_stats2(name,
			"pkts", ferret->stats2.layer4_pkts[i],
			"bytes", ferret->stats2.layer4_bytes[i]);
	}

	printf("\n--- Application Layer ----\n");
	for (i=0; i<LAYER7_TOTAL; i++) {
		const char *name;
		if (ferret->stats2.layer7_pkts[i] == 0)
			continue;
		name = filter_lookup_proto_name(i, 7);
		print_stats2(name, 
			"pkts", ferret->stats2.layer7_pkts[i],
			"bytes", ferret->stats2.layer7_bytes[i]);
	}
}
