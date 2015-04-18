/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-extract.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "util-val2string.h"	/* for translating OUIs */
#include <string.h>
#include <stdio.h>

typedef unsigned char MACADDR[6];

/**
 * This structure represents data parsed from various wifi management
 * packets, including data from the variable fields.
 */
struct	WIFI_MGMT {
	int frame_control;
	int duration;
	MACADDR destination;
	MACADDR source;
	MACADDR bss_id;
	int frag_number;
	int seq_number;
	char cisco_device_name[20];
	unsigned cisco_client_count;

	unsigned char *ssid;
	size_t ssid_length;

	unsigned maxrate;
	unsigned channel;

	unsigned is_wpa:1;
	unsigned is_wpa2:1;
	unsigned is_tkip:1;
	unsigned is_ccmp:1;
	unsigned is_psk:1;
	unsigned is_eap:1;
	unsigned is_wep40:1;
	unsigned is_wep104:1;

};




/**
 * Process the WPA information element
 */
static void 
process_ie_wpa(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, struct WIFI_MGMT *wifimgmt)
{
	unsigned count;
	unsigned offset = 0;
	unsigned version;

	UNUSEDPARM(ferret);

	/* validate length */
	if (length < 18) {
		FRAMERR(frame, "WPA: truncated\n");
		return;
	}

	/* VERSION */
	version = ex16le(px+offset);
	offset += 2;
	if (version != 1) {
		FRAMERR(frame, "WPA: unknown version %d\n", version);
		return;
	}

	/* Mark the fact that we have a WPA information element */
	wifimgmt->is_wpa = 1;
		
	/* multicast cipher */
	switch (ex32be(px+offset)) {
	case 0x0050f201:
	case 0x000fac01:
		wifimgmt->is_wep40 = 1;
		break;
	case 0x0050f202: /* WPA-TKIP */
	case 0x000fac02: /* WPA2-TKIP */
		wifimgmt->is_tkip = 1;
		break;
	case 0x0050f204: /* WPA-CCMP */
	case 0x000fac04: /* WPA2-CCMP */
		wifimgmt->is_ccmp = 1;
		break;
	default:
		FRAMERR(frame, "WPA: unknown cipher suite: 0x%08x\n", ex32be(px+offset));
	}
	offset += 4;

	/* skip unicast cipher suites */
	count = ex16le(px+offset);
	offset+=2;
	while (count && offset+4<length) {
		switch (ex32be(px+offset)) {
		case 0x0050f201:
		case 0x000fac01:
			wifimgmt->is_wep40 = 1;
		break;
		case 0x0050f202: /* WPA-TKIP */
		case 0x000fac02: /* WPA2-TKIP */
			wifimgmt->is_tkip = 1;
			break;
		case 0x0050f204: /* WPA-CCMP */
		case 0x000fac04: /* WPA2-CCMP */
			wifimgmt->is_ccmp = 1;
			break;
		default:
			FRAMERR(frame, "WPA: unknown cipher suite: 0x%08x\n", ex32be(px+offset));
		}
		count--;
		offset+=4;
	}

	/* grab auth methods */
	count = ex16le(px+offset);
	offset+=2;
	while (count && offset+4<=length) {
		switch (ex32be(px+offset)) {
		case 0x0050f201:
		case 0x000fac01:
			/* WPA? */
			break;
		case 0x0050f202: /* WPA-PSK */
		case 0x000fac02: /* WPA2-PSK */
			wifimgmt->is_psk = 1;
			break;
		default:
			FRAMERR(frame, "WPA: auth: 0x%08x\n", ex32be(px+offset));
		}
		count--;
		offset+=4;
	}
}


/**
 * This parses the variable-fields portion of many of the WiFi
 * management frames.
 *
 * Of particular interest are the "vendor-specific" fields. These
 * will help us fingerprint the device, and pull some particularly
 * useful information from some vendor's devices.
 *
 * Of even more interest is the Microsoft-vendor-specific portion.
 * In Windows Vista (as well as Zune and Xbox 360), Microsoft
 * has opened up their vendor field to user-mode applications to add
 * their own extensions.
 */
void process_wifi_fields(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct WIFI_MGMT *wifimgmt)
{
	/* We have to fix bugsin well-known cards that cause us to go off the 
	 * end. In theory, these packets are corrupt and should be discarded, 
	 * but in practice, we have to learn to live with them */

	while (offset < length) {
		unsigned tag, len;

		/* fix known bugs */
		if (offset == length-1 && px[offset] == 0x80 && memcmp(wifimgmt->source, "\x00\x02\x2d", 3) == 0)
			break;

		tag = px[offset++];
		if (offset >= length) {
			/* Fix Agere bug */
			FRAMERR(frame, "wifi parms: went past eof\n");
			break;
		}
		len = px[offset++];

		/* Fix bugs */
		if (tag == 5 && memcmp(wifimgmt->source, "\x00\x02\x2d", 3) == 0 && offset+len > length)
			len = length-offset;
		if (tag == 0x80 && length-offset>3 && memcmp(px+offset, "\x00\x60\x1d", 3) == 0 && offset+len > length)
			len = length-offset;
		if (tag == 0xdd && length-offset>3 && memcmp(px+offset, "\x00\x03\x7f", 3) == 0 && offset+len > length)
			len = length-offset;

		if (offset + len > length) {
			; /*FRAMERR(frame, "wifi parms: went past eof\n");*/
			break;
		}


		SAMPLE(ferret, "IEEE802.11",JOT_NUM("parm", tag));

		switch (tag) {
		case 0x00: /* SSID */
			wifimgmt->ssid = (unsigned char*)px+offset;
			wifimgmt->ssid_length = len;

			if (len == 0) {
				wifimgmt->ssid = (unsigned char*)"(broadcast)";
				wifimgmt->ssid_length = strlen((char*)wifimgmt->ssid);
			}
			break;
		case 1: /* SUPPORTED RATES */
		case 50: /* EXTENDED SUPPORTED RATES */
			{
				unsigned i;
				for (i=0; i<len; i++) {
					unsigned rate=0;

					rate = (px[offset+i]&0x7F) * 5;
					if (wifimgmt->maxrate < rate)
						wifimgmt->maxrate = rate;
				}
			}
			break;
		case 3: /* CHANNEL */
			if (len != 1)
				FRAMERR(frame, "wifi parms: bad channel length\n");
			if (len > 0)
				wifimgmt->channel = px[offset+len-1];
			break;
		case 4: /* CFG Parameter Set */
			break;
		case 5: /* TIM */
			/*TIM bug in Agere */
			if (offset + len > length)
				len = length-offset;
			break;
		case 0x2a: /*ERP Information */
			/* radiotap.pcap(1) */
		case 0x2f: /*ERP infomration (why is this the same as 0x2a?) */
			/* radiotap.pcap(1) */
			break;
		case 0x06: /*IBSS */
		case 10: /*unknown*/
		case 0x0b: /* QBSS Load Element for 802.11e */
		case 150: /*unknown*/
		case 0x2c: /*IEEE802.11e Traffic Classification (TCLAS) */
			break;
		case 0x85: /*Cisco proprietary */
			if (len < 27)
				FRAMERR(frame, "CISCO: tag 0x85 length is less than 26\n");
			else {
				memcpy(wifimgmt->cisco_device_name, px+offset+10, 16);
				wifimgmt->cisco_device_name[16] = '\0';
				wifimgmt->cisco_client_count = px[offset+26];
			}
			break;
		case 0x30: /*RSN Information */
			wifimgmt->is_wpa2 = 1;
			process_ie_wpa(ferret, frame, px+offset, len, wifimgmt);
			break;
		case 7: /* COUNTRY INFORMATION */
			/*
			if (tag < 3)
				FRAMERR(frame, "wifi parms: bad country info\n");
			else
			{
				char country[16];
				int country_len = len-3;
				int min_channel = px[offset+len-3];
				int max_channel = px[offset+len-2];
				int max_power = px[offset+len-1];
				char power[32];

				if (country_len > sizeof(country)-1)
					country_len = sizeof(country)-1;
				memcpy(country, px+offset, country_len);
				country[country_len] = '\0';

				sprintf_s(power, sizeof(power), "%d-dBm", max_power);

				JOTDOWN(ferret,
					JOT_SZ("proto","WiFi"),
					JOT_SZ("op","countryinfo"),
					JOT_MACADDR("macaddr", wifimgmt->source),
					JOT_SZ("wifi.country",country),
					JOT_NUM("wifi.minchannel",min_channel),
					JOT_NUM("wifi.maxchannel",max_channel),
					JOT_SZ("wifi.power",power),
					0);
			}*/
			break;
		case 0x80:
		case 0xdd:
			if (len < 3) {
				FRAMERR(frame, "wifi vendor extension: too short\n");
			} else {
				unsigned oui = ex24be(px+offset);

				SAMPLE(ferret,"IEEE802.11", JOT_NUM("oui", oui));

				switch (oui) {
				case 0x004096: /*aironet*/
					break;
				case 0x001018: /*broadcom*/
					break;
				case 0x00601d: /*agere*/
				case 0x000347: /*intel*/
				case 0x00037f: /*Atheros*/
					/*
					JOTDOWN(ferret,
						JOT_SZ("proto","WiFi"),
						JOT_SZ("op","vendor"),
						JOT_SZ("vendor.name",oui_vendor(oui)),
						JOT_HEX24("vendor.oui", oui),
						JOT_PRINT("vendor.data", px+offset+3, len-3),
						0);
					*/
					break;
				case 0x0050f2: /*Microsoft*/
					offset += 3;
					len -= 3;
					if (len < 1) 
						FRAMERR(frame, "wifi vendor extension: too short\n");
					else {
						int tag2 = px[offset];
						offset++;
						len--;
						if (len > length-offset)
							len = length-offset;

						switch (tag2) {
						case 0x01: /* WPA1 cypher suites */
							process_ie_wpa(ferret, frame, px+offset, len, wifimgmt);
							break;
						case 0x02:
							/* Wireless Media Extensions */
							break;
						case 0x04:
							/* WiFi Protected Setup */
							break;
						default:
							FRAMERR(frame, "wifi MS extension: unknown 0x%02x\n", tag2);
						}
					}
					break;
				case 0x00393: /* Apple */
					break;
				case 0x0af5: /* AirgoNet */
					break;
				case 0x00032f: /*GlobalSu*/
					break;
				case 0x000a5e: /*3com*/
					break;
				case 0x00904c: /*Epigram*/
					break;
				default:
					; /*FRAMERR(frame, "wifi vendor extension: unknown 0x%06x\n", oui);*/
				}
			}
			break;
		default:
			; /*FRAMERR(frame, "wifi parms: unknown tag %d(0x%02x)\n", tag, tag);*/
		}


		offset += len;
	}

}

void process_wifi_proberequest(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct	WIFI_MGMT wifimgmt;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	ferret->statistics.wifi_probes++;

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);

	/* Process variable tags */
	offset = 24;
	process_wifi_fields(ferret, frame, px, length, offset, &wifimgmt);

	JOTDOWN(ferret,
		JOT_SZ("proto","WiFi"),
		JOT_SZ("op","probe"),
		JOT_MACADDR("macaddr", wifimgmt.source),
		JOT_PRINT("SSID", wifimgmt.ssid, wifimgmt.ssid_length),
		JOT_MACADDR("BSSID", wifimgmt.bss_id),
		0);

	/*if (ferret_remember_beacon(ferret, wifimgmt.source, wifimgmt.bss_id, wifimgmt.ssid, wifimgmt.ssid_length, px[0], frame->time_secs) == 0)
		frame->flags.found.repeated = 1;*/

}

void process_wifi_proberesponse(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct	WIFI_MGMT wifimgmt;

	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* Grab the source Ethernet address (i.e. the address of the access point) */
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);

	/* Process variable tags */
	offset = 24;

	offset += 8; /* timestamp */

	offset += 2; /* beacon interval */

	offset += 2; /* capability information */

	process_wifi_fields(ferret, frame, px, length, offset, &wifimgmt);

	{
		char maxrate[32];
		if (wifimgmt.maxrate%10)
			sprintf_s(maxrate, sizeof(maxrate),"%d.%d-mbps", wifimgmt.maxrate/10, wifimgmt.maxrate%10);
		else
			sprintf_s(maxrate, sizeof(maxrate),"%d-mbps", wifimgmt.maxrate/10);

		JOTDOWN(ferret,
			JOT_SZ("proto","WiFi"),
			JOT_SZ("op","probe-response"),
			JOT_MACADDR("macaddr", wifimgmt.source),
			JOT_PRINT("SSID", wifimgmt.ssid, wifimgmt.ssid_length),
			JOT_MACADDR("BSSID", wifimgmt.bss_id),
			JOT_SZ("maxrate",maxrate),
			JOT_NUM("channel",wifimgmt.channel),
			0);

		if (ferret_remember_beacon(ferret, wifimgmt.source, wifimgmt.bss_id, wifimgmt.ssid, wifimgmt.ssid_length, wifimgmt.channel, px[0], frame->time_secs) == 0)
			frame->flags.found.repeated = 1;

	}
}

/**
 * The "associate request" is when the notebook computer "logs on" to the
 * the access-point.
 */
void process_wifi_associate_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct	WIFI_MGMT wifimgmt;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 28) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.destination, px+4, 6);
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);

	if (ferret_infilter_mac(ferret, wifimgmt.destination) | ferret_infilter_mac(ferret, wifimgmt.source)) {
		frame->flags.found.filtered = 1;
		return;
	}

	process_wifi_fields(ferret, frame, px, length, 28, &wifimgmt);

	{
		char maxrate[32];
		if (wifimgmt.maxrate%10)
			sprintf_s(maxrate, sizeof(maxrate),"%d.%d-mbps", wifimgmt.maxrate/10, wifimgmt.maxrate%10);
		else
			sprintf_s(maxrate, sizeof(maxrate),"%d-mbps", wifimgmt.maxrate/10);


		JOTDOWN(ferret,
			JOT_SZ("proto","WiFi"),
			JOT_SZ("op","associate"),
			JOT_MACADDR("macaddr", wifimgmt.source),
			JOT_PRINT("SSID", wifimgmt.ssid, wifimgmt.ssid_length),
			JOT_MACADDR("BSS", wifimgmt.bss_id),
			JOT_SZ("maxrate",maxrate),
			0);
	}
}


/**
 * The "disassociate" is when the mobile device logs-off or disconnects
 * from the access-point. There is a reason code associated with that
 * can indicate why the device is disassociating, such as going into
 * hibernate mode to conserve power.
 */
void process_wifi_disassociate_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct	WIFI_MGMT wifimgmt;
	unsigned reason;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.destination, px+4, 6);
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);
	reason = ex16le(px+24);

	JOTDOWN(ferret,
		JOT_SZ("proto","WiFi"),
		JOT_SZ("op","disassociate"),
		JOT_MACADDR("macaddr", wifimgmt.source),
		JOT_MACADDR("BSS", wifimgmt.bss_id),
		JOT_NUM("reason",reason),
		0);
}

void process_wifi_deauthentication(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct	WIFI_MGMT wifimgmt;
	unsigned reason;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.destination, px+4, 6);
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);
	reason = ex16le(px+24);

	JOTDOWN(ferret,
		JOT_SZ("proto","WiFi"),
		JOT_SZ("op","deauthentication"),
		JOT_MACADDR("macaddr", wifimgmt.source),
		JOT_MACADDR("BSS", wifimgmt.bss_id),
		JOT_NUM("reason",reason),
		0);
}

extern void
xleap_destroy(struct Ferret *ferret, const unsigned char *src_mac, const unsigned char *dst_mac);

void process_wifi_authentication(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned auth_type;
	//unsigned seq;
	unsigned status;

	if (length < 30) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}


	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;
	
	auth_type = ex16le(px+24);
	//seq = ex16le(px+26);
	status = ex16le(px+28);

	SAMPLE(ferret,"WIFI", JOT_NUM("authtype", auth_type));
	SAMPLE(ferret,"WIFI", JOT_NUM("status", status));

	/* Authentication algorithm */
	if (status == 0)
	switch (auth_type) {
	case 0x0000: /* Open */
		JOTDOWN(ferret,
			JOT_SZ("proto","WiFi"),
			JOT_SZ("op","authentication"),
			JOT_MACADDR("macaddr", frame->src_mac),
			JOT_MACADDR("BSS", frame->bss_mac),
			JOT_SZ("auth","Open"),
			0);
		break;
	case 0x0080: /* EAP */
		/* Reset any remember EAP authentication between these MAC addresses */
		xleap_destroy(ferret, frame->src_mac, frame->dst_mac);
		xleap_destroy(ferret, frame->dst_mac, frame->src_mac);
		JOTDOWN(ferret,
			JOT_SZ("proto","WiFi"),
			JOT_SZ("op","authentication"),
			JOT_MACADDR("macaddr", frame->src_mac),
			JOT_MACADDR("BSS", frame->bss_mac),
			JOT_SZ("auth","EAP"),
			0);
		break;
	default:
		FRAMERR(frame, "wifi: auth: unknown type\n");
		break;
	}
}

/**
 * Parses a "Beacon" packet from an WiFi Access Point (AP).
 * These are the packets that NetStumbler picks up on to find access-points.
 * On a quiet network, the majority of packets will be these beacons
 * from access points announcing themselves.
 *
 * The most important information we are interested in is the SSID.
 */
void process_wifi_beacon(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct	WIFI_MGMT wifimgmt;
	unsigned supports_wep=0;

	memset(&wifimgmt, 0, sizeof(wifimgmt));

	ferret->statistics.wifi_beacons++;

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}


	/* Grab the source Ethernet address (i.e. the address of the access point) */
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id,  px+16, 6);

	/* Process variable tags */
	offset = 24;


	offset += 8; /* timestamp */

	offset += 2; /* beacon interval */

	if (px[offset]&0x10)
		supports_wep = 1;

	offset += 2; /* capability information */

	/*
	 * Parse the variable fields from the packet
	 */
	process_wifi_fields(ferret, frame, px, length, offset, &wifimgmt);

	{
		char maxrate[32];
		if (wifimgmt.maxrate%10)
			sprintf_s(maxrate, sizeof(maxrate),"%d.%d-mbps", wifimgmt.maxrate/10, wifimgmt.maxrate%10);
		else
			sprintf_s(maxrate, sizeof(maxrate),"%d-mbps", wifimgmt.maxrate/10);

		JOTDOWN(ferret,
			JOT_MACADDR("ID-MAC", wifimgmt.source),
			JOT_PRINT("SSID", wifimgmt.ssid, wifimgmt.ssid_length),
			0);
		JOTDOWN(ferret,
			JOT_MACADDR("Access-Point", wifimgmt.source),
			JOT_PRINT("SSID", wifimgmt.ssid, wifimgmt.ssid_length),
			0);
		if (wifimgmt.cisco_device_name[0]) {
			JOTDOWN(ferret,
				JOT_MACADDR("Access-Point", wifimgmt.source),
				JOT_SZ("Device-Name", wifimgmt.cisco_device_name),
				0);
			JOTDOWN(ferret,
				JOT_MACADDR("Access-Point", wifimgmt.source),
				JOT_NUM("Clients", wifimgmt.cisco_client_count),
				0);
		}
		JOTDOWN(ferret,
			JOT_MACADDR("Access-Point", wifimgmt.source),
			JOT_NUM("channel",wifimgmt.channel),
			0);
		JOTDOWN(ferret,
			JOT_MACADDR("Access-Point", wifimgmt.source),
			JOT_MACADDR("BSSID", wifimgmt.bss_id),
			0);
		JOTDOWN(ferret,
			JOT_MACADDR("Access-Point", wifimgmt.source),
			JOT_SZ("maxrate", maxrate),
			0);

		if (!supports_wep && !wifimgmt.is_wpa && !wifimgmt.is_wpa2) {
			JOTDOWN(ferret,
				JOT_MACADDR("Access-Point", wifimgmt.source),
				JOT_SZ("Encryption", "none"),
				0);
		} else if (supports_wep && !wifimgmt.is_wpa && !wifimgmt.is_wpa2) {
			JOTDOWN(ferret,
				JOT_MACADDR("Access-Point", wifimgmt.source),
				JOT_SZ("Encryption", "WEP"),
				0);
		} else if (wifimgmt.is_wpa2) {
			if (wifimgmt.is_psk)
				JOTDOWN(ferret,
					JOT_MACADDR("Access-Point", wifimgmt.source),
					JOT_SZ("Encryption", "WPA2-PSK"),
					0);
			else
				JOTDOWN(ferret,
					JOT_MACADDR("Access-Point", wifimgmt.source),
					JOT_SZ("Encryption", "WPA2"),
					0);
		} else if (wifimgmt.is_wpa) {
			if (wifimgmt.is_psk)
				JOTDOWN(ferret,
					JOT_MACADDR("Access-Point", wifimgmt.source),
					JOT_SZ("Encryption", "WPA-PSK"),
					0);
			else
				JOTDOWN(ferret,
					JOT_MACADDR("Access-Point", wifimgmt.source),
					JOT_SZ("Encryption", "WPA"),
					0);
		}

		if (wifimgmt.is_wep40) {
			JOTDOWN(ferret,
				JOT_MACADDR("Access-Point", wifimgmt.source),
				JOT_SZ("Encryption", "WEP-40bit"),
				0);
		}

		if (ferret_remember_beacon(ferret, wifimgmt.source, wifimgmt.bss_id, wifimgmt.ssid, wifimgmt.ssid_length, wifimgmt.channel, px[0], frame->time_secs) == 0)
			frame->flags.found.repeated = 1;
	}
}

void process_wifi_data(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned ethertype;
	unsigned oui;

	if (length <= 24) {
		; //FRAMERR(frame, "wifi.data: too short\n");
		return;
	}
	frame->is_data = 1;

	switch (px[1]&0x03) {
	case 0:
	case 2:
		frame->dst_mac = px+4;
		frame->bss_mac = px+10;
		frame->src_mac = px+16;
		break;
	case 1:
		frame->bss_mac = px+4;
		frame->src_mac = px+10;
		frame->dst_mac = px+16;
		break;
	case 3:
		frame->bss_mac = (const unsigned char*)"\0\0\0\0\0\0";
		frame->dst_mac = px+16;
		frame->src_mac = px+24;
		offset += 6;
		break;
	}


	if ((px[22]&0xF) != 0) {
		/*fragmented*/
		return;
	}

	offset += 24;
	if (px[0] == 0x88)
		offset+=2;


	/* Look for SAP header */
	if (offset + 6 >= length) {
		FRAMERR(frame, "wifi.sap: too short\n");
		return;
	}

	if (length-offset > 5 && memcmp(px+offset, "\xe0\xe0\x03\xFF\xFF", 5) == 0) {
		offset += 3;
		parse_novell_ipx(ferret, frame, px+offset, length-offset);
		return;
	}

	if (memcmp(px+offset, "\x00\x00\xaa\xaa\x03", 5) == 0) {
		offset += 2;
	} else if (memcmp(px+offset, "\xaa\xaa\x03", 3) != 0) {
		JOTDOWN(ferret,
			JOT_SZ("proto", "WiFi"),
			JOT_SZ("op", "data.unknown"),
			JOT_PRINT("wifi.data", px+offset, length-offset),
			0);
		return;
	}
	offset +=3 ;

	if (offset+5 >= length) {
		FRAMERR(frame, "ethertype: packet too short\n");
		return;
	}

	oui = ex24be(px+offset);
	ethertype = ex16be(px+offset+3);
	SAMPLE(ferret,"SAP", JOT_NUM("ethertype", oui));

	/* Look for OUI code */
	switch (oui){
	case 0x000000:
		/* fall through below */
		break;
	case 0x004096: /* Cisco Wireless */
		return;
		break;
	case 0x00000c:
		offset +=3;
		if (offset < length)
		process_cisco00000c(ferret, frame, px+offset, length-offset);
		return;
	case 0x080007:
		break; /*apple*/
	case 0x000b85:
		/* Some sort of Cisco packet sent between access-points */
		return;
	case 0x0037f: /* Atheros */
		/* Looking at the packet, it seems to contains MULTPLE TCP/IP packets
		 * that have similar IP/port info to other packets on the wire. I'm thinking
		 * that maybe it's briding packet across multiple access points? Or, it
		 * maybe just including "slack" data, which of course happen to be
		 * packets */
		return;
	case 0x00601d: /* Lucent */
		return;
	case 0x0000f8:
		/* Regress: asleap/data/leap.dump(333)
		 * Seen on Cisco 802.1x packets, treat just the same as an OUI
		 * of 000000 */
		switch (ethertype) {
		case 0x888e:
			break;
		default:
			FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
			return;
		}
		break;
	default:
		FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
		return;
	}
	offset += 5;


	switch (ethertype) {
	case 0x0800:
		process_ip(ferret, frame, px+offset, length-offset);
		break;
	case 0x0806:
		process_arp(ferret, frame, px+offset, length-offset);
		break;
	case 0x888e: /*802.11x authentication*/
		process_802_1x_auth(ferret, frame, px+offset, length-offset);
		break;
	case 0x86dd: /* IPv6*/
		process_ipv6(ferret, frame, px+offset, length-offset);
		break;
	case 0x809b: /* Apple-talk I*/
		parse_atalk_ddp(ferret, frame, px+offset, length-offset);
		break;
	case 0x80f3: /* AppleTalk ARP */
		/* This will have the same format as ARP, except that AppleTalk
		 * addresses will be used instead of IP addresses */
		break;
	case 0x872d: /* Cisco OWL */
		break;
	case 0x0006: /* ??? */
		/* I saw this packet at Toorcon. I have no idea what it's doing, but I'm
		 * filtering it out from printing an error message */
		break;
	case 0x8863: /* PPPoE Discover */
		parse_ppoe_discovery(ferret, frame, px+offset, length-offset);

		break;
	default:
		if (length-offset > 8 && ethertype <= length-offset && ethertype+10 >length-offset && memcmp(px+offset, "\xAA\xAA\x03\x08\x00\x07\x80\x9b", 8) == 0) {
			offset += 8;
			parse_atalk_ddp(ferret, frame, px+offset, length-offset);
		} else if (ethertype == length-offset && ex16be(px+offset) == 0xAAAA) {
		}
		else
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
	}
}

const unsigned 
crc32_ccitt_table[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
        0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
        0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
        0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
        0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
        0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
        0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
        0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
        0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
        0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
        0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
        0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
        0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
        0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
        0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
        0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
        0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
        0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
        0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
        0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
        0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
        0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
        0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
        0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
        0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
        0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
        0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
        0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
        0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
        0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
        0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
        0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
        0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
        0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
        0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
        0x2d02ef8d
};

/* de-weps the block.  if successful, buf* will point to the data start. */
static int 
wep_decrypt(unsigned char *buf, unsigned len, 
			unsigned in_keylen, const unsigned char *in_wepkey)
{
#define SSWAP(a,b) {unsigned char tmp = s[a]; s[a] = s[b]; s[b] = tmp;}
	unsigned i, j, k, crc, keylen;
	unsigned char s[256], key[128], c_crc[4];
	unsigned char *dpos, *cpos;

	/* Needs to be at least 8 bytes of payload */
	if (len < 8)
		return -1;

	/* initialize the first bytes of the key from the IV */
	key[0] = buf[0];
	key[1] = buf[1];
	key[2] = buf[2];

	keylen = in_keylen;

	if (keylen == 0)
		return -1;
	if (in_wepkey == NULL)
		return -1;

	keylen += 3;  /* add in ICV bytes */

	/* copy the rest of the key over from the designated key */
	memcpy(key+3, in_wepkey, in_keylen);

	/* set up the RC4 state */
	for (i = 0; i < 256; i++)
		s[i] = (unsigned char)i;
	j = 0;
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % keylen]) & 0xff;
		SSWAP(i,j);
	}

	/* Apply the RC4 to the data, update the CRC32 */
	cpos = buf+4;
	dpos = buf;
	crc = (unsigned)(~0);
	i = j = 0;
	for (k = 0; k < (len -8); k++) {
		i = (i+1) & 0xff;
		j = (j+s[i]) & 0xff;
		SSWAP(i,j);
		*dpos = (unsigned char)(*cpos++ ^ s[(s[i] + s[j]) & 0xff]);
		crc = crc32_ccitt_table[(crc ^ *dpos++) & 0xff] ^ (crc >> 8);
	}
	crc = ~crc;

	/* now let's check the crc */
	c_crc[0] = (unsigned char)(crc >>  0);
	c_crc[1] = (unsigned char)(crc >>  8);
	c_crc[2] = (unsigned char)(crc >> 16);
	c_crc[3] = (unsigned char)(crc >> 24);

	for (k = 0; k < 4; k++) {
		i = (i + 1) & 0xff;
		j = (j+s[i]) & 0xff;
		SSWAP(i,j);
		if ((*cpos++ ^ s[(s[i] + s[j]) & 0xff]) != c_crc[k])
			  return -1; /* ICV mismatch */
	}

	return 0;
}

/**
 * Tries to decrypt a WEP packet by cycling through keys
 */
unsigned test_wep_decrypt(struct Ferret *ferret, struct NetFrame *frame, 
						const unsigned char *px, unsigned length, 
						unsigned char *new_px, unsigned *r_new_length)
{
	unsigned i;
	struct XKey {
		unsigned len;
		const char *key;
	} xkey[] = {
		{104, "\xa3\x42\xee\x54\xc1\x2e\x5d\x23\x1f\xfe\xe0\x02\x00"},
		{ 40, "\x11\x11\x11\x11\x11"},
		{ 40, "\x4b\x78\x52\xd7\x80"},
		{ 40, "\x00\x00\x00\x00\x00"},
		{ 40, "\x12\x34\x56\x78\x90"},
		{104, "\x10\x01\x11\x11\x00\x00\x11\x11\x00\x00\x11\x11\x01"},
		{104, "\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90"},
	};

	int foo;

	UNUSEDPARM(frame);
	UNUSEDPARM(ferret);

	if (length > 4)
		*r_new_length = length-4;
	else
		return 0; /* error, too short */

	/*
	 * Attempt to decrypt using all the keys, and return the
	 * first one that is found. WEP has a built-in CRC that we use
	 * to check that the encryption was successful.
	 */
	for (i=0; i<sizeof(xkey)/sizeof(xkey[0]); i++) {
		memcpy(new_px, px, length);
		foo = wep_decrypt(new_px+24, length-24, xkey[i].len/8, (const unsigned char*)xkey[i].key);
		if (foo == 0)
			return 1; /* Successfully decrypted */
	}

	return 0;
}


/**
 * Parses raw 802.11 WiFi frames. This requires specialized wifi adapters and
 * drivers, otherwise you'll just get Ethernet frames from the driver (and
 * would instead hit the 'parse_ethernet()' function instead of this one).
 *
 * Both wifi management packets (like Beacons and Probes) are parsed here,
 * as well as Data packets.
 *
 * TODO: at some point, we'll add the ability to import WEP and WAP keys to
 * automatically decrypt packets.
 */
void process_wifi_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->is_data = 0;
	SAMPLE(ferret,"wifi", JOT_NUM("type", px[0]));
	switch (px[0]) {
	case 0x00: /* association request */
		process_wifi_associate_request(ferret, frame, px, length);
		break;
	case 0xa0:
		process_wifi_disassociate_request(ferret, frame, px, length);
		break;
	case 0xc0:
		process_wifi_deauthentication(ferret, frame, px, length);
		break;

	case 0x10: /*assocation response */
		break;
	case 0xD4: /*acknowledgement*/
		/* These are noisy, worthless frames, so ignore them if we can */
		frame->flags.found.repeated = 1;
		break;
	case 0x80: /*beacon*/
		process_wifi_beacon(ferret, frame, px, length);
		break;
	case 0x40:
		process_wifi_proberequest(ferret, frame, px, length);
		break;
	case 0x50:
		process_wifi_beacon(ferret, frame, px, length);
		break;
	case 0x08: /*data*/
		if (px[1] & 0x40) {
			unsigned char tmp_packet[2048];
			unsigned tmp_length=0;
			if (ferret->cfg.is_wifi_slow) {
				if (test_wep_decrypt(ferret, frame, px, length, tmp_packet, &tmp_length))
					process_wifi_data(ferret, frame, tmp_packet, tmp_length);
			}
			ferret->statistics.encrypted_data++;
			break;
		} else {
			ferret->statistics.unencrypted_data++;
			process_wifi_data(ferret, frame, px, length);
		}
		break;
	case 0x88: /* QoS data */
		if (px[1] & 0x40)
			break;
		process_wifi_data(ferret, frame, px, length);
		break;
	case 0x48: /*NULL function*/
		/* These are noisy, worthless frames, so ignore them if we can */
		frame->flags.found.repeated = 1;
		break;
	case 0xb0: /*authentication*/
		process_wifi_authentication(ferret, frame, px, length);
		break;
	case 0xb4: /*request to send*/
		frame->flags.found.repeated = 1;
		break;
	case 0xC4: /*clear to send */
		frame->flags.found.repeated = 1;
		break;
	case 0xE4: /* CF-END */
		frame->flags.found.repeated = 1;
		break;
	case 0x30: /*reassociation response*/
		break;
	case 0xc8: /*QoS Null function*/
		break;
	case 0xa4: /*Power Save Poll */
		break;
	case 0x20: /* Reassociation Request */
		break;
	case 0x94: /* block ack */
		break;
	default:
		; //FRAMERR(frame, "unknown wifi packet [0x%02x]\n", px[0]);

	}
}

