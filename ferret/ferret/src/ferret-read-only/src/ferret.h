/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __FERRET_H
#define __FERRET_H
#ifdef __cplusplus
extern "C" {
#endif
#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS


#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

#include "util-stringtab.h"
#include "stack-netframe.h"

//struct SeapName;
//struct SeapValue;
struct Ferret;
struct NetFrame;
struct TCPRECORD;
struct Listener;
struct TCP_STREAM;

struct FerretEngine;
typedef void (*FERRET_PARSER)(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length);

#include "stack-tcpfrag.h"
#include "stack-tcp.h"
#include "out-jotdown.h"

/**
 * Values for ferret.output.sniff
 */
enum {
	FERRET_SNIFF_UNKNOWN,
	FERRET_SNIFF_NONE,
	FERRET_SNIFF_ALL,
	FERRET_SNIFF_MOST,
	FERRET_SNIFF_IVS,
	FERRET_SNIFF_SIFT,
	FERRET_SNIFF_FILTER,
};

struct BeaconEntry {
	uint64_t hash;
	unsigned char ssid[257];
	unsigned ssid_length;
	unsigned char bssid[6];
	time_t when;
	unsigned count;
	unsigned channel;
	struct BeaconEntry *next;
};

struct IPv6frag
{
	unsigned char ipv6_hdr[40];
	unsigned id;
	unsigned short next_hdr;
	unsigned char is_done;
	unsigned last_offset;

	time_t last_activity;

	struct TCP_segment *segments;

	struct IPv6frag *next;

};

void
ipv6_fragment_free_all(struct Ferret *ferret);

/** 
 * An instance of Ferret application data. We may have multiple
 * instances running at the same time, such as on two different
 * CPUs, so they shouldn't overlap
 */
struct FerretEngine
{
	struct Ferret *ferret;
	struct StringTable stringtab[1];

	struct TCPRECORD *current;
	struct TCPRECORD *sessions[1024*1024];
	unsigned session_count;


	/** A housekeeping module that will allow us, among other things,
	 * to free up stale TCP connections */
	struct Housekeeping *housekeeper;

	time_t last_activity;

    struct XUnknownEngine *tcp_smells;

	
};

struct Snarfer {
	char directory[256];
	unsigned mode;

	unsigned id;

	struct {
		char filename[256];
		FILE *fp;
		time_t last_activity;
	} files[32];
	unsigned file_count;
	unsigned max_files;
};

struct InFilter {
	unsigned char **mac_address;
	unsigned mac_address_count;
};

struct Stats2 {
	uint64_t layer3_pkts[LAYER3_TOTAL];
	uint64_t layer4_pkts[LAYER4_TOTAL];
	uint64_t layer7_pkts[LAYER7_TOTAL];
	
	uint64_t layer3_bytes[LAYER3_TOTAL];
	uint64_t layer4_bytes[LAYER4_TOTAL];
	uint64_t layer7_bytes[LAYER7_TOTAL];
};

struct Statistics {
	unsigned fcs_bad;
	unsigned fcs_good;
	unsigned remaining_4; 
	unsigned wifi_probes;
	unsigned wifi_beacons;
	unsigned unencrypted_data;
	unsigned encrypted_data;
	unsigned ipv4;
	unsigned ipv4frag;
	unsigned ipv6;
	unsigned ipx;
	unsigned arp;
	unsigned repeated;

	unsigned udp;
	unsigned tcp;
	unsigned icmp;

	unsigned http;
	unsigned dns;
	unsigned atalk;

    /** Size distribution */
    struct {
        unsigned size64;
        unsigned size128;
        unsigned size256;
        unsigned size512;
        unsigned size1024;
        unsigned size1500;
    } ip4size;

    struct {
        unsigned ntp;
        unsigned dns;
        unsigned dhcp;
        unsigned norton_av;
        unsigned tivoconnect;
    } udp_;

	/** Missing TCP fragments */
	unsigned errs_tcp_missing;
	unsigned errs_tcp_checksum;
	unsigned errs_udp_checksum;

};

struct LEAP;

struct Ferret
{
    unsigned is_regress:1;
	unsigned is_error:1;
	unsigned is_offline:1;
	unsigned is_live:1;
	unsigned is_ignoring_errors:1;
	unsigned is_verbose:1;

	union {
		struct {
			unsigned something_found:1;
			unsigned repeated_frame:1;
			unsigned wep_ivs_data:1;
		} flags;
		unsigned flags2;

	} framez;

	unsigned something_new_found;

	unsigned fcs_successes;

	struct Snarfer snarfer;

	/** A structure for doing simple IPv6 fragment reassembly */
	struct IPv6frag *ipv6frags[256];

	/**
	 * Information about the output 
	 */
	struct {
		char directory[256];
		char filename[256];
		char comment[256];
		unsigned sniff;
		unsigned noappend:1;
		unsigned include_fcs_err:1;
		char current_name[256];
		struct PcapFile *pf;
		time_t pf_opened;
		int linktype;
	} output;

	struct FerretEngine *eng[16];
	unsigned engine_count;

	/**
	 * Table for LEAP challenge-responses
	 */
	struct LEAP *leap;
	void (*leap_free)(struct LEAP *leap);

	/** 
	 * Table of beacon packets so that we can filter out the noise
	 */
	struct BeaconEntry beacons[256];
	time_t beacon_last_housekeeping;

	/**
	 * A structure used when printout out the JavaScript Tree info
	 */
	struct {
		FILE *fp;
	} jtree;

	/**
	 * The adapter index we should listen on when monitoring 
	 * packets live from a network.
	 */
	int linktype;

	/** 
	 * The system that records all the information that we find within
	 * the packets
	 */
	struct Jotdown *jot;


	struct {
		unsigned is_quiet_wifi:1;
		unsigned interface_checkfcs:1;
		unsigned interface_scan:1;
		unsigned no_vectors:1;
		unsigned no_hamster:1;
		unsigned statistics_print:1;
		unsigned report_stats2:1;
		unsigned report_hosts:16;
		unsigned report_nmap:16;
		unsigned report_fanout:16;
		unsigned report_fanin:16;
		unsigned report_filter_stats:1;
		unsigned report_ciphersuites:16;
		unsigned report_start:1;
		unsigned quiet:1; /* global quiet flag that turns off reporting with -q on the command line */
		unsigned is_speed_timer:1;
		unsigned is_wifi_slow:1;
		char *echo;
	} cfg;

	char interface_name[256];
	unsigned interface_channel;

	time_t interface_last_activity;
	time_t interface_last_channel_change;
	time_t now;
	time_t first;
	unsigned interface_interval_inactive;
	unsigned interface_interval_active;

	/**
	 * The name of an SSID to search for. This will cause us to scan through
	 * channels listening to all the SSIDs, then once we find the specified
	 * channel, will stay on that channel
	 */
	char interface_search[257];

	/**
	 * Streamer
	 */
	struct {
		/** Reflects the total count of segments in the system,
		 * which can be tested against the max number of segments 
		 * to prevent the system from allocating too many */
		unsigned segment_count;

		/** The maximum number of segments possible */
		unsigned max_segments;

		/** A list of freed segments, so we don't have to stress
		 * the malloc()/free() operators too much, we can instead
		 * realloc a recently used segment */
		struct TCP_segment *segments;
	} streamer;


	struct InFilter filter;

	struct Statistics statistics;
	struct Stats2 stats2;

	struct SniffFilter *sniff_filters;

	struct Listener *listener;

	struct ReportHosts *report_hosts;

	struct ReportNmap *report_nmap;

	struct ReportFanout *report_fanout;

	struct ReportCipherSuites *report_ciphersuites;

	struct ProtoPPP *proto_ppp;
};

struct Ferret *ferret_create();
void ferret_destroy(struct Ferret *result);



/**
 * Remember that we saw this beacon packet. This is so that when we 
 * are sniffing raw captures, we can avoid filling up our log files
 * with beacon packets. */
unsigned ferret_remember_beacon(struct Ferret *ferret, const unsigned char *macaddr, const unsigned char *bssid, const unsigned char *ssid, size_t ssid_length, unsigned channel, unsigned type, time_t secs);

/**
 * When "searching" for an SSID, this tests to see if we have found the desired SSID on a 
 * certain channel. If so, we'll change to that channel and stay there to monitor everything.
 */
unsigned beacon_get_channel_from_ssid(struct Ferret *ferret, const char *ssid, unsigned ssid_length);


void 
ferret_set_parameter(struct Ferret *ferret, const char *name, const char *value, unsigned depth);


/**
 * Filter out a MAC address. This is called by layer-2 parsers like the
 * Ethernet or wifi-802.11 parsers. This will return 1 if the MAC address
 * is in the filter list, or 0 if it isn't. If the MAC address is found,
 * then the system should drop the packet and ignore it.
 */
int
ferret_infilter_mac(struct Ferret *ferret, const unsigned char *mac_addr);


void 
config_echo(struct Ferret *ferret, FILE *fp);

unsigned
ferret_snarf_id(struct Ferret *ferret);
void 
ferret_snarf(struct Ferret *ferret, const char *filename, const unsigned char *px, unsigned length);

#ifdef __cplusplus
}
#endif
#endif /*__FERRET_H*/
