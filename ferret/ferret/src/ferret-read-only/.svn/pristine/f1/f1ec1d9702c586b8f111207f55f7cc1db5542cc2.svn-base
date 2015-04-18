/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "ferret.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "stack-extract.h"
#include "stack-netframe.h"
#include "stream-unknown.h"
#include "util-housekeeping.h"
#include "util-hexval.h"
#include "platform.h"
#include "filters.h"
#include "report.h"

static unsigned cfg_prefix(const char *name, const char *prefix, unsigned offset)
{
	unsigned i, p;

	if (name[offset] == '.')
		offset++;

	for (i=offset, p=0; name[i] && prefix[p]; i++, p++)
		if (name[i] != prefix[p])
			return 0;
	if (prefix[p] == '\0')
		return i;
	else
		return 0;
}

static unsigned
parse_boolean(const char *value)
{
	switch (value[0]) {
	case '1': /*1*/
	case 'y': /*yes*/
	case 'Y': /*YES*/
	case 'e': /*enabled*/
	case 'E': /*ENABLED*/
	case 't': /*true*/
	case 'T': /*TRUE*/
		return 1;
	case 'o': /*on/off*/
	case 'O': /*ON/OFF*/
		if (value[1] == 'n' || value[1] == 'N')
			return 1;
	}
	return 0;
}

static void log_choice(FILE *fp, const char *name, unsigned num, const char *choices)
{
	unsigned i;

	for (i=0; *choices; i++) {
		if (i == num) {
			fprintf(fp, "%s = %s\n", name, choices);
			return;
		}

		choices += strlen(choices)+1;
	}
}


/**
 * Parse a MAC address from hex input. It can be in a number of
 * formats, such as:
 *	[00:00:00:00:00:00]
 *  00-00-00-00-00-00
 *  000000000000
 */
static void
parse_mac_address(unsigned char *dst, size_t sizeof_dst, const char *src)
{
	unsigned i=0;
	unsigned found_non_xdigit=0;
	unsigned premature_end=0;

	if (*src == '[')
		src++;

	while (*src && i<6) {
		if (!isxdigit(*src))
			found_non_xdigit = 1;
		else {
			unsigned c;

			c = hexval(*src);
			src++;
			if (*src == '\0')
				premature_end=1;
			else if (!isxdigit(*src))
				found_non_xdigit = 1;
			else {
				c = c<<4 | hexval(*src);
				src++;
			}

			if (i<sizeof_dst)
				dst[i++] = (unsigned char)c;
			
			if (*src && ispunct(*src))
				src++;
		}
	}

	if (premature_end)
		fprintf(stderr, "premature end parsing MAC address\n");

	if (found_non_xdigit)
		fprintf(stderr, "parse_mac_address: non hex-digit found\n");
}

/**
 * Echo the configuration to a log file
 */
void 
config_echo(struct Ferret *ferret, FILE *fp)
{
	unsigned i;

#define LOG_BOOL(name,x) fprintf(fp, "%s = %s\n", name, ((x)?"true":"false"))
#define LOG_SZ(name,x) fprintf(fp, "%s = %s\n", name, x)
#define LOG_NUM(name,x) fprintf(fp, "%s = %u\n", name, x)

	if (ferret->is_offline)
		LOG_SZ("interface.name", "<files>");
	else
		LOG_SZ("interface.name", ferret->interface_name);
	LOG_BOOL("interface.checkfcs", ferret->cfg.interface_checkfcs);
	LOG_BOOL("interface.scan", ferret->cfg.interface_scan);
	LOG_NUM("interface.interval.inactive", ferret->interface_interval_inactive);
	LOG_NUM("interface.interval.active", ferret->interface_interval_active);
	LOG_SZ("sniffer.directory", ferret->output.directory);
	LOG_SZ("sniffer.filename", ferret->output.filename);
	log_choice(fp, "sniffer.mode", ferret->output.sniff, "none\0all\0most\0ivs\0sift\0proto\0\0");
	LOG_SZ("snarfer.directory", ferret->snarfer.directory);
	log_choice(fp, "snarfer.mode", ferret->snarfer.mode, "none\0all\0most\0\0");
	log_choice(fp, "vector.mode", ferret->cfg.no_vectors, "sift\0none\0\0");
	log_choice(fp, "hamster.mode", ferret->cfg.no_hamster, "sift\0none\0\0");
	LOG_BOOL("statistics.print", ferret->cfg.statistics_print);
	LOG_BOOL("report.stats", ferret->cfg.report_stats2);
	LOG_NUM("report.hosts", ferret->cfg.report_hosts);
	LOG_NUM("report.nmap", ferret->cfg.report_nmap);
	LOG_NUM("report.suites", ferret->cfg.report_ciphersuites);
	LOG_NUM("report.fanout", ferret->cfg.report_fanout);
	LOG_NUM("report.fanin", ferret->cfg.report_fanin);
	LOG_BOOL("config.quiet", ferret->cfg.quiet);

	/* Print the MAC addresses that we are filtering out */
	for (i=0; i<ferret->filter.mac_address_count; i++) {
		const unsigned char *mac = ferret->filter.mac_address[i];

		fprintf(fp, "filter.mac[%u] = [%02x:%02x:%02x:%02x:%02x:%02x]\n", 
			i,
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

}


/**
 * Called by OSI Layer 2 parsers (like WiFi and Ethernet) to ignore 
 * a list of MAC addresses.
 *
 * Right now, this is a terribly inefficient linear search, it really
 * should be a more efficient table
 */
int
ferret_infilter_mac(struct Ferret *ferret, const unsigned char *mac_addr)
{
	unsigned i;

	for (i=0; i<ferret->filter.mac_address_count; i++) {
		if (memcmp(mac_addr, ferret->filter.mac_address[i], 6) == 0)
			return 1;
	}
	return 0;
}

/**
 * Figures out whether the specified filename is a directory or normal
 * file. This is useful when recursing directories -- such as reading in
 * all packet-capture files in a directory structure for testing.
 */
static int
is_directory(const char *filename)
{
	struct stat s;

	if (stat(filename, &s) != 0) {
		/* Not found, so assume a "file" instead of "directory" */
		return 0;
	} else if (!(s.st_mode & S_IFDIR)) {
		/* Directory flag not set, so this is a "file" not a "directory" */
		return 0;
	}
	return 1;
}

/**
 * Parse <name=value> pairs from either a configuration file or from the 
 * command-line. This is the primary way the system is configured. This 
 * function will dispatch similar XXX_set_parameter() function based 
 * upon the leading keyword of the configuration parameter.
 */
void 
ferret_set_parameter(struct Ferret *ferret, const char *name, const char *value, unsigned depth)
{
	unsigned x=0;

	if (depth > 10)
		return;
	
	/* This macro is defined to match the leading keyword */
	#define MATCH(str) cfg_prefix(name, str, x) && ((x=cfg_prefix(name, str, x))>0)

	if (MATCH("filter")) {
		filter_set_parameter(ferret, name, value);
		ferret_set_parameter(ferret, "report", "filter", depth);
		return;
	}

	if (MATCH("config")) {
		if (MATCH("echo")) {
			ferret->cfg.echo = strdup(value);
		} else if (MATCH("quiet")) {
			ferret->cfg.quiet = parse_boolean(value);
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
	} else

	if (MATCH("interface")) {
		if (MATCH("checkfcs")) {
			ferret->cfg.interface_checkfcs = parse_boolean(value);
		} else if (MATCH("scan")) {
			ferret->cfg.interface_scan = parse_boolean(value);
		} else if (MATCH("interval")) {
			if (MATCH("inactive"))
				ferret->interface_interval_inactive = strtoul(value,0,0);
			else if (MATCH("active"))
				ferret->interface_interval_active = strtoul(value,0,0);
			
		} else if (MATCH("name")) {
			strcpy_s(ferret->interface_name, sizeof(ferret->interface_name), value);
			ferret->is_live = 1;
		} else if (MATCH("search")) {
			strcpy_s(ferret->interface_search, sizeof(ferret->interface_search), value);
			ferret->is_live = 1;
		} else if (MATCH("channel")) {
			if (value && *value && isdigit(*value)) {
				ferret->interface_channel = strtoul(value,0,0);
			}
		}
	} else if (MATCH("speed.timer")) {
		ferret->cfg.is_speed_timer = 1;
	} else if (MATCH("vector")) {
		if (MATCH("mode")) {
			if (strcmp(value, "none")==0)
				ferret->cfg.no_vectors = 1;
		}
	} else if (MATCH("hamster")) {
		if (MATCH("mode")) {
			if (strcmp(value, "none")==0)
				ferret->cfg.no_hamster = 1;
		}
	} else if (MATCH("filter")) {
		if (MATCH("mac")) {
			/* Parse the MAC address in the value field and add it
			 * to the end of our list of MAC address filters.
			 * TODO: we should probably sort these and/or check
			 * for duplicates */
			unsigned char **newfilters = (unsigned char**)malloc((ferret->filter.mac_address_count+1)*sizeof(unsigned char*));
			unsigned i;
			for (i=0; i<ferret->filter.mac_address_count; i++)
				newfilters[i] = ferret->filter.mac_address[i];
			newfilters[i] = (unsigned char*)malloc(6);
			memset(newfilters[i], 0xa3, 6);
			parse_mac_address(newfilters[i], 6, value);
			if (ferret->filter.mac_address)
				free(ferret->filter.mac_address);
			ferret->filter.mac_address = newfilters;
			ferret->filter.mac_address_count++;
		}
	} else if (MATCH("include")) {
		FILE *fp;
		char line[2048];

		fp = fopen(value, "rt");
		if (fp == NULL) {
			fprintf(stderr, "%sreading configuration file\n", "ERR:CFG: ");
			perror(value);
			return;
		}

		while (fgets(line, sizeof(line), fp)) {
			char *name;
			char *value;

			name = line;
			value = strchr(line, '=');
			if (value == NULL)
				continue;
			*value = '\0';
			value++;

			while (*name && isspace(*name))
				memmove(name, name+1, strlen(name));
			while (*value && isspace(*value))
				memmove(value, value+1, strlen(value));
			while (*name && isspace(name[strlen(name)-1]))
				name[strlen(name)-1] = '\0';
			while (*value && isspace(value[strlen(value)-1]))
				value[strlen(value)-1] = '\0';

			ferret_set_parameter(ferret, name, value, depth+1);

		}
	} else if (MATCH("statistics")) {
		ferret->cfg.statistics_print = parse_boolean(value);
		if (ferret->cfg.statistics_print) {
			ferret->cfg.no_hamster = 1;
			ferret->cfg.no_vectors = 1;
		}
	} else if (MATCH("report")) {
		if (ferret->cfg.report_start == 0) {
			ferret->cfg.no_hamster = 1;
			ferret->cfg.no_vectors = 1;
			ferret->cfg.statistics_print = 0;
			ferret->cfg.report_start = 1;
		}
		if (MATCH("host")) {
			if (MATCH("addr")) {
				report_hosts_set_parameter(ferret, "addr", value);
			} else
				ferret->cfg.report_hosts = strtoul(value,0,0);
		} else if (MATCH("nmap")) {
			if (MATCH("addr")) {
				report_hosts_set_parameter(ferret, "addr", value);
			} else
				ferret->cfg.report_nmap = strtoul(value,0,0);
		} else if (MATCH("fanout")) {
			if (MATCH("addr")) {
				report_fanout_set_parameter(ferret, "addr", value);
			} else
				ferret->cfg.report_fanout = strtoul(value,0,0);
		} else if (MATCH("fanin")) {
			if (MATCH("addr")) {
				report_fanout_set_parameter(ferret, "addr", value);
			} else
				ferret->cfg.report_fanin = strtoul(value,0,0);
		} else if (memcmp(value, "stat", 4)==0)
			ferret->cfg.report_stats2 = 1;
		else if (memcmp(value, "host", 4)==0)
			ferret->cfg.report_hosts = 20;
		else if (memcmp(value, "nmap", 4)==0)
			ferret->cfg.report_nmap = 20;
		else if (memcmp(value, "fanout", 4)==0)
			ferret->cfg.report_fanout = 20;
		else if (memcmp(value, "fanin", 4)==0)
			ferret->cfg.report_fanin = 20;
		else if (memcmp(value, "filter", 4)==0)
			ferret->cfg.report_filter_stats = 1;
		else if (memcmp(value, "suites", 6)==0)
			ferret->cfg.report_ciphersuites = 20;
		else
			fprintf(stderr, "cfg: unknown: -%s=%s\n", name, value);
	} else if (MATCH("regress")) {
        ferret->is_regress = 1;
	} else if (MATCH("sniffer")) {
		if (MATCH("dir")) {
			const char *directory_name = value;
			size_t directory_length = strlen(directory_name);
			char *p;

			if (directory_length > sizeof(ferret->output.directory)-1) {
				fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
			if (ferret->output.directory[0]) {
				fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, ferret->output.directory);
				fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}

			/* Remove trailing spaces and slashes */
			p = ferret->output.directory;
			while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
				p[strlen(p)-1] = '\0';

			strcpy_s(ferret->output.directory, sizeof(ferret->output.directory), directory_name);
			return;
		} else if (MATCH("filename")) {
			if (is_directory(value)) {
				ferret_set_parameter(ferret, "sniffer.directory", value, depth);
				return;
			}
			strcpy_s(ferret->output.filename, sizeof(ferret->output.filename), value);
			if (ferret->output.sniff == FERRET_SNIFF_NONE)
				ferret->output.sniff = FERRET_SNIFF_MOST;
			if (ferret->output.noappend == 0)
				ferret->output.noappend = 1;
		} else if (MATCH("mode")) {
			if (strcmp(value, "all")==0)
				ferret->output.sniff = FERRET_SNIFF_ALL;
			else if (strcmp(value, "most")==0)
				ferret->output.sniff = FERRET_SNIFF_MOST;
			else if (strcmp(value, "ivs")==0)
				ferret->output.sniff = FERRET_SNIFF_IVS;
			else if (strcmp(value, "sift")==0)
				ferret->output.sniff = FERRET_SNIFF_SIFT;
			else if (strcmp(value, "none")==0)
				ferret->output.sniff = FERRET_SNIFF_NONE;
			else {
				fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
		} else if (MATCH("noappend")) {
			ferret->output.noappend = parse_boolean(value);
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
	} else if (MATCH("snarfer")) {
		if (MATCH("dir")) {
			const char *directory_name = value;
			size_t directory_length = strlen(directory_name);
			char *p;

			if (directory_length > sizeof(ferret->snarfer.directory)-1) {
				fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
			if (ferret->snarfer.directory[0]) {
				fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, ferret->snarfer.directory);
				fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}

			/* Remove trailing spaces and slashes */
			p = ferret->snarfer.directory;
			while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
				p[strlen(p)-1] = '\0';

			strcpy_s(ferret->snarfer.directory, sizeof(ferret->snarfer.directory), directory_name);
			return;
		} else if (MATCH("mode")) {
			if (strcmp(value, "all")==0)
				ferret->snarfer.mode = FERRET_SNIFF_ALL;
			else if (strcmp(value, "most")==0)
				ferret->snarfer.mode = FERRET_SNIFF_MOST;
			else if (strcmp(value, "none")==0)
				ferret->snarfer.mode = FERRET_SNIFF_NONE;
			else {
				fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

	} else
		fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

}

/**
 * Sets the default configuration
 */
void ferret_defaults(struct Ferret *ferret)
{
	ferret->interface_channel = 6;
	ferret->interface_interval_inactive = 3;
	ferret->interface_interval_active = 5*60;
	ferret->is_verbose = 1; /* verbose items, like HTTP cookies */
}

static struct FerretEngine *
engine_create(struct Ferret *ferret)
{
	struct FerretEngine *engine;

	engine = (struct FerretEngine*)malloc(sizeof(*engine));
	if (engine == NULL)
		return 0;
	memset(engine, 0, sizeof(*engine));

	engine->ferret = ferret;

	/*
	 * Create a housekeeping object for this engine. This does things
	 * like timeout TCP connections.
	 */
	engine->housekeeper = housekeeping_create();

    engine->tcp_smells = tcpsmellslike_create_engine();

	return engine;
}

/**
 * Create an instance of the FERRET object, please
 * cleanup with 'ferret_destroy()'.
 */
struct Ferret *ferret_create()
{
	struct Ferret *result;

	result = (struct Ferret*)malloc(sizeof(*result));
	if (result == NULL)
		return 0;
	memset(result, 0, sizeof(*result));

	/* Create the "JOTDOWN" module */
	result->jot = jotdown_create();

	/* Create a single "APP-INST" to begin with */
	result->eng[result->engine_count++] = engine_create(result);




	ferret_defaults(result);

	return result;
}


void engine_destroy(struct FerretEngine *engine)
{
	if (engine == NULL)
		return;

	/* Destroy the housekeeping object */
	housekeeping_destroy(engine->housekeeper);
	engine->housekeeper = NULL;

	stringtab_clear(engine->stringtab);

    tcpsmellslike_destroy_engine(engine->tcp_smells);

	free(engine);
}


void ferret_remember_beacon_cleanup(struct Ferret *ferret)
{
	static const size_t entry_count = sizeof(ferret->beacons)/sizeof(ferret->beacons[0]);
	unsigned i;
	/* This is a hash table followed by linked lists. We need to
	 * go through and clean up all the linked entries */
	for (i=0; i<entry_count; i++) {
		while (ferret->beacons[i].next) {
			struct BeaconEntry *entry;
			entry = ferret->beacons[i].next;
			ferret->beacons[i].next = entry->next;
			free(entry);
		}
	}
}

/**
 * Destroys the instance created by 'ferret_create()'
 */
void ferret_destroy(struct Ferret *ferret)
{
	unsigned i;

	ipv6_fragment_free_all(ferret);

	for (i=0; i<ferret->engine_count; i++)
		engine_destroy(ferret->eng[i]);

	jotdown_destroy(ferret->jot);

	ferret_remember_beacon_cleanup(ferret);

	free(ferret);
}


/**
 * BEACON FILTER:
 *	This is a bit of a kludge to filter out beacon packets when saving
 *	packet captures. On a typical wifi network, 90% of packets will be
 *	the constant beacon activity. Therefore, this bit of code will
 *	remember recent beacon traffic and notify the rest of the system
 *	when the beacon is a repeat. The system forgets about beacons
 *	every so often, which will cause the occasional duplicate beacon
 *	to appear in the capture. This is fine: a few beacons now and then
 *	are good, many beacons a second are not.
 */
unsigned 
ferret_remember_beacon(
	struct Ferret *ferret, 
	const unsigned char *macaddr, 
	const unsigned char *bssid, 
	const unsigned char *ssid, size_t ssid_length,
	unsigned channel,
	unsigned type, 
	time_t now)
{
	uint64_t hash = 0;
	unsigned i;
	static const size_t entry_count = sizeof(ferret->beacons)/sizeof(ferret->beacons[0]);
	struct BeaconEntry *entry;
	unsigned index;

	/* 
	 * Timeout old entries 
	 */
	if (ferret->beacon_last_housekeeping != ferret->now) {
		for (i=0; i<entry_count; i++) {
			struct BeaconEntry *entry = &ferret->beacons[i];

			while (entry) {
				if (entry->hash != 0 && entry->when+15 < now)
					entry->hash = 0;
				entry = entry->next;
			}
		}

		ferret->beacon_last_housekeeping = ferret->now;
	}

	/*
	 * Hash the beacon data
	 */
	hash = type;
	for (i=0; i<6; i++) {
		const uint64_t z = macaddr[i];
		hash ^= z<<(8*(i&0x7));
	}
	for (i=0; i<6; i++) {
		const uint64_t z = bssid[i];
		hash ^= z<<(8*((6+i)&0x7));
	}
	for (i=0; i<ssid_length; i++) {
		const uint64_t z = ssid[i];
		hash ^= z<<(8*((12+i)&0x7));
	}


	/* Look for existing entry */
	index = (unsigned)(hash%(uint64_t)(sizeof(ferret->beacons)/sizeof(ferret->beacons[0])));
	
	entry = &ferret->beacons[index];
	
	while (entry) {
		if (entry->hash == hash) {
			entry->count++;
			return 0;
		}
		entry = entry->next;
	}

	/* Fall through: if we don't find it, then we'll fall through below
	 * and create a new entry */

	/* We didn't find an existing entry, so create one for this beacon */
	entry = &ferret->beacons[index];
	
	if (entry->hash != 0) {
		struct BeaconEntry **r_entry = &entry->next;
		while (*r_entry) {
			if ((*r_entry)->hash == 0)
				break;
			r_entry = &(*r_entry)->next;
		}
		if (*r_entry == NULL) {
			*r_entry = (struct BeaconEntry*)malloc(sizeof(**r_entry));
			(*r_entry)->next = 0;
		}
		entry = *r_entry;
	}

	if (ssid_length > 256)
		ssid_length = 256;
	memcpy(entry->ssid, ssid, ssid_length);
	entry->ssid[ssid_length] = '\0';
	entry->ssid_length = (unsigned)ssid_length;
	memcpy(entry->bssid, bssid, 6);
	entry->channel = channel;
	entry->hash = hash;
	entry->count = 0;
	entry->when = now;
	return 1;
}

/* lookup a channel based on SSID */
unsigned
beacon_get_channel_from_ssid(struct Ferret *ferret, const char *ssid, unsigned ssid_length)
{
	unsigned i;

	for (i=0; i<sizeof(ferret->beacons)/sizeof(ferret->beacons[0]); i++) {
		struct BeaconEntry *entry;

		entry = &ferret->beacons[i];

		while (entry) {
			if (entry->ssid[0]) {
				if (entry->ssid_length == ssid_length && memcmp(entry->ssid, ssid, ssid_length) == 0) {
					return entry->channel;
				}
			}
			entry = entry->next;
		}
	}
	return 0;
}


unsigned
ferret_snarf_id(struct Ferret *ferret)
{
	return ferret->snarfer.id++;
}

void 
ferret_snarf(struct Ferret *ferret, const char *filename, const unsigned char *px, unsigned length)
{
	struct Snarfer *snarf = &ferret->snarfer;
	unsigned i;
	FILE *fp = NULL;

	UNUSEDPARM(length); UNUSEDPARM(px); 

	/* First, see if we have the file already open */
	for (i=0; i<sizeof(snarf->files)/sizeof(snarf->files[0]); i++) {
		if (strcmp(snarf->files[i].filename, filename) == 0) {
			fp = snarf->files[i].fp;
			break;
		}
	}

	/* If we don't have an open slot, then createa a new slot (by getting 
	 * rid of the oldes) and open the file */
	if (fp == NULL) {
		char newfile[256];

		if (snarf->directory[0] == '\0')
			snarf->directory[0] = '.';

		sprintf_s(newfile, sizeof(newfile), "%s/%s", ferret->snarfer.directory, filename);

	}


}
