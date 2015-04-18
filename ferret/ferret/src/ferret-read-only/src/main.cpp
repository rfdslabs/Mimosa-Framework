/* Copyright (c) 2007-2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "ferret.h"
#include "report.h"
#include "filters.h"
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>

#include "stack-extract.h"
#include "stack-netframe.h"
#include "stack-parser.h"
#include "util-hamster.h"


#ifdef WIN32
#include <direct.h> /* for Posix mkdir() */
#endif

#include "in-pcaplive.h"
#include "in-pcapfile.h"
#include "util-mystring.h"

#include "pixie.h"

/**
 * This structure is initialized with 'pcap_init()' at the beginning
 * of the 'main()' function to runtime load the libpcap library.
 */
struct PCAPLIVE pcap;
pcap_if_t *alldevs;



int debug=0;


extern "C" void VALIDATE(int exp)
{
	if (!exp)
		printf("(.X)");
}

void FRAMERR(struct NetFrame *frame, const char *msg, ...)
{
	va_list marker;

	if (debug==0)
		return;

	va_start(marker, msg);

	fprintf(stderr, "%s(%d): ", frame->filename, frame->frame_number);

	vfprintf(stderr, msg, marker);

	va_end(marker);
}

unsigned control_c_pressed=0;

void control_c_handler(int sig)
{
	UNUSEDPARM(sig);
	control_c_pressed = 1;
}



/**
 * Verifies that a directory exists, this will create the directory
 * if necessary.
 */
int verify_directory(const char *dirname)
{
	char part[256];
	size_t i;
	struct stat s;

	/* Starting condition: when it starts with a slash */
	i=0;
	if (dirname[i] == '/' || dirname[i] == '\\')
		i++;

	/* move forward until next slash */
again:
	while (dirname[i] != '\0' && dirname[i] != '/' && dirname[i] != '\\')
		i++;
	memcpy(part, dirname, i);
	part[i] = '\0';


	/* Make sure it exists */
	if (stat(part, &s) != 0) {
#ifdef WIN32
		_mkdir(part);
#else
		mkdir(part, 0777);
#endif
	} else if (!(s.st_mode & S_IFDIR)) {
		fprintf(stderr, "%s: not a directory\n", part);
		return -1;
	}

	if (dirname[i] == '\0')
		return 0;
	else {
		while (dirname[i] == '/' || dirname[i] == '\\')
			i++;
		goto again;
	}
}

/**
 * This is a small packet sniffer function that either sniffs
 * all packets, most of them (ignoring common repeats, like beacon
 * frames), just the IVS for WEP cracking, or just the ones that
 * trigger data to be generated.
 *
 * The packets are appended to rotating logfiles in the specified
 * directory.
 */
void sniff_packets(struct Ferret *ferret, const unsigned char *buf, const struct NetFrame *frame)
{
	time_t now;
	struct tm *ptm;


	/* First, test if we are allowed to capture this packet into a file */
	switch (ferret->output.sniff) {
	case FERRET_SNIFF_NONE:
		return;
	case FERRET_SNIFF_ALL:
		break;
	case FERRET_SNIFF_MOST:
		if (frame->flags.found.repeated)
			return;
		break;
	case FERRET_SNIFF_IVS:
		if (!frame->flags.found.ivs)
			return;
		break;
	case FERRET_SNIFF_SIFT:
		if (!ferret->something_new_found)
			return;
		break;
	case FERRET_SNIFF_FILTER:
		{
			unsigned include=0, exclude=0;
			filter_eval(ferret->sniff_filters, frame, &include, &exclude);
			if (exclude)
				return;
			if (!include)
				return;
		}
		break;
	default:
		return;
	}


	/* If we don't have a file open for sniffing, then open one. Also,
	 * if the linktype changes, we need to close the previous file we
	 * were writing to and open a new one to avoid mixing frames incorrectly.
	 */
	if (ferret->output.pf == NULL || ferret->output.linktype != ferret->linktype) {
		char filename[256];
		char linkname[16];

		if (ferret->output.pf) {
			pcapfile_close(ferret->output.pf);
			ferret->output.pf = NULL;
		}

		switch (ferret->linktype) {
		case 1:
			strcpy_s(linkname, sizeof(linkname), "eth");
			break;
		case 0x69:
			strcpy_s(linkname, sizeof(linkname), "wifi");
			break;
		default:
			sprintf_s(linkname, sizeof(linkname), "%d", ferret->linktype);
			break;
		}



		/* Format the current time */
		now = time(0);
		ptm = localtime(&now);

		if (ferret->output.filename[0]) {
			strcpy_s(filename, sizeof(filename), ferret->output.filename);
		} else {
			/* make sure we have a directory name */
			if (ferret->output.directory[0] == '\0') {
				ferret->output.directory[0] = '.';
				ferret->output.directory[1] = '\0';
			}
			/* Make sure the directory exists */
			if (verify_directory(ferret->output.directory) == -1) {
				/* oops, error creating directory, so just exit */
				return;
			}

			sprintf_s(filename, sizeof(filename), "%s/sniff-%04d-%02d-%02d-%s.pcap",
				ferret->output.directory,
				ptm->tm_year+1900,
				ptm->tm_mon+1,
				ptm->tm_mday,
				linkname
				);
		}

		/*
		 * Normally, we append to files (because we need to keep so many open,
		 * we temporarily close some).
		 */
		if (ferret->output.noappend)
			ferret->output.pf = pcapfile_openwrite(filename, ferret->linktype);
		else
			ferret->output.pf = pcapfile_openappend(filename, ferret->linktype);


		ferret->output.linktype = ferret->linktype;
		ferret->output.pf_opened = time(0); /* now */
	}


	if (ferret->output.pf) {

		if (frame->flags.found.bad_fcs && !ferret->output.include_fcs_err)
			return;
		if (frame->flags.found.filtered)
			return;

		pcapfile_writeframe(ferret->output.pf, buf, frame->captured_length, frame->original_length,
			frame->time_secs, frame->time_usecs);

		/* Close the file occasionally to make sure it's flushed to the disk */
		if (!ferret->output.noappend)
		if (ferret->output.pf_opened+600 < time(0)) {
			pcapfile_close(ferret->output.pf);
			ferret->output.pf = NULL;
		}
	}

	

}

void pcapHandlePacket(unsigned char *v_seap, 
    const struct pcap_pkthdr *framehdr, const unsigned char *buf)
{
	static struct NetFrame frame[1];
	struct Ferret *ferret = (struct Ferret*)v_seap;

	memset(frame,0,sizeof(*frame));

	frame->filename = "live";
	frame->layer2_protocol = ferret->linktype;
	frame->frame_number++;
	
	frame->time_secs = framehdr->ts.tv_sec;
	frame->time_usecs = framehdr->ts.tv_usec;
	frame->original_length = framehdr->len;
	frame->captured_length = framehdr->caplen;
	frame->layer2_protocol = ferret->linktype;	


	/* Wrap in try/catch block */
	try {
		process_frame(ferret, frame, buf, frame->captured_length);
	} catch (...) {
		struct PcapFile *pf;
		char filename[256];
		time_t now;
		struct tm *ptm;

		if (ferret->is_live) {

			/* Make sure we get a copy of this packet */
			sniff_packets(ferret, buf, frame);
			if (ferret->output.pf)
				pcapfile_close(ferret->output.pf);

			/* A packet caused us to crash. Therefore, create an output file
			 * and copy the packet to it so that we can investigate the problem */
			now = time(0);
			ptm = localtime(&now);

			sprintf_s(filename, sizeof(filename), "crash-%04d-%02d-%02d.pcap",
				ptm->tm_year+1900,
				ptm->tm_mon+1,
				ptm->tm_mday
				);

			pf = pcapfile_openappend(filename, ferret->linktype);
			if (pf) {
				pcapfile_writeframe(pf, buf, frame->captured_length, frame->original_length,
					frame->time_secs, frame->time_usecs);
				pcapfile_close(pf);
			}
		}

		if (!ferret->is_ignoring_errors)
			throw;
	}

	if (frame->flags.found.repeated)
		ferret->statistics.repeated++;

	sniff_packets(ferret, buf, frame);

	if (ferret->something_new_found)
		ferret->interface_last_activity = frame->time_secs;


}

/**
 * Return the name of the type of link giving it's numeric identifier
 */
const char *
get_link_name_from_type(unsigned linktype)
{
	switch (linktype) {
	case 0: return "UNKNOWN";
	case 1: return "Ethernet";
	case 105: return "WiFi";
	case 109: return "WiFi-Prism";
	case 127: return "WiFi-Radiotap";
	default: return "";
	}
}


/**
 * Configure or re-configure the channel on the specified WiFi interface.
 */
static void
wifi_set_channel(struct Ferret *ferret, void *hPcap, unsigned channel)
{

#ifdef __linux
	{
		char cmd[256];
		sprintf_s(cmd, sizeof(cmd), "iwconfig %s channel %u\n", ferret->interface_name, channel);
		fprintf(stderr, "CHANGE: %s", cmd);
		system(cmd);
	}
#endif
#ifdef WIN32
	{
		void *h = pcap.get_airpcap_handle(hPcap);
		if (h == NULL) {
			fprintf(stderr, "ERR: Couldn't get Airpcap handle\n");
		} else {
			if (pcap.airpcap_set_device_channel(h, channel) != 1) {
				fprintf(stderr, "ERR: Couldn't set '%s' to channel %d\n", ferret->interface_name, channel);
			} else
				fprintf(stderr, "CHANGE: monitoring channel %d on wifi interface %s\n", channel, ferret->interface_name);
		}
	}
#endif

	/* Remember when we last changed the channel, so that when searching
	 * through channels, we know not to stay on the same channel for too
	 * long. */
	ferret->interface_last_channel_change = time(0);
}

/**
 * Return TRUE if the linktype is wifi
 */
static unsigned
is_wireless(unsigned linktype)
{
	switch (linktype) {
	case 105: /* wifi radiotap */
	case 109: /* wifi prism */
	case 127: /* wifi raw */
		return 1;
	default:
		return 0;
	}
}

/**
 * This is called by "main()" to monitor an interface. This will continue
 * until the user presses <ctrl-c>, or if an error occurs on the interface
 */
void process_live(struct Ferret *ferret, const char *devicename)
{
    int traffic_seen = 0;
    int total_packets_processed = 0;
    void *hPcap;
    char errbuf[1024];
	int is_promiscuous = 1;

	ferret->interface_last_activity = time(0);

	/* Under Windows, the Intel 2200BG card cannot open the adapter in
	 * promiscuous mode. We can either error out, or we can change the
	 * mode to non-promiscuous, which will allow the user to at least
	 * monitor their own connection */
	if (strstr(devicename, "PRO/Wireless 2200BG"))
		is_promiscuous = 0;

	/*
	 * Open the adapter
	 */
    hPcap = pcap.open_live( devicename,
                            2000,				/*snap len*/
                            is_promiscuous,
                            10,					/*10-ms read timeout*/
                            errbuf
                            );
    if (hPcap == NULL) {
        fprintf(stderr, "%s: %s\n", devicename, errbuf);
        return;
    }
	ferret->linktype = pcap.datalink(hPcap);
	fprintf(stderr, "SNIFFING: %s\n", devicename);
	fprintf(stderr, "LINKTYPE: %d %s\n", ferret->linktype, get_link_name_from_type(ferret->linktype));
	if (is_wireless(ferret->linktype)) {
		if (ferret->interface_channel != 0) {
			wifi_set_channel(ferret, hPcap, ferret->interface_channel);
		}
	}

	/*
	 * If doing WiFi search
	 */
	if (is_wireless(ferret->linktype))
	while (ferret->interface_search != 0 && ferret->interface_search[0] != 0) {
		unsigned i;

		/* go through all channels */
		for (i=1; i<14 && !control_c_pressed; i++) {
			clock_t timeof_last_channel_change = clock();

			wifi_set_channel(ferret, hPcap, i);
	
			/* Monitor this channel for a while */
			while (!control_c_pressed) {
				int packets_read;
				clock_t time_since_last_channel_change;

				/* Read the next packet */
				packets_read = pcap.dispatch(
										hPcap, /*handle to PCAP*/
										10,        /*next 10 packets*/
										pcapHandlePacket, /*callback*/
										(unsigned char*)ferret);
				if (packets_read < 0) {
					control_c_pressed = 1;
					break;
				}

				/* Handle "traffic seen" message */
				total_packets_processed += packets_read;
				if (!traffic_seen && total_packets_processed > 0) {
					fprintf(stderr, "Traffic seen\n");
					traffic_seen = 1;
				}

				/* See if it's time to change channels */
				time_since_last_channel_change = clock() - timeof_last_channel_change;
				if (time_since_last_channel_change > CLOCKS_PER_SEC/5) {
					break;
				}
			} /* end 'monitor channel for a while' */
		} /*end 'for all channels */

		/*
		 * Now that we have scanned all the channels, let's see if
		 * any of the channels has the SSID we are looking for
		 */
		{
			unsigned channel;

			channel = beacon_get_channel_from_ssid(ferret, &ferret->interface_search[0], (unsigned)strlen(ferret->interface_search));
			if (channel != 0) {
				fprintf(stderr, "\nFOUND: \"%s\" on channel %u\n", ferret->interface_search, channel);
				ferret->interface_channel = channel;
				wifi_set_channel(ferret, hPcap, channel);
				break;
			}
		}

	}

    /* 
	 * MAIN LOOOP
	 *
	 * Sit in this loop forever, reading packets from the network then
	 * processing them.
	 */
    while (!control_c_pressed) {
        int packets_read;

		packets_read = pcap.dispatch(
								hPcap, /*handle to PCAP*/
								10,        /*next 10 packets*/
								pcapHandlePacket, /*callback*/
								(unsigned char*)ferret);
		
		if (packets_read < 0)
			break;
        total_packets_processed += packets_read;
        if (!traffic_seen && total_packets_processed > 0) {
            fprintf(stderr, "Traffic seen\n");
            traffic_seen = 1;
        }
		//printf(".");


		/* If we have had no recent activity on the current wifi channel, then
		 * switch it */
		if (ferret->cfg.interface_scan && is_wireless(ferret->linktype)) {
			if (ferret->interface_last_activity + (time_t)ferret->interface_interval_inactive < time(0)
				|| ferret->interface_last_activity + (time_t)ferret->interface_interval_active < time(0)) {
				ferret->interface_channel++;
				if (ferret->interface_channel < 1 || ferret->interface_channel > 13)
					ferret->interface_channel = 1;
				
				wifi_set_channel(ferret, hPcap, ferret->interface_channel);

				ferret->interface_last_activity = time(0);
			}
		}
    }

    /* Close the file and go onto the next one */
    pcap.close(hPcap);
}

uint64_t total_bytes_read = 0;

void speed_timer(void *)
{
	uint64_t last_bytes_read = 0;

	for (;;) {
		uint64_t bits_per_second;

		pixie_sleep(1000);

		if (total_bytes_read == last_bytes_read)
			continue;

		bits_per_second = (total_bytes_read - last_bytes_read)*8;
		last_bytes_read = total_bytes_read;

		fprintf(stderr, "rate = %u-mbps\n", (unsigned)(bits_per_second/1000000));

	}
}

/**
 * Process a file containing packet capture data.
 */
int process_file(struct Ferret *ferret, const char *capfilename)
{
	struct PcapFile *capfile;
	unsigned char buf[65536];
	unsigned linktype;
	unsigned frame_number = 0;

	/*
	 * Open the capture file
	 */
	capfile = pcapfile_openread(capfilename);
	if (capfile == NULL)
		return 0;
	linktype = pcapfile_datalink(capfile);
	ferret->linktype = linktype;

	fprintf(stderr, "%s\n", capfilename);
	
	/*
	 * Read in all the packets
	 */
	for (;;) {
		struct NetFrame frame[1];
		unsigned x;

		memset(frame,0,sizeof(*frame));

		/* Get next frame */
		x = pcapfile_readframe(capfile,
			&frame->time_secs,
			&frame->time_usecs,
			&frame->original_length,
			&frame->captured_length,
			buf,
			sizeof(buf)
			);
		if (x == 0)
			break;

		total_bytes_read += frame->captured_length;

		/* Clear the flag. This will be set if the processing finds something
		 * interesting. At that point, we might want to save a copy of the 
		 * frame in a 'sift' file. */
		frame->filename = capfilename;
		frame->layer2_protocol = linktype;
		frame->frame_number = ++frame_number;

		//printf("%u %u\n", frame->layer2_protocol, linktype);

		/*
		 * Analyze the packet
		 */
		try {
			process_frame(ferret, frame, buf, frame->captured_length);
		} catch (...) {
			struct PcapFile *pf;
			char filename[256];
			time_t now;
			struct tm *ptm;

			{
				/* A packet caused us to crash. Therefore, create an output file
				 * and copy the packet to it so that we can investigate the problem */
				now = time(0);
				ptm = localtime(&now);

				sprintf_s(filename, sizeof(filename), "crash-%04d-%02d-%02d.pcap",
					ptm->tm_year+1900,
					ptm->tm_mon+1,
					ptm->tm_mday
					);

				pf = pcapfile_openappend(filename, linktype);
				if (pf) {
					pcapfile_writeframe(pf, buf, frame->captured_length, frame->original_length,
						frame->time_secs, frame->time_usecs);
					pcapfile_close(pf);
				}
				throw;
			}

		}

		if (frame->flags.found.repeated)
			ferret->statistics.repeated++;
		sniff_packets(ferret, buf, frame);

	}


	pcapfile_close(capfile);

	return 0;
}


/**
 * Provide help, either an overview, or more help on a specific option.
 */
void main_help()
{
	fprintf(stderr,"options:\n");
	fprintf(stderr," -i <adapter>    Sniffs the wire(less) attached to that network adapter. \n");
	fprintf(stderr,"                 Must have libpcap or winpcap installed to work.\n");
	fprintf(stderr," -r <files>      Read files in off-line mode. Can use wildcards, such as \n");
	fprintf(stderr,"                 using \"ferret -r *.pcap\". Doesn't need libpcap to work.\n");
	fprintf(stderr," -c <file>       Reads in more advanced parameters from a file.\n");
}



/**
 * Set some defaults for monitoring WiFi
 */
void main_set_wifi_defaults(struct Ferret *ferret, const char *channel)
{
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *desired_interface=0;
	unsigned desired_level=0;
    
	if (!pcap.is_available) {
		printf("FAILURE: can't link to pcap library\n");
		exit(1);
	}
	if (pcap.findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
		exit(1);
	}
	if (alldevs == NULL) {
		fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
		exit(1);
	}

	/*
	 * Go through the list of adapters and find one that looks like
	 * it can be used for monitoring. We find the MOST ATTRACTIVE
	 * interface. An adapter named "\\.\airpcap00" is more attractive
	 * than one with the description "Broadcom 802.11n Network Adapter".
	 * An adapter with the name "ath0" is more attractive than one
	 * with the name "wifi0".
	 */	
	for(d=alldevs; d; d=d->next) {
		if (strstr(d->name, "airpcap") && desired_level < 100) {
			desired_level = 100;
			desired_interface = d->name;
		}
		if (strstr(d->description, "802.11") && desired_level < 50) {
			desired_level = 50;
			desired_interface = d->name;
		}
		if (memcmp(d->name, "wifi", 4)==0 && desired_level < 25) {
			desired_level = 25;
			desired_interface = d->name;
		}
		if (memcmp(d->name, "ath",3)==0 && desired_level < 50) {
			desired_level = 50;
			desired_interface = d->name;
		}
	}
	if (desired_interface && desired_level > 0) {
		ferret_set_parameter(ferret, "interface.name", desired_interface, 0);
	} else {
		printf("ERR: WiFi interface not found, configure manually with '-i'\n");
	}

	/*
	 * Look for a channel based upon SSID
	 */
	if (channel) {
		if ((strlen(channel) == 1 && isdigit(channel[0]))
			|| (strlen(channel) == 2 && isdigit(channel[0]) && isdigit(channel[1])))
			ferret_set_parameter(ferret, "interface.channel", channel, 0);
		else
			ferret_set_parameter(ferret, "interface.search", channel, 0);
	}

}


/**
 * Set which 'operation' we are going to perform on the packets
 * Some examples are:
 *	cookies
 *		Grab cookies and send to Hamster.
 *  protos
 *		List the protocols within the packets.
 *	fanin
 *		Sort hosts according to top incoming connections.
 *  fanout
 *		Sort hosts according to top outgoing connections.
 */
static void 
main_args_operation(const char *op, struct Ferret *ferret)
{
	if (memcmp("regress", op, 7) == 0)
        ferret_set_parameter(ferret, "regress", "true", 0);
	else if (memcmp("fanin", op, 5) == 0)
		ferret_set_parameter(ferret, "report.fanin", "100", 0);
	else if (memcmp("fanout", op, 5) == 0)
		ferret_set_parameter(ferret, "report.fanout", "100", 0);
	else if (memcmp("host", op, 4) == 0)
		ferret_set_parameter(ferret, "report.host", "100", 0);
	else if (memcmp("stats1", op, 6) == 0)
		ferret_set_parameter(ferret, "statistics", "true", 0);
	else if (memcmp("stats", op, 6) == 0)
		ferret_set_parameter(ferret, "statistics", "true", 0);
	else if (memcmp("protos", op, 5) == 0)
		ferret_set_parameter(ferret, "report", "stat", 0);
	else if (memcmp("suites", op, 5) == 0)
		ferret_set_parameter(ferret, "report", "suites", 0);
	else if (memcmp("nmap", op, 4) == 0)
		ferret_set_parameter(ferret, "report", "nmap", 0);
	else {
		fprintf(stderr, "unknown operation: %s\n", op);
		exit(1);
	}
}

/**
 * Parse the command-line arguments
 */
static void 
main_args(int argc, char **argv, struct Ferret *ferret)
{
	int i;
	int first_arg = 1;

	/*
	 * See if there is an <op> command
	 */
	if (argc > 1 && argv[1][0] != '-'
		&& memcmp(argv[1], "filter", 6) != 0) {
		first_arg = 1;
		main_args_operation(argv[1], ferret);
	}


	for (i=first_arg; i<argc; i++) {
		const char *arg = argv[i];

		/* See if a <name=value> style configuration parameter was 
		 * given on the command-line */
		if (arg[0] != '-' && strchr(argv[i],'=')) {
			char name[256];
			size_t name_length;
			const char *value;
			unsigned j;

			/* Extract the name */
			name_length = strchr(argv[i], '=') - argv[i];
			if (name_length > sizeof(name)-1)
				name_length = sizeof(name)-1;
			memcpy(name, argv[i], name_length);
			while (name_length && isspace(name[name_length-1]))
				name_length--;
			while (name_length && isspace(name[0]))
				memmove(name, name+1, --name_length);
			name[name_length] = '\0';
			for (j=0; j<name_length; j++)
				name[j] = (char)tolower(name[j]);
			
			/* Extract the value */
			value = strchr(argv[i],'=') + 1;
			while (*value && isspace(*value))
				value++;

			/* Set the configuration parameter */
			ferret_set_parameter(ferret, name, value,1);

			continue; /*loop to next command-line parameter*/
		}

		if (arg[0] != '-')
			continue;

		/*
		 * Look for gnu-style parameters, such as "--channel"
		 */
		if (arg[1] == '-') {
			arg += 2;

			/* some defaults for "wifi" monitoring. This selects the
			 * first monitor-mode wifi adapter it can find */
			if (stricmp(arg, "wifi") == 0) {
				if (i+1 < argc && argv[i+1][0] != '-') {
					main_set_wifi_defaults(ferret, argv[i+1]);
					i++;
				} else {
					main_set_wifi_defaults(ferret, NULL);
				}
			} else if (stricmp(arg, "channel") == 0) {
				if (i+1 < argc && isdigit(argv[i+1][0])) {
					ferret_set_parameter(ferret, "interface.channel", argv[i+1], 0);
					i++;
				} else {
					printf("%s: unknown option\n", argv[i]);
				}
			} else {
				printf("%s: unknown option\n", argv[i]);
			}
			continue;
		}

		switch (arg[1]) {
		case 'c':
			if (arg[2] == '\0')
				ferret_set_parameter(ferret, "include", argv[++i], 0);
			else
				ferret_set_parameter(ferret, "include", argv[i]+2, 0);
			break;
		case 'd':
			debug++;
			break;
		case 'h':
		case 'H':
		case '?':
		case '-':
			main_help();
			exit(0);
			break;

		case 'q':
			ferret_set_parameter(ferret, "config.quiet", "true", 0);
			break;

		case 'F':
			ferret_set_parameter(ferret, "interface.checkfcs", "true", 0);
			break;
		case 'S':
			ferret_set_parameter(ferret, "statistics.print", "true", 0);
			break;

		case 'r':
			if (ferret->is_live) {
				fprintf(stderr,"ERROR: cannot process live and offline data at the same time\n");
				ferret->is_error = 1;
			}
			ferret->is_offline = 1;
			if (argv[i][2] == '\0') {
				while (i+1<argc) {
					const char *filename = argv[i+1];
					if (filename[0] == '-' || strchr(filename, '='))
						break;
					else
						i++;
				}
			}
			break;
		case 'i':
			if (ferret->is_offline) {
				fprintf(stderr,"Cannot process live and offline data at the same time\n");
				ferret->is_error = 1;
			} else {
				if (arg[2] == '\0' && i+1<argc) {
					ferret_set_parameter(ferret, "interface.name", argv[i+1], 0);
					i++;
				} else if (isdigit(arg[2])) {
					ferret_set_parameter(ferret, "interface.name", arg+2, 0);
				} else {
					fprintf(stderr, "%s: invalid argument, expected something like \"-i1\" or \"-i eth0\"\n", argv[i]);
					ferret->is_error = 1;
				}
			}
			break;
		case 'W':
			ferret->is_live = 1;
			break;
		case 'w':
			if (arg[2] == '\0')
				ferret_set_parameter(ferret, "sniffer.filename", argv[++i], 0);
			else
				ferret_set_parameter(ferret, "sniffer.filename", argv[i]+2, 0);
			
			if (ferret->output.sniff == 0)
			ferret_set_parameter(ferret, "sniffer.mode", "most", 0);
			break;
		}
	}
}


extern "C" void t_leak_check(void);

extern "C" int smells_selftest_bittorrent_dht(void);

/****************************************************************************
 ****************************************************************************/
#ifdef __GNUC__
#include <execinfo.h>

void handle_segfault(int sig) {
  void *array[10];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, 10);

  // print out all the frames to stderr
  fprintf(stderr, "Error: signal %d:\n", sig);
  backtrace_symbols_fd(array, size, 2);
  exit(1);
}
#endif

/**
 * This is the main entry point to the program
 */
#ifndef FERRET_MAIN
#define FERRET_MAIN main
#endif
/*
int main(int argc, char **argv)
*/
int FERRET_MAIN(int argc, char **argv)
{
	int i;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct Ferret *ferret;

#if 0
    const char *myargv[] = {"ferret", "protos", "-r", "profile.pcap", 0};
    argc = 4;
    argv = (char**)myargv;
#endif

	/* Print backtraces when we crash */
#ifdef __GNUC__
	  //signal(SIGSEGV, handle_segfault);
#endif

	fprintf(stderr, "-- FERRET 3.0.1 - 2007-2012 (c) Errata Security\n");
	fprintf(stderr, "-- build = %s %s (%u-bits)\n", __DATE__, __TIME__, (unsigned)sizeof(size_t)*8);
    

	/*
	 * Register a signal handler for the <ctrl-c> key. This allows
	 * files to be closed gracefully when exiting. Otherwise, the
	 * last bit of data gets corrupted when the user hits <ctrl-c>
	 */
	//signal(SIGINT, control_c_handler);

	/*
	 * Runtime-load the libpcap shared-object or the winpcap DLL. We
	 * load at runtime rather than loadtime to allow this program to 
	 * be used to process offline content, and to provide more helpful
	 * messages to people who don't realize they need to install PCAP.
	 */
	pcaplive_init(&pcap);
	if (!pcap.is_available) {
		fprintf(stderr,"WinPcap is not available. Please install it from: http://www.winpcap.org/\n");
		fprintf(stderr,"Without WinPcap, you can process capture packet capture files (offline mode), \n");
		fprintf(stderr,"but you will not be able to monitor the network (live mode).\n");
	} else {
		//fprintf(stderr,"-- %s\n", pcap.lib_version());
	}


	/*
	 * Create a Ferret instance. These are essentially the "globals"
	 * of the system. 
	 */
	ferret = ferret_create();

	
	/*
	 * Parse the command-line arguments. This many also parse the configuration
	 * file that contains more difficult options.
	 */
	main_args(argc, argv, ferret);

    if (ferret->is_regress) {
        int x = 0;

        x += smells_selftest_bittorrent_dht();

        if (x) {
            printf("regression test: failed\n");
            return 1;
        } else {
            printf("regression test: succeeded\n");
            return 0;
        }

    }

	/*
	 * Echo parameters
	 */
	if (ferret->cfg.echo) {
		FILE *fp;
		char *value = ferret->cfg.echo;

		if (strcmp(value, "stdout")== 0)
			fp = stdout;
		else if (strcmp(value, "stderr")==0)
			fp = stderr;
		else
			fp = fopen(value, "wt");

		config_echo(ferret, fp);

		if (fp != stderr && fp != stdout)
			fclose(fp);
	}

	/* 
	 * Retrieve the device list (if libpcap is available)
	 */
	if (pcap.is_available && ferret->is_live) {
		if (pcap.findalldevs(&alldevs, errbuf) != -1)
		{
			pcap_if_t *d;
			i=0;

			if (alldevs == NULL) {
				fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
			}
			/* Print the list */
			for(d=alldevs; d; d=d->next)
			{
				fprintf(stderr, " %d  %s \t", ++i, d->name);
				if (d->description)
					fprintf(stderr, "(%s)\n", d->description);
				else
					fprintf(stderr, "(No description available)\n");
			}
			fprintf(stderr,"\n");
		} else {
			fprintf(stderr, "%s\n", errbuf);
		}
	}

	if (ferret->cfg.is_speed_timer)
		pixie_begin_thread(speed_timer, 0, 0);

	/* 
	 * If the user doesn't specify any options, then print a helpful
	 * message.
	 */
	if (argc <= 1) {
		fprintf(stderr,"Usage:\n");
		fprintf(stderr," ferret -i <num>                 (where <num> is an interface to monitor)\n");
		fprintf(stderr," ferret -r <file1> <file2> ...   (where <files> contain captured packets)\n");
		fprintf(stderr," ferret -h						 (for more help)\n");
		return 0;
	}

	/*
	 * Run through all the "jobs", which includes either lists of 
	 * packet-capture files to do offline processing on, or interfacs
	 * to do live capture on.
	 */
	if (ferret->is_live) {

		/* Default to always save packets */
		if (ferret->snarfer.mode == FERRET_SNIFF_UNKNOWN) {
			ferret_set_parameter(ferret, "sniffer.mode", "most", 0);
			ferret_set_parameter(ferret, "sniffer.directory", ".", 0);
		}
			


		if (ferret->interface_name[0] == '\0') {
			/* no interface provided, so choose the best one */
			char *devicename;
			char errbuf[1024];
			devicename = pcap.lookupdev(errbuf);
			if (devicename == NULL)
				fprintf(stderr, "ERROR:PCAP:%s\n", errbuf);
			else 
				sprintf_s(ferret->interface_name, sizeof(ferret->interface_name), "%s", devicename);
		} else if (isdigit(ferret->interface_name[0])) {
				pcap_if_t *d;
				int i=0;
				int inum;
				char errbuf[1024];

				if (alldevs == NULL)
					pcap.findalldevs(&alldevs, errbuf);
				
				inum = strtoul(ferret->interface_name,0,0);

				for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

				sprintf_s(ferret->interface_name, sizeof(ferret->interface_name), "%s", d->name);
		}
		process_live(ferret, ferret->interface_name);
			
	} else if (ferret->is_offline) {
	}

	for (i=1; i<argc; i++) {
		if (argv[i][0] != '-')
			continue;
		if (argv[i][1] != 'r')
			continue;
		/* Process one or more filenames after the '-r' option */
		if (argv[i][2] != '\0')
			process_file(ferret, argv[i]+2);
		while (i+1 < argc && argv[i+1][0] != '-') {
			process_file(ferret, argv[i+1]);
			i++;
		}
	}


	if (ferret->output.pf) {
		pcapfile_close(ferret->output.pf);
		ferret->output.pf = NULL;
	}


	if (ferret->cfg.statistics_print)
		report_stats1(ferret);
	if (ferret->cfg.report_stats2)
		report_stats2(ferret);
	if (ferret->cfg.report_hosts)
		report_hosts_topn(ferret, ferret->cfg.report_hosts);
	if (ferret->cfg.report_nmap)
		report_nmap(ferret, ferret->cfg.report_nmap);
	if (ferret->cfg.report_nmap)
		report_nmap(ferret, ferret->cfg.report_hosts);
	if (ferret->cfg.report_fanout)
		report_fanout_topn(ferret, ferret->cfg.report_fanout);
	if (ferret->cfg.report_fanin)
		report_fanin_topn(ferret, ferret->cfg.report_fanin);
	if (ferret->cfg.report_ciphersuites)
		report_ciphersuites(ferret, ferret->cfg.report_ciphersuites);


	/*
	 * Create an artificial timeout frame
	 */
	{
		struct NetFrame frame[1];
		memset(frame,0,sizeof(*frame));

		frame->filename = "timeout";
		frame->layer2_protocol = ferret->linktype;
		frame->frame_number++;
		
		frame->time_secs = (unsigned)(ferret->now + 60*60);
		frame->time_usecs = 0;
		frame->original_length = 0;
		frame->captured_length = 0;
		frame->layer2_protocol = ferret->linktype;	

		process_frame(ferret, frame, (const unsigned char*)"", frame->captured_length);
		if (ferret->eng[0]->session_count)
			fprintf(stderr, "ERROR: %d TCP sessions remaining\n", ferret->eng[0]->session_count);



	}

	ferret_destroy(ferret);

	{
	hamster_set_cookie(0xa3a3a3a4, 0,0, 0,0, 0,0, 0,0);
	hamster_set_cookie(0xa3a3a3a3, 0,0, 0,0, 0,0, 0,0);
	}	
	t_leak_check();
	fprintf(stderr, "-- graceful exit --\n");
	return 0;
}
