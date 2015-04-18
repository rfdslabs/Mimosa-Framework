/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	BITTORRENT DHT (UDP) PROTOCOL

  Some BitTorrent application, especially Azeureus, have a
  distributed tracker protocol that is carried over UDP packets.

  Right now, we are simply implementing a "smells-like" system
  of heuristically identifying the UDP packets as part of this
  protocol. The more we can identify what a UDP is not (i.e.
  not part of bittorrent), the more guesses we can make about
  what else it might be.
*/
#include "platform.h"
#include "ferret.h"
#include "stack-netframe.h"

enum {
	ACT_REQUEST_PING		= 1024,
	ACT_REPLY_PING			= 1025,
	ACT_REQUEST_STORE		= 1026,
	ACT_REPLY_STORE			= 1027,
	ACT_REQUEST_FIND_NODE	= 1028,
	ACT_REPLY_FIND_NODE		= 1029,
	ACT_REQUEST_FIND_VALUE	= 1030,
	ACT_REPLY_FIND_VALUE	= 1031,
	ACT_REPLY_ERROR			= 1032,
	ACT_REPLY_STATS			= 1033,
	ACT_REQUEST_STATS		= 1034,
	ACT_DATA				= 1035,
	ACT_REQUEST_KEY_BLOCK	= 1036,
	ACT_REPLY_KEY_BLOCK		= 1037,
	ACT_END
};

static unsigned
is_valid_action(unsigned action)
{
	if (action < ACT_REQUEST_PING || ACT_END <= action)
		return 0;
	else
		return 1;
}

/*
	public static final byte PROTOCOL_VERSION_2304					= 8;	
	public static final byte PROTOCOL_VERSION_2306					= 12;	
	public static final byte PROTOCOL_VERSION_2400					= 13;	
	public static final byte PROTOCOL_VERSION_2402					= 14;	
	public static final byte PROTOCOL_VERSION_2500					= 15;	
	
	public static final byte PROTOCOL_VERSION_MIN					= PROTOCOL_VERSION_2402;
	public static final byte PROTOCOL_VERSION_DIV_AND_CONT			= 6;
	public static final byte PROTOCOL_VERSION_ANTI_SPOOF			= 7;
	public static final byte PROTOCOL_VERSION_ENCRYPT_TT			= 8;	// refed from DDBase
	public static final byte PROTOCOL_VERSION_ANTI_SPOOF2			= 8;

		// we can't fix the originator position until a previous fix regarding the incorrect
		// use of a contact's version > sender's version is fixed. This will be done at 2.3.0.4
		// We can therefore only apply this fix after then
	
	public static final byte PROTOCOL_VERSION_FIX_ORIGINATOR		= 9;
	public static final byte PROTOCOL_VERSION_VIVALDI				= 10;
	public static final byte PROTOCOL_VERSION_REMOVE_DIST_ADD_VER	= 11;
	public static final byte PROTOCOL_VERSION_XFER_STATUS			= 12;
	public static final byte PROTOCOL_VERSION_SIZE_ESTIMATE			= 13;
	public static final byte PROTOCOL_VERSION_VENDOR_ID				= 14;
	public static final byte PROTOCOL_VERSION_BLOCK_KEYS			= 14;

	public static final byte PROTOCOL_VERSION_GENERIC_NETPOS		= 15;
	public static final byte PROTOCOL_VERSION_VIVALDI_FINDVALUE		= 16;

	
	public static final byte PROTOCOL_VERSION_RESTRICT_ID_PORTS		= 32;	// introduced now (2403/V15) to support possible future change to id allocation
																			// If/when introduced the min DHT version must be set to 15 at the same time

		// multiple networks reformats the requests and therefore needs the above fix to work
	
	public static final byte PROTOCOL_VERSION_NETWORKS				= PROTOCOL_VERSION_FIX_ORIGINATOR;
	
	public static final byte PROTOCOL_VERSION_MAIN					= PROTOCOL_VERSION_VIVALDI_FINDVALUE;	
	
	public static final byte PROTOCOL_VERSION_CVS					= PROTOCOL_VERSION_VIVALDI_FINDVALUE;

	public static final byte VENDOR_ID_AELITIS		= 0x00;
	public static final byte VENDOR_ID_ShareNET		= 0x01;			// http://www.sharep2p.net/
	public static final byte VENDOR_ID_NONE			= (byte)0xff;

	public static final byte VENDOR_ID_ME			= VENDOR_ID_AELITIS;

  */
static uint64_t 
get_long(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	uint64_t result = 0;
		
	if (length >= 8 + (*r_offset))
		length = 8 + (*r_offset);
	else {
		(*r_offset) = length+1;
		return 0xa3a3a3a3;
	}
	
	while (*r_offset < length) {
		result <<= 8;
		result |= px[*r_offset];
		(*r_offset)++;
	}
	return result;
}
static unsigned get_int(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result = 0;
	
	if (length >= 4 + (*r_offset))
		length = 4 + (*r_offset);
	else {
		(*r_offset) = length+1;
		return 0xa3a3a3a3;
	}
	
	while (*r_offset < length) {
		result <<= 8;
		result |= px[*r_offset];
		(*r_offset)++;
	}
	return result;
}
static unsigned get_short(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result = 0;
	
	if (length >= 2 + (*r_offset))
		length = 2 + (*r_offset);
	else {
		(*r_offset) = length+1;
		return 0xA3A3;
	}
	
	while (*r_offset < length) {
		result <<= 8;
		result |= px[*r_offset];
		(*r_offset)++;
	}
	return result;
}
static unsigned get_byte(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result = 0;
	
	if (length >= 1 + (*r_offset))
		length = 1 + (*r_offset);
	else {
		(*r_offset) = length+1;
		return 0xA3;
	}

	
	while (*r_offset < length) {
		result <<= 8;
		result |= px[*r_offset];
		(*r_offset)++;
	}

	return result;
}


unsigned smellslike_bittorrent_XYZ(const unsigned char *px, unsigned length)
{
	unsigned offset=0;

	if (length < 8)
		return 0;

	/* When sending requests, the first 8 bytes are the 64-bit connection-ID,
	 * followed by the 32-bit action-type. All connection-IDs are forced to
	 * have their high-order bit set to one, and all action-types are forced
	 * to have the high-order bit cleared to zero. Thus, we test a request
	 * vs. reply by looking at this bit.
	 */
	if (px[0] & 0x80) {
		unsigned len;
		//uint64_t connection_id;
		unsigned action_type;
		//unsigned transaction_id;
		unsigned protocol_version;
		unsigned vendor_id;
		//unsigned network;
		//unsigned originator_version;
		struct OriginatorAddress {
			unsigned ver;
			unsigned ipv4;
			unsigned ipv6[4];
			unsigned port;
		} originator_address;
		//unsigned originator_instance_id;
		//uint64_t originator_time;

		/* Connection ID is 64-bits of random data, with the high-order bit set */
		get_long(px, length, &offset);

		/* Action/type is one of ACT_REQUEST_PING etc. */
		action_type = get_int(px, length, &offset);

		/* Transaction ID is random data */
		get_int(px, length, &offset);

		/* Protocol-version is a single byte. I'm not sure what it means */
		protocol_version = get_byte(px, length, &offset);

		switch (protocol_version) {
		default:
		case 8: /* Azureus/2.3.0.4 */
		case 12: /* Azureus/2.3.0.6 */
		case 13: /* Azureus/2.4.0.0 */
		case 14: /* Azureus/2.4.0.2 */
			return 0; /* I don't know this protocols */
		case 15: /* Azureus/2.5.0.0 */
		case 16: /* Azuerus/2.5.0.4 */
			break;

		}

		/* Vendor ID, added in Azureus/2.4.0.2 */
		if (protocol_version >= 14) {
			vendor_id = get_byte(px, length, &offset);
			switch (vendor_id) {
			case 0x00: /* Aelitis, aka. Azureus */
				break;
			case 0x01: /* ShareNET, http://www.sharep2p.net/ */
				break;
			case 0xFF: /* None */
				break;
			default:
				break;
			}
		}

		/* Network number, added in Azureus/2.3.0.5 */
		if (protocol_version >= 9) {
			get_int(px, length, &offset);
		}

		/* Originator version, added in Azuereus/2.3.0.5 */
		if (protocol_version >= 9) {
			get_byte(px, length, &offset);
		}

		/* Get the IP address, which may be IPv6 */
		originator_address.ver = get_byte(px, length, &offset);
		if (originator_address.ver == 4) {
			originator_address.ipv4 = get_int(px, length, &offset);
		} else {
			originator_address.ipv6[0] = get_int(px, length, &offset);
			originator_address.ipv6[1] = get_int(px, length, &offset);
			originator_address.ipv6[2] = get_int(px, length, &offset);
			originator_address.ipv6[3] = get_int(px, length, &offset);
		}
		originator_address.port = get_short(px, length, &offset);

		/* Get the "instance-id" of the originator, which is a 32-bit random number */
		get_int(px, length, &offset);

		/* Get the originator's time, which is a 64-bit number measuring the 
		 * number of milliseconds from midnight, January 1, 1970 UTC.*/
		get_long(px, length, &offset);
		/* 0x000001116d6e3519 = March 19, 2007 */

		/*
		 * Do action-type specific stuff
		 */
		switch (action_type) {
		case ACT_REQUEST_PING:			/* 1024 */
			if (offset != length)
				return 0;
			/* no content past this */
			break;
		case ACT_REPLY_PING:			/* 1025 */
			return 0; /* reply, not request */
		case ACT_REQUEST_STORE:			/* 1026 */
			{
				unsigned count;

				offset += 4; /* random_id */

				/* Keys, which is an array of strings */
				count = get_byte(px, length, &offset);
				while (count && offset < length ) {
					len = get_byte(px, length, &offset);
					offset += len;
					count--;
				}
				
				/* and array of Transport values */
				count = get_byte(px, length, &offset);
				while (count && offset < length) {
					offset += 2; /*unsigned len2 = get_short(px, length, &offset);*/
					if (protocol_version >= 11)
						offset += 4; /* other version */
					else
						offset += 4; /* read distance */
					offset += 8; /* created */

					len = get_short(px, length, &offset);
					offset += len;

					if (get_byte(px, length, &offset) != 1)
						return 0;
					offset += 1; /*another version */

					/* IP address + port */
					if (get_byte(px, length, &offset) == 4)
						offset += 6;
					else
						offset += 18;

					/* flags */
					offset += 1;

					count--;
				}
			}
			break;
		case ACT_REPLY_STORE:			/* 1027 */
			return 0; /* reply, not request */
		case ACT_REQUEST_FIND_NODE:		/* 1028 */
			len = get_byte(px, length, &offset);
			offset += len; /* node */
			break;
		case ACT_REPLY_FIND_NODE:		/* 1029 */
			return 0; /* reply, not request */
		case ACT_REQUEST_FIND_VALUE:	/* 1030 */
			len = get_byte(px, length, &offset);
			offset += len; /* id */
			offset += 1; /* flags */
			offset += 1; /* maximum values */
			break;
		case ACT_REPLY_FIND_VALUE:		/* 1031 */
			return 0; /* reply, not request */
		case ACT_REPLY_ERROR:			/* 1032 */
			return 0; /* reply, not request */
		case ACT_REPLY_STATS:			/* 1033 */
			return 0; /* reply, not request */
		case ACT_REQUEST_STATS:			/* 1034 */
			offset += 4; /* stats type */
			break;
		case ACT_DATA:					/* 1035 */
			/*todo*/
			break;
		case ACT_REQUEST_KEY_BLOCK:		/* 1036 */
			offset += 4; /*random_id*/
			len = get_byte(px, length, &offset);
			offset += len;
			len = get_short(px, length, &offset);
			offset += len;
			break;
		case ACT_REPLY_KEY_BLOCK:		/* 1037 */
			return 0; /* reply, not request */
		}

		/* Older versions put originator version at end */
		if (protocol_version < 9)
			get_byte(px, length, &offset);

		if (offset == length)
			return 1;
		else
			return 0;
	} else {
		unsigned action_type;
		//unsigned transaction_id;
		//uint64_t connection_id;
		unsigned protocol_version;
		unsigned vendor_id;
		//unsigned target_instance_id;
		//unsigned network;

		/* The 32-bit action/type field is the first field in the reply packets */
		action_type = get_int(px, length, &offset);
		if (!is_valid_action(action_type))
			return 0;

		/* [Transaction ID] is random data */
		get_int(px, length, &offset);

		/* [Connection ID] is 64-bits of random data, with the high-order bit set */
		get_long(px, length, &offset);

		/* Protocol-version is a single byte. I'm not sure what it means */
		protocol_version = get_byte(px, length, &offset);

		switch (protocol_version) {
		default:
		case 8: /* Azureus/2.3.0.4 */
		case 12: /* Azureus/2.3.0.6 */
		case 13: /* Azureus/2.4.0.0 */
		case 14: /* Azureus/2.4.0.2 */
			return 0; /* I don't know this protocols */
		case 15: /* Azureus/2.5.0.0 */
		case 16: /* Azuerus/2.5.0.4 */
			break;

		}

		/* Vendor ID, added in Azureus/2.4.0.2 */
		if (protocol_version >= 14) {
			vendor_id = get_byte(px, length, &offset);
			switch (vendor_id) {
			case 0x00: /* Aelitis, aka. Azureus */
				break;
			case 0x01: /* ShareNET, http://www.sharep2p.net/ */
				break;
			case 0xFF: /* None */
				break;
			default:
				break;
			}
		}

		/* [Network number], added in Azureus/2.3.0.5 */
		if (protocol_version >= 9) {
			get_int(px, length, &offset);
		}

		/* [target-instance-id] of the originator, which is a 32-bit random number */
		 get_int(px, length, &offset);

		switch (action_type) {
		case ACT_REQUEST_PING:			/* 1024 */
			return 0; /* request, not reply */
		case ACT_REPLY_PING:			/* 1025 */
			if (protocol_version >= 15) {
				unsigned entries;
				entries = get_byte(px, length, &offset);
				while (entries) {
					//unsigned type;
					unsigned size;

                    /* [type] */
					get_byte(px, length, &offset);

                    /* [size] */
					size = get_byte(px, length, &offset);
					offset += size;
					entries--;
				}
			} else {
			}
			break;
		case ACT_REQUEST_STORE:			/* 1026 */
			return 0; /* request, not reply */
		case ACT_REPLY_STORE:			/* 1027 */
			return 0; /* reply, not request */
		case ACT_REQUEST_FIND_NODE:		/* 1028 */
			return 0; /* request, not reply */
		case ACT_REPLY_FIND_NODE:		/* 1029 */
			return 0; /* reply, not request */
		case ACT_REQUEST_FIND_VALUE:	/* 1030 */
			return 0; /* request, not reply */
		case ACT_REPLY_FIND_VALUE:		/* 1031 */
			return 0; /* reply, not request */
		case ACT_REPLY_ERROR:			/* 1032 */
			return 0; /* reply, not request */
		case ACT_REPLY_STATS:			/* 1033 */
			return 0; /* reply, not request */
		case ACT_REQUEST_STATS:			/* 1034 */
			return 0; /* request, not reply */
		case ACT_DATA:					/* 1035 */
			return 0; /* request, not reply */
		case ACT_REQUEST_KEY_BLOCK:		/* 1036 */
			return 0; /* request, not reply */
		case ACT_REPLY_KEY_BLOCK:		/* 1037 */
			return 0; /* reply, not request */
		}
		if (offset == length)
			return 1;
		else
			return 0;

	}
}

void process_bittorrent_XYZ(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = LAYER7_BITTORRENT_XYZ;
}
void process_bittorrent_DHT(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = LAYER7_BITTORRENT_DHT;
}
void process_bittorrent_uTP(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = LAYER7_BITTORRENT_uTP;
}
