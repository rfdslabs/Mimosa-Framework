#ifndef STACK_LISTENER_H
#define STACK_LISTENER_H
struct Ferret;

enum LISTENER_TYPE {
	LISTENER_UNKNOWN,
	LISTENER_UDP_SIP,
	LISTENER_TCP_SIP,
	LISTENER_UDP_RTPAVP,
	LISTENER_UDP_RTCP,
	LISTENER_TCP_FTPDATA,
};

/**
 * Register that we know about a protocol running on certain port number on
 * a machine so that when we see a connection to that port in the future,
 * we know what protocol that connection will be.
 *
 * The traditional example of this is FTP whose command channel runs on
 * port 21, but whose files are transferes on connections to other ports.
 * We must therefore parse FTP on port 21 to find the ip:port numbers
 * for the file transfers.
 *
 * A more recent example is VoIP, where SIP packets occur on one port to
 * to set up a call, and where the call using RTP runs across arbitrary
 * other ports. We must therefore parse SIP packets in order to find
 * the ports that RTP runs over.
 */
void listener_register_udp(
	struct Ferret *ferret, 
	enum LISTENER_TYPE application_protocol,
	unsigned ip,
	unsigned port,
	unsigned time_secs
	);
void listener_register_tcp(
	struct Ferret *ferret, 
	enum LISTENER_TYPE application_protocol,
	unsigned ip,
	unsigned port,
	unsigned time_secs
	);

/**
 * Called while processing UDP packets to lookup a dynamic port
 */
unsigned
listener_lookup_udp(
	struct Ferret *ferret, 
	unsigned ip,
	unsigned port
	);
unsigned
listener_lookup_tcp(
	struct Ferret *ferret, 
	unsigned ip,
	unsigned port
	);

#endif
