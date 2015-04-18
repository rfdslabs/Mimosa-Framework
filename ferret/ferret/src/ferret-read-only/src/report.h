#ifndef REPORT_H
#define REPORT_H
#ifdef __cplusplus
extern "C" {
#endif

void report_stats1(struct Ferret *ferret);
void report_stats2(struct Ferret *ferret);

void record_host_transmit(struct Ferret *ferret, unsigned ipv4, unsigned frame_size);
void record_host_receive(struct Ferret *ferret, unsigned ipv4, unsigned frame_size);
void record_host2host(struct Ferret *ferret, unsigned ipsrc, unsigned ipdst, unsigned frame_size);
void record_listening_port(struct Ferret *ferret, unsigned hops, 
        unsigned ipver, unsigned ip, const unsigned char *ipv6, 
        unsigned transport, unsigned port, 
        const char *proto, 
        const unsigned char *banner, unsigned banner_length);
enum {LISTENING_ON_TCP, LISTENING_ON_UDP, LISTENING_ON_ETHERNET};

void report_hosts_topn(struct Ferret *ferret, unsigned report_count);
void report_nmap(struct Ferret *ferret, unsigned report_count);
void report_ciphersuites(struct Ferret *ferret, unsigned report_count);
void report_fanout_topn(struct Ferret *ferret, unsigned report_count);
void report_fanin_topn(struct Ferret *ferret, unsigned report_count);

void report_hosts_set_parameter(struct Ferret *ferret, const char *name, const char *value);
void report_nmap_set_parameter(struct Ferret *ferret, const char *name, const char *value);
void report_fanout_set_parameter(struct Ferret *ferret, const char *name, const char *value);

#ifdef __cplusplus
}
#endif
#endif
