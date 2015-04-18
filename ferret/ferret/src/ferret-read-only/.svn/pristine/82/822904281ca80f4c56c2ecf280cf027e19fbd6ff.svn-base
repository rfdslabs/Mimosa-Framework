#ifndef FILTERS_H
#define FILTERS_H
#ifdef __cplusplus
extern "C" {
#endif
struct Ferret;
struct SniffFilter;
struct FilterItem;

void filter_set_parameter(struct Ferret *ferret, const char *name, const char *value);

void filter_eval(const struct SniffFilter *flt, const struct NetFrame *frame, unsigned *include, unsigned *exclude);

void flt_add_item(struct SniffFilter *flt, struct FilterItem *item);

void flt_proto_eval(const struct SniffFilter *flt, const struct FilterItem *item, const struct NetFrame *frame, unsigned *include, unsigned *exclude);
void flt_proto_set_parameter(struct SniffFilter *flt, const char *name, const char *value);

void flt_addr_eval(const struct SniffFilter *flt, const struct FilterItem *item, const struct NetFrame *frame, unsigned *include, unsigned *exclude);
void flt_addr_set_parameter(struct SniffFilter *flt, const char *name, const char *value);



enum FilterType {
	FLT_TYPE_PROTO,
	FLT_TYPE_ADDR,
	FLT_TYPE_COUNT
};

struct FilterItem {
	enum FilterType type;
	unsigned exclude:1;
	unsigned include:1;
	union {
		struct {
			unsigned layer;
			unsigned proto;
		} proto;
		struct {
			unsigned char ver;
			unsigned ipv4;
			unsigned short port_first;
			unsigned short port_last;
			unsigned char ipv6[16];
		} addr;
	} u;
};

#ifdef __cplusplus
}
#endif
#endif
