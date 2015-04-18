#include "ferret.h"
#include "stack-netframe.h"
#include "filters.h"

#include <ctype.h>
extern void filter_lookup_proto(const char *name, unsigned *layer, unsigned *proto);



void flt_proto_set_parameter(struct SniffFilter *flt, const char *name, const char *value)
{
	unsigned layer;
	unsigned proto;
	struct FilterItem item;
	unsigned exclude = 0;

	if (*value == '!') {
		exclude = 1;
		value++;
	}

	filter_lookup_proto(value, &layer, &proto);
	if (layer == 0) {
		fprintf(stderr, "unknown proto: %s=%s\n", name, value);
		return;
	}

	item.type = FLT_TYPE_PROTO;
	item.include = !exclude;
	item.exclude = exclude;
	item.u.proto.proto = proto;
	item.u.proto.layer = layer;

	flt_add_item(flt, &item);
	
}


void
flt_proto_eval(const struct SniffFilter *flt, const struct FilterItem *item, const struct NetFrame *frame, unsigned *include, unsigned *exclude)
{
	*exclude = 0;

	switch (item->u.proto.layer) {
	case 0:
		if (item->exclude)
			*exclude = 1;
		if (item->include)
			*include = 1;
		break;
	case 3:
		if (frame->layer3_protocol == item->u.proto.proto) {
			if (item->exclude)
				*exclude = 1;
			if (item->include)
				*include = 1;
		}
		break;
	
	case 4:
		if (frame->layer3_protocol != LAYER3_IP && frame->layer3_protocol != LAYER3_IPV6)
			return;
		if (frame->layer4_protocol == item->u.proto.proto) {
			if (item->exclude)
				*exclude = 1;
			if (item->include)
				*include = 1;
		}
		break;
	
	case 7:
		if (frame->layer4_protocol != LAYER4_TCP && frame->layer4_protocol != LAYER4_UDP)
			return;
		if (frame->layer7_protocol == item->u.proto.proto) {
			if (item->exclude)
				*exclude = 1;
			if (item->include)
				*include = 1;
		}
		break;
	}

	return;
}

