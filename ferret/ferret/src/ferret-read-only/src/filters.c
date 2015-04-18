#include "ferret.h"
#include "stack-netframe.h"
#include "filters.h"

#include <ctype.h>
#include <string.h>


struct SniffFilter
{
	struct FilterItem *filters;
	unsigned count;
	unsigned count_includes[FLT_TYPE_COUNT];
	unsigned count_excludes[FLT_TYPE_COUNT];
};

void flt_add_item(struct SniffFilter *flt, struct FilterItem *item)
{
	if (flt->filters == NULL)
		flt->filters = (struct FilterItem *)malloc(sizeof(*item));
	else
		flt->filters = (struct FilterItem *)realloc(flt->filters, sizeof(*item) * (flt->count + 1));

	memcpy(&flt->filters[flt->count], item, sizeof(*item));
	flt->count++;

	flt->count_includes[item->type] += item->include;
	flt->count_excludes[item->type] += item->exclude;

}

void filter_eval(const struct SniffFilter *flt, const struct NetFrame *frame, unsigned *include, unsigned *exclude)
{
	unsigned i;


	*include = 0;
	*exclude = 0;

	/*
	 * If we've only specified 'excludes' for a filter type, then
	 * default to 'include' anything that isn't excluded.
	 */
	for (i=0; i<FLT_TYPE_COUNT; i++) {
		if (flt->count_includes[i]  == 0 && flt->count_excludes[i])
			*include = 1;
	}

	if (flt == NULL)
		return;

	for (i=0; i<flt->count; i++) {
		const struct FilterItem *item = &flt->filters[i];
		switch (item->type) {
		case FLT_TYPE_PROTO:
			flt_proto_eval(flt, item, frame, include, exclude);
			break;
		case FLT_TYPE_ADDR:
			flt_addr_eval(flt, item, frame, include, exclude);
			break;
		case FLT_TYPE_COUNT:
		default:
			;
		}
	}


}

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



struct SniffFilter *sniff_filter_create()
{
	struct SniffFilter *flt;

	flt = (struct SniffFilter *)malloc(sizeof(*flt));
	memset(flt, 0, sizeof(*flt));

	return flt;
}

void filter_set_parameter(struct Ferret *ferret, const char *name, const char *value)
{
	unsigned x = 0;

	ferret->output.sniff = FERRET_SNIFF_FILTER;

	if (ferret->sniff_filters == 0)
		ferret->sniff_filters = sniff_filter_create();

	/*
	 * remove "filter" from the front of the name
	 */
	if (memcmp(name, "filter", 6) == 0) {
		name += 6;
		while (ispunct(*name))
			name++;
	}
	
	/* This macro is defined to match the leading keyword */
	#define MATCH(str) (cfg_prefix(name, str, x) && ((x=cfg_prefix(name, str, x))>0))

	if (MATCH("proto")) {
		flt_proto_set_parameter(ferret->sniff_filters, name, value);
	} else if (MATCH("addr") || MATCH("host")) {
		flt_addr_set_parameter(ferret->sniff_filters, name, value);
	} else if (MATCH("port")) {
		flt_addr_set_parameter(ferret->sniff_filters, name, value);
	} else {
		fprintf(stderr, "cfg: unknown filter spec: %s=%s\n", name, value);
	}
}
