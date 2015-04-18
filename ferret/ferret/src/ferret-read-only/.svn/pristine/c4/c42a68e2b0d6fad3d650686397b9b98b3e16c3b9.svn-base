#ifndef DGRAM_SIP_H
#define DGRAM_SIP_H

struct Field
{
	const unsigned char *px;
	unsigned length;
};

void parse_sdp_invite_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);

uint64_t field_next_number(const struct Field *field, unsigned *inout_offset);
int field_is_number(const struct Field *field, unsigned offset);
int field_equals_nocase(const char *name, const struct Field *field);


#endif
