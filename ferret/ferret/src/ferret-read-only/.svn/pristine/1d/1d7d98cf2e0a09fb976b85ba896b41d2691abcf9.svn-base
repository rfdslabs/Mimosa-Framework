#ifndef STACK_SMELLS_H
#define STACK_SMELLS_H
struct NetFrame;

struct SmellsDCERPC
{
	unsigned state;
	unsigned len;
};

int
smellslike_msrpc_toserver(struct SmellsDCERPC *smell, const unsigned char *px, unsigned length);

struct SmellsSSL
{
	unsigned state;
	unsigned char type;
	unsigned char subtype;
	unsigned char version_major:4;
	unsigned char version_minor:4;
	unsigned short length;
	unsigned short inner_length;
};

int
smellslike_ssl_request(const struct NetFrame *frame, struct SmellsSSL *smell, const unsigned char *px, unsigned length);

#endif
