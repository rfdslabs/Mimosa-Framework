#include "ferret.h"
#include "report.h"
#include "stack-netframe.h"
#include "parse-address.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define TABLE_SIZE 0x4000


struct ReportCipherSuites
{
	unsigned short counts[0x10000];
};



struct ReportCipherSuites *
ciphersuites_create()
{
	struct ReportCipherSuites *hosts;

	hosts = (struct ReportCipherSuites *)malloc(sizeof(*hosts));
	memset(hosts, 0, sizeof(*hosts));
	
	return hosts;
}






void record_ciphersuite(struct Ferret *ferret, unsigned ciphersuite)
{
    if (!ferret->cfg.report_ciphersuites)
        return;
  	if (ferret->report_ciphersuites == NULL)
		ferret->report_ciphersuites = ciphersuites_create();

    ferret->report_ciphersuites->counts[ciphersuite]++;
}


struct tmprecord {
	uint64_t byte_count;
	unsigned short record;
};

static void
sort_records(struct tmprecord *list, unsigned count)
{
	unsigned i;

	for (i=0; i<count; i++) {
		unsigned j;
		unsigned max = count - i - 1;
		for (j=0; j<max; j++) {
			if (list[j].byte_count < list[j+1].byte_count) {
				struct tmprecord swap;

				swap.byte_count = list[j].byte_count;
				swap.record = list[j].record;

				list[j].byte_count = list[j+1].byte_count;
				list[j].record = list[j+1].record;

				list[j+1].byte_count = swap.byte_count;
				list[j+1].record = swap.record;
			}
		}
	}

}

static const char *
description(unsigned ciphersuite)
{
    switch (ciphersuite) {
    case 0x0004:    return "TLS_RSA_WITH_RC4_128_MD5";
    case 0x0005:    return "TLS_RSA_WITH_RC4_128_SHA";
    case 0x0006:    return "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
    case 0x0007:    return "TLS_RSA_WITH_IDEA_CBC_SHA";
    case 0x0008:    return "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA";
    case 0x0009:    return "TLS_RSA_WITH_DES_CBC_SHA";
    case 0x000A:    return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0x000B:    return "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
    case 0x000C:    return "TLS_DH_DSS_WITH_DES_CBC_SHA";
    case 0x000D:    return "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
    case 0x000E:    return "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
    case 0x000F:    return "TLS_DH_RSA_WITH_DES_CBC_SHA";
    case 0x0010:    return "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0x0011:    return "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
    case 0x0012:    return "TLS_DHE_DSS_WITH_DES_CBC_SHA";
    case 0x0013:    return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
    case 0x0014:    return "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
    case 0x0015:    return "TLS_DHE_RSA_WITH_DES_CBC_SHA";
    case 0x0016:    return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0x0017:    return "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5";
    case 0x0018:    return "TLS_DH_anon_WITH_RC4_128_MD5";
    case 0x0019:    return "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
    case 0x001A:    return "TLS_DH_anon_WITH_DES_CBC_SHA";
    case 0x001B:    return "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
    
    case 0x002E:    return "TLS_RSA_PSK_WITH_NULL_SHA";
    case 0x002F:    return "TLS_RSA_WITH_AES_128_CBC_SHA";
    case 0x0030:    return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
    case 0x0031:    return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
    case 0x0032:    return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
    case 0x0033:    return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
    case 0x0034:    return "TLS_DH_anon_WITH_AES_128_CBC_SHA";
    case 0x0035:    return "TLS_RSA_WITH_AES_256_CBC_SHA";
    case 0x0036:    return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
    case 0x0037:    return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
    case 0x0038:    return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
    case 0x0039:    return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
    case 0x003A:    return "TLS_DH_anon_WITH_AES_256_CBC_SHA";
    case 0x003B:    return "TLS_RSA_WITH_NULL_SHA256";
    case 0x003C:    return "TLS_RSA_WITH_AES_128_CBC_SHA256";
    case 0x003D:    return "TLS_RSA_WITH_AES_256_CBC_SHA256";
    case 0x003E:    return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
    case 0x003F:    return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
    case 0x0040:    return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
    
    case 0x0067:    return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
    case 0x0068:    return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
    case 0x0069:    return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
    case 0x006A:    return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
    case 0x006B:    return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
    case 0x006C:    return "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
    case 0x006D:    return "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
    case 0x0084:    return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
    case 0x0085:    return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
    case 0x0086:    return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
    case 0x0087:    return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
    case 0x0088:    return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";

    case 0xC002:    return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
    case 0xC003:    return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
    case 0xC004:    return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
    case 0xC005:    return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
    case 0xC006:    return "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
    case 0xC007:    return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
    case 0xC008:    return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
    case 0xC009:    return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
    case 0xC00A:    return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
    case 0xC00B:    return "TLS_ECDH_RSA_WITH_NULL_SHA";
    case 0xC00C:    return "TLS_ECDH_RSA_WITH_RC4_128_SHA";
    case 0xC00D:    return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0xC00E:    return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
    case 0xC00F:    return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
    case 0xC010:    return "TLS_ECDHE_RSA_WITH_NULL_SHA";
    case 0xC011:    return "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
    case 0xC012:    return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
    case 0xC013:    return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
    case 0xC014:    return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";

    case 0xC023:    return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
    case 0xC024:    return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
    case 0xC025:    return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
    case 0xC026:    return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
    case 0xC027:    return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
    case 0xC028:    return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
    case 0xC029:    return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
    case 0xC02A:    return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
    case 0xC02B:    return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xC02C:    return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xC02D:    return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
    case 0xC02E:    return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
    case 0xC02F:    return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
    case 0xC030:    return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
    case 0xC031:    return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
    case 0xC032:    return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";

    default: return "";
    }
}
void
report_ciphersuites(struct Ferret *ferret, unsigned report_count)
{
	struct tmprecord *list;
	unsigned i;
	unsigned n;

    if (ferret->report_ciphersuites == NULL)
        return;

	list = (struct tmprecord *)malloc(0x10000 * sizeof(*list));

	/*
	 * Walk through the hash table grabbing all the records
	 */
	n = 0;
	for (i=0; i<0x10000; i++) {
        unsigned count = ferret->report_ciphersuites->counts[i];
        if (count) {
            list[n].byte_count = count;
            list[n].record = i;
            n++;
        }
	}
    

	sort_records(list, n);

	/*
	 * Print the results
	 */
    printf("  count     suite  - description\n");
	for (i=0; i<report_count && i<n; i++) {
		unsigned ciphersuite = list[i].record;
		

		
		printf("%11llu 0x%04x - %s", list[i].byte_count, ciphersuite, description(ciphersuite));
		printf("\n");
	}

	printf("\n");
}
