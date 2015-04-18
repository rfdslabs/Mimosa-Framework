#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util-hamster.h"
#include "platform.h"
static FILE *fp;


struct CookieTrunc {
    unsigned domain_length;
    char *domain;
    unsigned path_length;
    char *path;
    unsigned name_length;
    char *name;
};
struct CookieTrunc cookietrunc[] = {
    {7, "2o7.net", 1, "/", 14, "s_vi_deknefkhe"}, 
    {7, "2o7.net", 1, "/", 11, "s_vi_kjdeik"}, 
    {23, "adopt.specificclick.net", 1, "/", 4, "CTCI"}, 
    {23, "adopt.specificclick.net", 1, "/", 3, "DGI"}, 
    {23, "adopt.specificclick.net", 1, "/", 5, "DMEXP"}, 
    {23, "adopt.specificclick.net", 1, "/", 2, "HS"}, 
    {23, "adopt.specificclick.net", 1, "/", 2, "LO"}, 
    {23, "adopt.specificclick.net", 1, "/", 2, "UI"}, 
    {21, "ads.chinatimes.com.tw", 1, "/", 17, "ASP.NET_SessionId"}, 
    {21, "ads.chinatimes.com.tw", 1, "/", 8, "HttpOnly"}, 
    {19, "ads.cyberone.com.tw", 1, "/", 4, "GUID"}, 
    {21, "afe.specificclick.net", 1, "/", 3, "dmc"}, 
    {21, "afe.specificclick.net", 1, "/", 3, "dmk"}, 
    {21, "afe.specificclick.net", 1, "/", 3, "smc"}, 
    {21, "afe.specificclick.net", 1, "/", 3, "smk"}, 
    {9, "atdmt.com", 1, "/", 5, "AA002"}, 
    {17, "chinatimes.com.tw", 1, "/", 10, "SITESERVER"}, 
    {26, "computersecurityupdate.com", 1, "/", 7, "LastURL"}, 
    {26, "computersecurityupdate.com", 1, "/", 10, "RandomSeed"}, 
    {26, "computersecurityupdate.com", 1, "/", 15, "SessionCounters"}, 
    {26, "computersecurityupdate.com", 1, "/", 9, "SessionID"}, 
    {15, "doubleclick.net", 1, "/", 11, "test_cookie"}, 
    {25, "ehg-techtarget.hitbox.com", 1, "/", 14, "DM5212192CBAV6"}, 
    {25, "ehg-techtarget.hitbox.com", 1, "/", 14, "DM5212204PCAV6"}, 
    {13, "fastclick.net", 1, "/", 6, "adv_ic"}, 
    {13, "fastclick.net", 1, "/", 2, "m6"}, 
    {13, "fastclick.net", 1, "/", 3, "pjw"}, 
    {17, "feeds.cbsnews.com", 1, "/", 24, "NSC_gffe-iuuq-mc-wtfswfs"}, 
    {17, "feeds.cbsnews.com", 1, "/", 3, "ath"}, 
    {17, "feeds.cbsnews.com", 1, "/", 6, "xpires"}, 
    {20, "feeds.feedburner.com", 1, "/", 10, "JSESSIONID"}, 
    {20, "feeds.feedburner.com", 1, "/", 24, "NSC_gffe-iuuq-mc-wtfswfs"}, 
    {20, "feeds.feedburner.com", 1, "/", 3, "ath"}, 
    {20, "feeds.feedburner.com", 1, "/", 6, "xpires"}, 
    {6, "go.com", 1, "/", 4, "SWID"}, 
    {10, "google.com", 1, "/", 4, "PREF"}, 
    {10, "google.com", 1, "/", 1, "S"}, 
    {10, "google.com", 1, "/", 3, "SID"}, 
    {10, "google.com", 1, "/", 3, "ath"}, 
    {10, "google.com", 1, "/", 5, "omain"}, 
    {10, "google.com", 1, "/", 6, "xpires"}, 
    {10, "google.com", 5, "/mail", 11, "GMAIL_LOGIN"}, 
    {10, "google.com", 5, "/mail", 9, "GMAIL_RTT"}, 
    {10, "hitbox.com", 1, "/", 3, "CTG"}, 
    {10, "hitbox.com", 1, "/", 6, "WSS_GW"}, 
    {10, "hitbox.com", 1, "/", 7, "max-age"}, 
    {11, "hoovers.com", 1, "/", 3, "HID"}, 
    {11, "hoovers.com", 1, "/", 7, "mktgPop"}, 
    {22, "itsecurityexpert.co.uk", 1, "/", 32, "c5a215027949490ee342689c127acc24"}, 
    {33, "learninggerman.mschubertberlin.de", 1, "/", 6, "Apache"}, 
    {15, "mail.google.com", 1, "/", 10, "GMAIL_HELP"}, 
    {15, "mail.google.com", 1, "/", 3, "ath"}, 
    {15, "mail.google.com", 5, "/mail", 3, "GBE"}, 
    {15, "mail.google.com", 5, "/mail", 8, "GMAIL_AT"}, 
    {15, "mail.google.com", 5, "/mail", 10, "GMAIL_STAT"}, 
    {15, "mail.google.com", 5, "/mail", 8, "GMAIL_SU"}, 
    {15, "mail.google.com", 5, "/mail", 1, "S"},
/*
	{9, "yahoo.com", 1, "/", 1, "F"},
	{9, "yahoo.com", 1, "/", 1, "B"},
	{9, "yahoo.com", 1, "/", 2, "HP"},
	{9, "yahoo.com", 1, "/", 2, "PH"},
	{9, "yahoo.com", 1, "/", 2, "SO"},
	{9, "yahoo.com", 1, "/", 1, "T"},
	{9, "yahoo.com", 1, "/", 1, "U"},
	{9, "yahoo.com", 1, "/", 1, "Y"},
	{9, "yahoo.com", 1, "/", 3, "YLS"},
	
	{14, "news.yahoo.com", 1, "/", 10, "YNEWSFRONT"},
	{13, "www.yahoo.com", 1, "/", 3, "FPS"},
*/

    {17, "messenger.msn.com", 1, "/", 3, "WLM"}, 
    {18, "mysearch.intel.com", 1, "/", 17, "ASP.NET_SessionId"}, 
    {18, "mysearch.intel.com", 1, "/", 19, "IntelSearch.Culture"}, 
    {12, "news.com.com", 1, "/", 10, "JSESSIONID"}, 
    {7, "npr.org", 1, "/", 4, "v1st"}, 
    {12, "overture.com", 1, "/", 10, "CMUserData"}, 
    {12, "overture.com", 1, "/", 7, "Max-Age"}, 
    {18, "podcast.el-usa.com", 1, "/", 17, "ASP.NET_SessionId"}, 
    {18, "podcast.el-usa.com", 1, "/", 8, "HttpOnly"}, 
    {18, "podcast.el-usa.com", 1, "/", 2, "gd"}, 
    {21, "rotator.adjuggler.com", 1, "/", 31, "ajess1_80408593F7B1CB1C03AF13FE"}, 
    {21, "rotator.adjuggler.com", 1, "/", 3, "ath"}, 
    {21, "rotator.adjuggler.com", 1, "/", 6, "ax-Age"}, 
    {21, "rotator.adjuggler.com", 1, "/", 5, "optin"}, 
    {21, "rotator.adjuggler.com", 1, "/", 6, "xpires"}, 
    {11, "rss.cnn.com", 1, "/", 24, "NSC_gffe-iuuq-mc-wtfswfs"}, 
    {11, "rss.cnn.com", 1, "/", 3, "ath"}, 
    {11, "rss.cnn.com", 1, "/", 6, "xpires"}, 
    {16, "rss.sonibyte.com", 1, "/", 23, "BIGipServerBootsoft-www"}, 
    {16, "rss.sonibyte.com", 1, "/", 10, "JSESSIONID"}, 
    {30, "sandiegocbc.podshowcreator.com", 1, "/", 17, "ASP.NET_SessionId"}, 
    {17, "specificclick.net", 1, "/", 3, "smx"}, 
    {10, "tacoda.net", 1, "/", 5, "ANRTT"}, 
    {10, "tacoda.net", 1, "/", 4, "Anxd"}, 
    {10, "tacoda.net", 1, "/", 5, "TData"}, 
    {10, "tacoda.net", 1, "/", 3, "Tcc"}, 
    {10, "tacoda.net", 1, "/", 4, "Tsid"}, 
    {14, "techtarget.com", 1, "/", 8, "Accessv1"}, 
    {14, "techtarget.com", 1, "/", 6, "Datav1"}, 
    {14, "techtarget.com", 1, "/", 3, "IPC"}, 
    {14, "techtarget.com", 1, "/", 1, "U"}, 
    {7, "tros.nl", 1, "/", 12, "fe_typo_user"}, 
    {10, "vmware.com", 1, "/", 6, "ELOQUA"}, 
    {10, "vmware.com", 1, "/", 9, "ELQSTATUS"}, 
    {15, "www.answers.com", 1, "/", 10, "JSESSIONID"}, 
    {15, "www.answers.com", 1, "/", 4, "afid"}, 
    {15, "www.answers.com", 1, "/", 3, "ath"}, 
    {15, "www.answers.com", 1, "/", 21, "atomicaclientsettings"}, 
    {15, "www.answers.com", 1, "/", 22, "atomicaclientsettingsS"}, 
    {15, "www.answers.com", 1, "/", 5, "nafid"}, 
    {15, "www.answers.com", 1, "/", 13, "tacodaSession"}, 
    {15, "www.answers.com", 1, "/", 6, "xpires"}, 
    {27, "www.champcarworldseries.com", 1, "/", 20, "ASPSESSIONIDSSRCTSCA"}, 
    {27, "www.champcarworldseries.com", 1, "/", 15, "FTOAtlanticHole"}, 
    {27, "www.champcarworldseries.com", 1, "/", 10, "FTOFeature"}, 
    {27, "www.champcarworldseries.com", 1, "/", 9, "FTOLatest"}, 
    {27, "www.champcarworldseries.com", 1, "/", 8, "FTOPromo"}, 
    {27, "www.champcarworldseries.com", 1, "/", 6, "FTOTop"}, 
    {27, "www.champcarworldseries.com", 1, "/", 17, "RemotePoll140Test"}, 
    {27, "www.champcarworldseries.com", 6, "/Teams", 10, "LanguageID"}, 
    {11, "www.chds.us", 1, "/", 9, "PHPSESSID"}, 
    {14, "www.cnettv.com", 1, "/", 30, "NSC_d18-sc-dofuuw-bqq-wjefp-mc"}, 
    {14, "www.cnettv.com", 1, "/", 3, "ath"}, 
    {14, "www.cnettv.com", 1, "/", 6, "xpires"}, 
    {20, "www.linuxjournal.com", 1, "/", 9, "PHPSESSID"}, 
    {18, "www.linuxworld.com", 1, "/", 6, "Apache"}, 
    {14, "www.novell.com", 1, "/", 12, "ZNPCQ002-www"}, 
    {14, "www.novell.com", 5, "/home", 10, "JSESSIONID"}, 
    {19, "www.virtualiron.com", 1, "/", 4, "CFID"}, 
    {19, "www.virtualiron.com", 1, "/", 7, "CFTOKEN"}, 
    {19, "www.virtualiron.com", 1, "/", 3, "ath"}, 
    {14, "www.vmware.com", 1, "/", 21, "BIGipServerapache_bea"}, 
    {14, "www.vmware.com", 1, "/", 3, "uid"}, 
	{0,0, 0,0, 0,0}
};

/*static unsigned h_starts_with(const void *vpx, unsigned length, const char *prefix)
{
	const unsigned char *px = (const unsigned char*)vpx;
	unsigned i;

	if (strlen(prefix) > length)
		return 0;

	for (i=0; i<length && prefix[i]; i++) {
		if (prefix[i] != toupper(px[i]))
			return 0;
	}
	if (prefix[i] == '\0')
		return 1;
	return 0;
}*/

/*static unsigned h_ends_with(const void *vfilename, unsigned filename_length, const char *suffix)
{
	const char *filename = (const char *)vfilename;
	unsigned suffix_length = strlen(suffix);

	if (filename_length < suffix_length)
		return 0;

	return strnicmp(filename+filename_length-suffix_length, suffix, suffix_length) == 0;
}*/


void hamster_trunc_cookie(
					const char **r_domain, unsigned *r_domain_length,
					const void *path, unsigned *r_path_length,
					const void *name, unsigned name_length)
{
	unsigned i;
	const char *domain = *(const char **)r_domain;

	/*if (h_ends_with(*r_domain, *r_domain_length, "mail.yahoo.com") 
		|| h_starts_with(name, name_length, "YM.CGP_")
		|| h_starts_with(path, *r_path_length, "/dc")
		) {
		*r_domain = domain + *r_domain_length - 14;
		*r_path_length = 3;
		return;
	}*/

	for (i=0; cookietrunc[i].name_length; i++) {
		struct CookieTrunc *c = &cookietrunc[i];
		if (name_length != c->name_length || memcmp(name, c->name, c->name_length) != 0)
			continue;
		if (*r_path_length < c->path_length || memcmp(path, c->path, c->path_length) != 0)
			continue;
		if (*r_domain_length < c->domain_length || memcmp(domain+*r_domain_length-c->domain_length, c->domain, c->domain_length) != 0)
			continue;

		if (*r_domain_length == c->domain_length && *r_path_length == c->path_length)
			return; /*nothing to do*/

		*r_domain = domain+*r_domain_length-c->domain_length;
		*r_domain_length = c->domain_length;
		if (*r_path_length == c->path_length)
			return; /*nothing to do*/
		*r_path_length = c->path_length;
		return;
	}
}

void hamster_cookie(unsigned client_ip, 
					const void *vdomain, unsigned domain_length,
					const void *vpath, unsigned path_length,
					const void *vname, unsigned name_length,
					const void *vvalue, unsigned value_length)
{
	const char *domain = (const char*)vdomain;
	const char *name = (const char*)vname;
	const char *path = (const char*)vpath;
	const char *value = (const char*)vvalue;
	unsigned i;
	if (name_length == 7 && strnicmp(name, "expires", 7) == 0)
		return;

	if ((name_length == 6 && strnicmp(name, "xpires", 6) == 0) || (name_length == 3 && strnicmp(name, "ath", 3) == 0)) {
		printf("." "%s %u", __FILE__, __LINE__); exit(1);
	}

	if (fp == NULL) {
		fp = fopen("hamster.txt", "wt+");
	}
	if (fp == NULL)
		return;

	for (i=0; i<path_length && path[i] != '?'; i++)
		;
	path_length = i;

	hamster_trunc_cookie(&domain, &domain_length, path, &path_length, name, name_length);

	fprintf(fp, "Instance: %d.%d.%d.%d\n", 
		(client_ip>>24)&0xFF,(client_ip>>16)&0xFF,(client_ip>>8)&0xFF,(client_ip>>0)&0xFF
		);
	fprintf(fp, "Domain: %.*s\n", domain_length, domain);
	fprintf(fp, "Path: %.*s\n", path_length, path);
	fprintf(fp, "Name: %.*s\n", name_length, name);
	fprintf(fp, "Value: %.*s\n", value_length, value);
	fprintf(fp, "\n");
}
void hamster_set_cookie(unsigned client_ip, 
					const void *vdomain, unsigned domain_length,
					const void *vpath, unsigned path_length,
					const void *vname, unsigned name_length,
					const void *vvalue, unsigned value_length)
{
	UNUSEDPARM(client_ip);
	UNUSEDPARM(vdomain);
	UNUSEDPARM(domain_length);
	UNUSEDPARM(vpath);
	UNUSEDPARM(path_length);
	UNUSEDPARM(vname);
	UNUSEDPARM(name_length);
	UNUSEDPARM(vvalue);
	UNUSEDPARM(value_length);
#if 0
	const char *domain = (const char*)vdomain;
	const char *path = (const char*)vpath;
	const char *name = (const char*)vname;
	const char *value = (const char*)vvalue;
	unsigned i;
	char item[1024];
	static char **items=0;
	static unsigned item_count=0;

	UNUSEDPARM(value);UNUSEDPARM(value_length);
	return;

	if (name_length == 7 && strnicmp(name, "expires", 7) == 0)
		return;

	/*
	 * SPECIAL: This is a special command to load an existing 
	 * table of cookies.
	 */
	if (client_ip == 0xa3a3a3a4 && path==NULL) {
		for (i=0; cookietrunc[i].name_length; i++) {
			struct CookieTrunc *c = &cookietrunc[i];
			hamster_set_cookie(0,
					c->domain, c->domain_length,
					c->path, c->path_length,
					c->name, c->name_length,
					"", 0);
		}

	}

	/*
	 * SPECIAL: This is a special command to save the cookies
	 * then free the tables
	 */
	if (client_ip == 0xa3a3a3a3 && path==NULL) {
		FILE *fp = fopen("\\set-cookie.txt", "wt");

		fprintf(fp, "struct CookieTrunc {\n");
		fprintf(fp, "    unsigned domain_length;\n    char *domain;\n");
		fprintf(fp, "    unsigned path_length;\n    char *path;\n");
		fprintf(fp, "    unsigned name_length;\n    char *name;\n");
		fprintf(fp, "};\n");
		fprintf(fp, "struct CookieTrunc *cookietrunc[] = {\n");
		for (i=0; i<item_count; i++) {
			unsigned j, k;
			fprintf(fp, "    {");
			for (j=0; items[i][j] && items[i][j] != '/'; j++)
				;
			fprintf(fp, "%d, \"%.*s\", ", j, j, items[i]);

			for (k=j; items[i][k] && items[i][k] != '('; k++)
				;
			fprintf(fp, "%d, \"%.*s\", ", k-j, k-j, items[i]+j);

			if (items[i][k] == '(')
				k++;
			for (j=k; items[i][j] && items[i][j] != ')'; j++)
				;
			fprintf(fp, "%d, \"%.*s\"}, \n", j-k, j-k, items[i]+k);
		}

		fclose(fp);
		return;
	}


	while (domain_length && domain[0] == '.') {
		domain++;
		domain_length--;
	}
	sprintf_s(item, sizeof(item), "%.*s%.*s(%.*s)",
		domain_length, domain,
		path_length, path,
		name_length, name);


	for (i=0; i<item_count; i++) {
		int x;
		
		x = strcmp(item, items[i]);
		if (x == 0)
			return;
		if (x < 0)
			break;
	}

	{
		char **new_items = malloc((item_count+2)*sizeof(char*));
		if (items) {
			memcpy(new_items, items, item_count*sizeof(char*));
			if (i < item_count)
				memmove(&new_items[i+1], &new_items[i], (item_count-i)*sizeof(char*));
			free(items);
		}
		items = new_items;
		items[i] = malloc(strlen(item)+1);
		memcpy(items[i], item, strlen(item)+1);
		item_count++;
	}
#endif
}

void hamster_url(unsigned client_ip, 
					const void *vdomain, unsigned domain_length,
					const void *vurl, unsigned url_length,
					const void *vreferer, unsigned referer_length)
{
	const char *domain = (const char*)vdomain;
	const char *url = (const char*)vurl;
	const char *referer = (const char*)vreferer;

	if (fp == NULL) {
		fp = fopen("hamster.txt", "wt+");
	}
	if (fp == NULL)
		return;

	fprintf(fp, "Instance: %d.%d.%d.%d\n", 
		(client_ip>>24)&0xFF,(client_ip>>16)&0xFF,(client_ip>>8)&0xFF,(client_ip>>0)&0xFF
		);
	fprintf(fp, "Domain: %.*s\n", domain_length, domain);
	fprintf(fp, "URL: %.*s\n", url_length, url);
	if (referer_length)
		fprintf(fp, "Referer: %.*s\n", referer_length, referer);
	fprintf(fp, "\n");
}

void hamster_userid(const void *vid_ip, unsigned id_ip_length,
					const void *vuserid, unsigned userid_length
					)
{
	const char *id_ip = (const char*)vid_ip;
	const char *userid = (const char*)vuserid;

	if (fp == NULL) {
		fp = fopen("hamster.txt", "wt+");
	}
	if (fp == NULL)
		return;

	fprintf(fp, "Instance: %.*s\n", id_ip_length, id_ip);
	fprintf(fp, "User-ID: %.*s\n", userid_length, userid);
	fprintf(fp, "\n");
}

void hamster_icon(const void *vid_ip, unsigned id_ip_length,
					const void *vuserid, unsigned userid_length
					)
{
	const char *id_ip = (const char*)vid_ip;
	const char *userid = (const char*)vuserid;

	if (fp == NULL) {
		fp = fopen("hamster.txt", "wt+");
	}
	if (fp == NULL)
		return;

	fprintf(fp, "Instance: %.*s\n", id_ip_length, id_ip);
	fprintf(fp, "Icon: %.*s\n", userid_length, userid);
	fprintf(fp, "\n");
}
