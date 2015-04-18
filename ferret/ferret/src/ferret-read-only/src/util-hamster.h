/*
	Glue logic between FERRET and  HAMSTER
*/
#ifndef __HAMSTER_H
#define __HAMSTER_H
#ifdef __cplusplus
extern "C" {
#endif

void hamster_cookie(unsigned client_ip, 
					const void *domain, unsigned domain_length,
					const void *path, unsigned path_length,
					const void *name, unsigned name_length,
					const void *value, unsigned value_length);

void hamster_url(unsigned client_ip, 
					const void *domain, unsigned domain_length,
					const void *url, unsigned url_length,
					const void *referer, unsigned referer_length);


void hamster_userid(const void *id_ip, unsigned id_ip_length,
					const void *userid, unsigned userid_length
					);

void hamster_set_cookie(unsigned client_ip, 
					const void *vdomain, unsigned domain_length,
					const void *vpath, unsigned path_length,
					const void *name, unsigned name_length,
					const void *value, unsigned value_length);

#ifdef __cplusplus
}
#endif
#endif
