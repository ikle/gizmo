/*
 * LDAP Authentication Helper Library
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LDAP_AUTH
#define LDAP_AUTH  1

#include <ldap.h>

struct ldap_auth_conf {
	const char *uri;
	const char *tls;	/* never, allow, try, demand */

	const char *user;	/* bind DN */
	const char *password;

	const char *cadir;
	const char *ca;
	const char *cert;
	const char *key;

	const char *userdn;
};

LDAP *ldap_auth_open (const struct ldap_auth_conf *c);
void ldap_auth_close (LDAP *o);

LDAPMessage *ldap_auth_login (LDAP *o, const struct ldap_auth_conf *c,
			      const char *user, const char *password);

#endif  /* LDAP_AUTH */
