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
	const char *role;	/* CN of group or role DN needed for auth */

	const char *cadir;
	const char *ca;
	const char *cert;
	const char *key;

	const char *userdn;
	const char *roledn;	/* group or role base DN */
};

struct ldap_auth {
	const struct ldap_auth_conf *conf;
	LDAP *ldap;
	int error;
	LDAPMessage *answer;
};

int  ldap_auth_init (struct ldap_auth *o, const struct ldap_auth_conf *c);
void ldap_auth_fini (struct ldap_auth *o);

const char *ldap_auth_error (const struct ldap_auth *o);

int ldap_auth_login (struct ldap_auth *o,
		     const char *user, const char *password);
char *ldap_auth_get_uid (struct ldap_auth *o);

#endif  /* LDAP_AUTH */
