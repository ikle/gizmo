/*
 * LDAP Authentication Helper Library
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LDAP_AUTH
#define LDAP_AUTH  1

#include <stdarg.h>
#include <ldap.h>

struct ldap_auth {
	LDAP *ldap;
	int error;
	LDAPMessage *answer;

	int tls;

	const char *user;	/* bind DN */
	const char *password;

	const char *userdn;
	const char *role;	/* CN of group or role DN needed for auth */
	const char *roledn;	/* group or role base DN */
};

int  ldap_auth_init_va (struct ldap_auth *o, const char *uri, va_list ap);
int  ldap_auth_init (struct ldap_auth *o, const char *uri, ...);
void ldap_auth_fini (struct ldap_auth *o);

const char *ldap_auth_error (const struct ldap_auth *o);

int ldap_auth_login (struct ldap_auth *o,
		     const char *user, const char *password);
char *ldap_auth_get_uid (struct ldap_auth *o);

#endif  /* LDAP_AUTH */
