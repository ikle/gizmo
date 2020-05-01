/*
 * LDAP Authentication Helper Library Sample
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include <ldap-auth.h>

int main (int argc, char *argv[])
{
	struct ldap_auth *o;

	o = ldap_auth_alloc ("ldap://ikle-ldap", "tls", "demand",
			     "userdn", "ou=users,dc=example,dc=com",
			     NULL);
	if (o == NULL) {
		perror ("E: Cannot open LDAP connection");
		return 1;
	}

	if (!ldap_auth_login (o, "alice", "Qwe123$-alice")) {
		fprintf (stderr, "E: Cannot authenticate user: %s\n",
				 ldap_auth_error (o));
		goto no_auth;
	}

	ldap_auth_dump_entries (o, stdout);

	ldap_auth_free (o);
	return 0;
no_auth:
	ldap_auth_free (o);
	return 1;
}
