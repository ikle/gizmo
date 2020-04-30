/*
 * LDAP Authentication Helper Library Sample
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "ldap-auth.h"

int main (int argc, char *argv[])
{
	struct ldap_auth o;
	char *uid;

	if (!ldap_auth_init (&o, "ldap://ikle-ldap", "tls", "demand",
			     "userdn", "ou=users,dc=example,dc=com",
			     NULL)) {
		fprintf (stderr, "E: Cannot open LDAP connection: %s\n",
			 ldap_auth_error (&o));
		return 1;
	}

	if (!ldap_auth_login (&o, "alice", "Qwe123$-alice")) {
		fprintf (stderr, "E: Cannot authenticate user: %s\n",
				 ldap_auth_error (&o));
		goto no_auth;
	}

	if ((uid = ldap_auth_get_uid (&o)) != NULL) {
		printf ("I: Logged in as %s\n\n", uid);
		free (uid);
	}

	ldap_auth_dump_entries (&o, stdout);

	ldap_auth_fini (&o);
	return 0;
no_auth:
	ldap_auth_fini (&o);
	return 1;
}
