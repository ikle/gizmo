/*
 * LDAP Access Helper Library Sample
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include <gizmo.h>
#include <gizmo-misc.h>

int main (int argc, char *argv[])
{
	struct gizmo *o;

	o = gizmo_open ("ldap://ikle-ldap", "tls", "demand",
			"userdn", "ou=users,dc=example,dc=com",
			NULL);
	if (o == NULL) {
		perror ("E: Cannot open LDAP connection");
		return 1;
	}

	if (!gizmo_login (o, "alice", "Qwe123$-alice")) {
		fprintf (stderr, "E: Cannot authenticate user: %s\n",
				 gizmo_error (o));
		goto no_auth;
	}

	gizmo_dump_entries (o, stdout);

	gizmo_close (o);
	return 0;
no_auth:
	gizmo_close (o);
	return 1;
}
