/*
 * LDAP Authentication Helper Library Sample
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "ldap-auth.h"

static void dump (LDAP *o, LDAPMessage *m)
{
	LDAPMessage *e;
	char *name;
	BerElement *be;
	struct berval **vals;
	size_t i;

	for (
		e = ldap_first_entry (o, m);
		e != NULL;
		e = ldap_next_entry (o, e)
	) {
		name = ldap_get_dn (o, e);
		printf ("%s:\n", name);
		ldap_memfree (name);

		for (
			name = ldap_first_attribute (o, e, &be);
			name != NULL;
			name = ldap_next_attribute (o, e, be)
		) {
			vals = ldap_get_values_len (o, e, name);

			for (i = 0; vals[i] != NULL; ++i)
				printf ("    %s = %.*s\n", name,
					(int) vals[i]->bv_len, vals[i]->bv_val);

			ldap_value_free_len (vals);
		}
	}
}

int main (int argc, char *argv[])
{
	struct ldap_auth_conf c = {};
	LDAP *o;
	LDAPMessage *m;

	c.uri    = "ldap:///";
	c.userdn = "ou=users,dc=example,dc=com";

	if ((o = ldap_auth_open (&c)) == NULL) {
		perror ("cannot open LDAP connection");
		return 1;
	}

	if ((m = ldap_auth_login (o, &c, "alice", "Qwe123$-alice")) == NULL) {
		perror ("cannot authenticate user");
		goto no_auth;
	}

	dump (o, m);

	ldap_msgfree (m);
	ldap_auth_close (o);
	return 0;
no_auth:
	ldap_auth_close (o);
	return 1;
}
