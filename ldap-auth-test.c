/*
 * LDAP Authentication Helper Library Sample
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include "ldap-auth.h"

static void sep (const void *o)
{
	if (o != NULL)
		putchar ('\n');
}

static void dump (const struct ldap_auth *o)
{
	LDAPMessage *e;
	char *name;
	BerElement *be;
	struct berval **vals;
	size_t i;

	for (
		e = ldap_first_entry (o->ldap, o->answer);
		e != NULL;
		sep (e = ldap_next_entry (o->ldap, e))
	) {
		name = ldap_get_dn (o->ldap, e);
		printf ("dn: %s\n", name);
		ldap_memfree (name);

		for (
			name = ldap_first_attribute (o->ldap, e, &be);
			name != NULL;
			name = ldap_next_attribute (o->ldap, e, be)
		) {
			vals = ldap_get_values_len (o->ldap, e, name);

			for (i = 0; vals[i] != NULL; ++i)
				printf ("%s: %.*s\n", name,
					(int) vals[i]->bv_len, vals[i]->bv_val);

			ldap_value_free_len (vals);
		}
	}
}

int main (int argc, char *argv[])
{
	struct ldap_auth_conf c = {};
	struct ldap_auth o;

	c.uri    = "ldap://ikle-ldap";
	c.tls    = "demand";
	c.userdn = "ou=users,dc=example,dc=com";

	if (!ldap_auth_init (&o, &c)) {
		fprintf (stderr, "E: Cannot open LDAP connection: %s\n",
			 ldap_auth_error (&o));
		return 1;
	}

	if (!ldap_auth_login (&o, "alice", "Qwe123$-alice")) {
		fprintf (stderr, "E: Cannot authenticate user: %s\n",
				 ldap_auth_error (&o));
		goto no_auth;
	}

	dump (&o);

	ldap_auth_fini (&o);
	return 0;
no_auth:
	ldap_auth_fini (&o);
	return 1;
}
