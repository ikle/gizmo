/*
 * LDAP Authentication Helper Library Miscelaneous Utilites
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ldap-auth-misc.h>

#include "ldap-auth-int.h"

static void sep (const void *o, FILE *to)
{
	if (o != NULL)
		putc ('\n', to);
}

static void dump_attrs (const struct ldap_auth *o, LDAPMessage *e, FILE *to)
{
	char *name;
	BerElement *be;
	struct berval **vals;
	size_t i;

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
			fprintf (to, "%s: %.*s\n", name,
				 (int) vals[i]->bv_len, vals[i]->bv_val);

		ldap_value_free_len (vals);
	}
}

void ldap_auth_dump_entries (const struct ldap_auth *o, FILE *to)
{
	LDAPMessage *e;

	for (
		e = ldap_first_entry (o->ldap, o->answer);
		e != NULL;
		sep (e = ldap_next_entry (o->ldap, e), to)
	)
		dump_attrs (o, e, to);
}
