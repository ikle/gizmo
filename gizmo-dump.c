/*
 * LDAP Access Helper Library, Dump helpers
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <gizmo-misc.h>

#include "base64.h"
#include "gizmo-int.h"

static void sep (const void *o, FILE *to)
{
	if (o != NULL)
		putc ('\n', to);
}

static void dump_attr (const char *name, const char *data, size_t len, FILE *to)
{
	struct b64_filter b64;
	size_t i;

	if (strstr (name, ";binary") == NULL) {
		fprintf (to, "%s: %.*s\n", name, (int) len, data);
		return;
	}

	fprintf (to, "%s::\n ", name);
	b64_init (&b64, to, "\n ");

	for (i = 0; i < len; ++i)
		b64_putc (&b64, data[i]);

	b64_fini (&b64);
	fprintf (to, "\n");
}

static void dump_attrs (const struct gizmo *o, LDAPMessage *e, FILE *to)
{
	char *name;
	BerElement *be = NULL;
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
			dump_attr (name, vals[i]->bv_val, vals[i]->bv_len, to);

		ldap_value_free_len (vals);
	}

	ber_free (be, 0);
}

void gizmo_dump_entries (const struct gizmo *o, FILE *to)
{
	LDAPMessage *e;

	for (
		e = ldap_first_entry (o->ldap, o->answer);
		e != NULL;
		sep (e = ldap_next_entry (o->ldap, e), to)
	)
		dump_attrs (o, e, to);
}
