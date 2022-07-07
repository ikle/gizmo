/*
 * LDAP Access Helper Library, Scan result helpers
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "gizmo-int.h"

static
int scan_attrs (struct gizmo *o, LDAPMessage *e, gizmo_cb cb, void *cookie)
{
	char *name;
	BerElement *be = NULL;
	int stop = 0;
	struct berval **vals;
	size_t i;

	name = ldap_get_dn (o->ldap, e);
	cb (o, name, NULL, 0, cookie);
	ldap_memfree (name);

	for (
		name = ldap_first_attribute (o->ldap, e, &be);
		!stop && name != NULL;
		name = ldap_next_attribute (o->ldap, e, be)
	) {
		vals = ldap_get_values_len (o->ldap, e, name);

		for (i = 0; !stop && vals[i] != NULL; ++i)
			stop = cb (o, name, vals[i]->bv_val,
				   vals[i]->bv_len, cookie);

		ldap_value_free_len (vals);
		ber_memfree (name);
	}

	ber_free (be, 0);
	return stop;
}

int gizmo_scan (struct gizmo *o, gizmo_cb cb, void *cookie)
{
	LDAPMessage *e;
	int stop = 0;

	for (
		e = ldap_first_entry (o->ldap, o->answer);
		!stop && e != NULL;
		e = ldap_next_entry (o->ldap, e)
	)
		stop = scan_attrs (o, e, cb, cookie);

	return stop;
}
