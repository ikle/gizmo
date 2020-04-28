/*
 * LDAP Authentication Helper Library Miscelaneous Utilites
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ldap.h>

#include "ldap-auth.h"

static char *ldap_auth_get (struct ldap_auth *o, const char *attrs[])
{
	LDAPMessage *e;
	struct berval **vals;
	char *uid;

	if (o->answer == NULL ||
	    (e = ldap_first_entry (o->ldap, o->answer)) == NULL)
		goto no_attr;

	for (; attrs[0] != NULL; ++attrs)
		if ((vals = ldap_get_values_len (o->ldap, e, attrs[0])) != NULL)
			break;

	if (attrs[0] == NULL)
		goto no_attr;

	uid = strdup (vals[0]->bv_val);
	ldap_value_free_len (vals);

	if (uid == NULL)
		o->error = LDAP_NO_MEMORY;

	return uid;
no_attr:
	o->error = LDAP_NO_SUCH_ATTRIBUTE;
	return NULL;
}

char *ldap_auth_get_uid (struct ldap_auth *o)
{
	static const char *attrs[] = { "uid", "sAMAccountName", };

	return ldap_auth_get (o, attrs);
}
