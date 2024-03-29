/*
 * LDAP Login Helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gizmo-int.h"

static int ldap_check_role (struct gizmo *o, const char *dn)
{
	static const char *attrs[] = { "member", "roleOccupant", };
	static const char *filter =
		"(|"
		"(&(cn=%1$s)(member=%2$s)(ObjectClass=Group))"
		"(&(cn=%1$s)(uniqueMember=%2$s)(ObjectClass=groupOfUniqueNames))"
		"(&(cn=%1$s)(roleOccupant=%2$s)(ObjectClass=organizationalRole))"
		")";
	LDAPMessage *m = o->answer;
	int match;

	if (o->role == NULL)
		return 1;

	match = gizmo_fetch (o, o->roledn, attrs, GIZMO_SUB, filter, o->role, dn) &&
		ldap_count_entries (o->ldap, m) > 0;

	ldap_msgfree (o->answer);
	o->answer = m;

	if (!match)
		o->error = LDAP_INSUFFICIENT_ACCESS;

	return match;
}

int gizmo_login (struct gizmo *o, const char *user, const char *password)
{
	LDAPMessage *e;

	if (!gizmo_bind (o, o->admin, o->password) ||
	    !gizmo_get_user (o, user, NULL))
		goto fail;

	for (
		e = ldap_first_entry (o->ldap, o->answer);
		e != NULL;
		e = ldap_next_entry (o->ldap, e)
	) {
		ldap_memfree (o->user);

		if ((o->user = ldap_get_dn (o->ldap, e)) == NULL) {
			o->error = LDAP_DECODING_ERROR;
			continue;
		}

		if (ldap_check_role (o, o->user) &&
		    gizmo_bind (o, o->user, password))
			return 1;
	}
fail:
	errno = EACCES;
	return 0;
}
