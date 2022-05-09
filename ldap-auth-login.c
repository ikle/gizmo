/*
 * LDAP Authentication Login Helper
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ldap-auth-int.h"

static int ldap_check_role (struct ldap_auth *o, const char *dn)
{
	static const char *attrs[] = { "member", "roleOccupant", };
	static const char *filter =
		"(|"
		"(&(cn=%1$s)(member=%2$s)(ObjectClass=Group))"
		"(&(cn=%1$s)(uniqueMember=%2$s)(ObjectClass=groupOfUniqueNames))"
		"(&(cn=%1$s)(roleOccupant=%2$s)(ObjectClass=organizationalRole))"
		")";
	LDAPMessage *m;
	int match;

	if (o->role == NULL)
		return 1;

	m = ldap_auth_fetch (o, o->roledn, attrs, filter, o->role, dn);
	match = o->error == 0 && ldap_count_entries (o->ldap, m) > 0;
	ldap_msgfree (m);

	if (!match)
		o->error = LDAP_INSUFFICIENT_ACCESS;

	return match;
}

int ldap_auth_login (struct ldap_auth *o,
		     const char *user, const char *password)
{
	LDAPMessage *e;
	char *dn;
	int ldap_error = LDAP_INVALID_CREDENTIALS, ok;

	if (!ldap_auth_bind (o, o->user, o->password) ||
	    !ldap_auth_get_user (o, user, NULL))
		goto no_user;

	if (ldap_count_entries (o->ldap, o->answer) != 1)
		goto no_uniq;

	e = ldap_first_entry (o->ldap, o->answer);

	if ((dn = ldap_get_dn (o->ldap, e)) == NULL) {
		ldap_error = LDAP_DECODING_ERROR;
		goto no_dn;
	}

	ok = ldap_check_role (o, dn) && ldap_auth_bind (o, dn, password);

	ldap_memfree (dn);
	return ok;
no_dn:
no_uniq:
	ldap_msgfree (o->answer);
	o->answer = NULL;
no_user:
	o->error = ldap_error;
	errno = EACCES;
	return 0;
}
