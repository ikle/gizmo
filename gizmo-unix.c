/*
 * LDAP Access Helper Library, UNIX helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>

#include <gizmo-unix.h>

#include "gizmo-int.h"

static char *get_str (struct gizmo *o, LDAPMessage *e, const char *name)
{
	struct berval **vals;
	char *value;

	if ((vals = ldap_get_values_len (o->ldap, e, name)) == NULL)
		return NULL;

	value = strdup (vals[0]->bv_val);
	ldap_value_free_len (vals);
	return value;
}

static int get_num (struct gizmo *o, LDAPMessage *e, const char *name)
{
	struct berval **vals;
	int value;

	if ((vals = ldap_get_values_len (o->ldap, e, name)) == NULL)
		return -1;

	value = atoi (vals[0]->bv_val);
	ldap_value_free_len (vals);
	return value;
}

int gizmo_getent (struct gizmo *o, const char *user, struct passwd *p)
{
	static const char *attrs[] = {
		"uid", "sAMAccountName",
		"uidNumber",
		"gidNumber",
		"gecos", "cn",
		"homeDirectory", "unixHomeDirectory",
		"loginShell",
	};
	LDAPMessage *e;

	if (!gizmo_get_user (o, user, attrs))
		return 0;

	if (o->answer == NULL ||
	    (e = ldap_first_entry (o->ldap, o->answer)) == NULL)
		return 0;

	memset (p, 0, sizeof (*p));

	if ((p->pw_name = get_str (o, e, "uid")) == NULL)
		p->pw_name = get_str (o, e, "sAMAccountName");

	p->pw_uid = get_num (o, e, "uidNumber");
	p->pw_gid = get_num (o, e, "gidNumber");

	if ((p->pw_gecos = get_str (o, e, "gecos")) == NULL)
		p->pw_gecos = get_str (o, e, "cn");

	if ((p->pw_dir = get_str (o, e, "homeDirectory")) == NULL)
		p->pw_dir = get_str (o, e, "unixHomeDirectory");

	p->pw_shell = get_str (o, e, "loginShell");

	return 1;
}
