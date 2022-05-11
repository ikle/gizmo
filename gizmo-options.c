/*
 * LDAP Access Options
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include "gizmo-int.h"

static int set_ldap_option (struct gizmo *o, int option, const void *v)
{
	o->error = ldap_set_option (o->ldap, option, v);
	return o->error == 0;
}

static int set_tls (struct gizmo *o, const char *tls)
{
	int opt;

	if (tls == NULL)
		goto no_param;

	if (strcmp (tls, "off") == 0) {
		o->flags &= ~LDAP_AUTH_STARTTLS;
		return 1;
	}

	if      (strcmp (tls, "never")  == 0) opt = LDAP_OPT_X_TLS_NEVER;
	else if (strcmp (tls, "allow")  == 0) opt = LDAP_OPT_X_TLS_ALLOW;
	else if (strcmp (tls, "try")    == 0) opt = LDAP_OPT_X_TLS_TRY;
	else if (strcmp (tls, "demand") == 0) opt = LDAP_OPT_X_TLS_DEMAND;
	else
		goto no_param;

	o->flags |= LDAP_AUTH_STARTTLS;
	return set_ldap_option (o, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt);
no_param:
	o->error = LDAP_PARAM_ERROR;
	return 0;
}

static int set_option (struct gizmo *o, const char *name, const char *value)
{
	if (strcmp (name, "tls") == 0)
		return set_tls (o, value);

	if (strcmp (name, "tls-cadir") == 0)
		return set_ldap_option (o, LDAP_OPT_X_TLS_CACERTDIR, value);

	if (strcmp (name, "tls-ca") == 0)
		return set_ldap_option (o, LDAP_OPT_X_TLS_CACERTFILE, value);

	if (strcmp (name, "tls-cert") == 0)
		return set_ldap_option (o, LDAP_OPT_X_TLS_CERTFILE, value);

	if (strcmp (name, "tls-key") == 0)
		return set_ldap_option (o, LDAP_OPT_X_TLS_KEYFILE, value);

	if (strcmp (name, "admin") == 0)
		o->admin = value;

	else if (strcmp (name, "password") == 0)
		o->password = value;

	else if (strcmp (name, "userdn") == 0)
		o->userdn = value;

	else if (strcmp (name, "role") == 0)
		o->role = value;

	else if (strcmp (name, "roledn") == 0)
		o->roledn = value;

	return 1;
}

int gizmo_set_options_va (struct gizmo *o, va_list ap)
{
	const char *name, *value;

	o->admin	= NULL;
	o->password	= NULL;

	o->userdn	= NULL;
	o->role		= NULL;
	o->roledn	= NULL;

	while ((name = va_arg (ap, const char *)) != NULL) {
		value = va_arg (ap, const char *);

		if (!set_option (o, name, value))
			return 0;
	}

	return 1;
}
