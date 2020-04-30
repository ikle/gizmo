/*
 * LDAP Authentication Options
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>

#include "ldap-auth.h"

static int ldap_auth_set_option (struct ldap_auth *o, int option, const void *v)
{
	o->error = ldap_set_option (o->ldap, option, v);
	return o->error == 0;
}

static int set_tls (struct ldap_auth *o, const char *tls)
{
	int opt;

	o->tls = 0;

	if (tls == NULL)
		return 1;

	if      (strcmp (tls, "never")  == 0) opt = LDAP_OPT_X_TLS_NEVER;
	else if (strcmp (tls, "allow")  == 0) opt = LDAP_OPT_X_TLS_ALLOW;
	else if (strcmp (tls, "try")    == 0) opt = LDAP_OPT_X_TLS_TRY;
	else if (strcmp (tls, "demand") == 0) opt = LDAP_OPT_X_TLS_DEMAND;
	else {
		o->error = LDAP_PARAM_ERROR;
		return 0;
	}

	o->tls = 1;
	return ldap_auth_set_option (o, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt);
}

static int set_option (struct ldap_auth *o, const char *name, const char *value)
{
	if (strcmp (name, "user") == 0)
		o->user = value;

	else if (strcmp (name, "password") == 0)
		o->password = value;

	else if (strcmp (name, "userdn") == 0)
		o->userdn = value;

	else if (strcmp (name, "role") == 0)
		o->role = value;

	else if (strcmp (name, "roledn") == 0)
		o->roledn = value;

	else if (strcmp (name, "tls") == 0) {
		if (!set_tls (o, value))
			return 0;
	}
	else if (strcmp (name, "tls-cadir") == 0) {
		if (!ldap_auth_set_option (o, LDAP_OPT_X_TLS_CACERTDIR, value))
			return 0;
	}
	else if (strcmp (name, "tls-ca") == 0) {
		if (!ldap_auth_set_option (o, LDAP_OPT_X_TLS_CACERTFILE, value))
			return 0;
	}
	else if (strcmp (name, "tls-cert") == 0) {
		if (!ldap_auth_set_option (o, LDAP_OPT_X_TLS_CERTFILE, value))
			return 0;
	}
	else if (strcmp (name, "tls-key") == 0) {
		if (!ldap_auth_set_option (o, LDAP_OPT_X_TLS_KEYFILE, value))
			return 0;
	}

	return 1;
}

int ldap_auth_set_options_va (struct ldap_auth *o, va_list ap)
{
	const char *name, *value;

	o->tls = 0;

	o->user		= NULL;
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

int ldap_auth_set_options (struct ldap_auth *o, ...)
{
	va_list ap;
	int rc;

	va_start (ap, o);
	rc = ldap_auth_set_options_va (o, ap);
	va_end (ap);
	return rc;
}
