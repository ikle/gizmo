/*
 * LDAP Authentication Helper Library
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ldap.h>

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

static int set_options (struct ldap_auth *o, va_list ap)
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

static int do_tls (struct ldap_auth *o, const char *uri)
{
	return	!o->tls ||
		strncmp (uri, "ldaps://", 8) == 0 ||
		ldap_start_tls_s (o->ldap, NULL, NULL) == 0;
}

static
int ldap_auth_bind (struct ldap_auth *o, const char *user, const char *password)
{
	struct berval cred;

	cred.bv_val = password == NULL ? "" : (void *) password;
	cred.bv_len = strlen (cred.bv_val);

	o->error = ldap_sasl_bind_s (o->ldap, user, LDAP_SASL_SIMPLE,
				     &cred, NULL, NULL, NULL);
	return o->error == 0;
}

int ldap_auth_init_va (struct ldap_auth *o, const char *uri, va_list ap)
{
	const int version = LDAP_VERSION3;

	o->error = LDAP_PARAM_ERROR;
	o->answer = NULL;

	if (uri == NULL || uri[strcspn (uri, " ,")] != '\0' ||
	    (o->error = ldap_initialize (&o->ldap, uri) != 0))
		return 0;

	if (!ldap_auth_set_option (o, LDAP_OPT_PROTOCOL_VERSION, &version) ||
	    !set_options (o, ap) ||
	    !do_tls (o, uri))
		goto error;

	return 1;
error:
	ldap_destroy (o->ldap);
	return 0;
}

int ldap_auth_init (struct ldap_auth *o, const char *uri, ...)
{
	va_list ap;
	int rc;

	va_start (ap, uri);
	rc = ldap_auth_init_va (o, uri, ap);
	va_end (ap);
	return rc;
}

void ldap_auth_fini (struct ldap_auth *o)
{
	ldap_msgfree (o->answer);
	ldap_destroy (o->ldap);
}

const char *ldap_auth_error (const struct ldap_auth *o)
{
	return ldap_err2string (o->error);
}

static LDAPMessage *
ldap_fetch_va (struct ldap_auth *o, const char *basedn, const char *attrs[],
	       const char *fmt, va_list ap)
{
	int len;
	char *filter;
	LDAPMessage *m;

	len = vsnprintf (NULL, 0, fmt, ap) + 1;

	if ((filter = malloc (len)) == NULL)
		return 0;

	vsnprintf (filter, len, fmt, ap);

	o->error = ldap_search_ext_s (o->ldap, basedn, LDAP_SCOPE_SUBTREE,
				      filter, (char **) attrs, 0,
				      NULL, NULL, NULL,
				      LDAP_NO_LIMIT, &m);
	free (filter);

	if (o->error == 0)
		return m;

	ldap_msgfree (m);
	return NULL;
}

static LDAPMessage *
ldap_fetch (struct ldap_auth *o, const char *basedn, const char *attrs[],
	    const char *fmt, ...)
{
	va_list ap;
	LDAPMessage *m;

	va_start (ap, fmt);
	m = ldap_fetch_va (o, basedn, attrs, fmt, ap);
	va_end (ap);
	return m;
}

static int ldap_get_user (struct ldap_auth *o, const char *user)
{
	static const char *filter =
		"(|"
		"(&(cn=%1$s)(objectClass=person))"
		"(&(uid=%1$s)(objectClass=posixAccount))"
		"(&(sAMAccountName=%1$s)(ObjectClass=User))"
		")";

	o->answer = ldap_fetch (o, o->userdn, NULL, filter, user);
	return o->error == 0;
}

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

	m = ldap_fetch (o, o->roledn, attrs, filter, o->role, dn);
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
	int ok;

	if (!ldap_auth_bind (o, o->user, o->password)||
	    !ldap_get_user (o, user))
		goto no_user;

	if (ldap_count_entries (o->ldap, o->answer) != 1)
		goto no_uniq;

	e = ldap_first_entry (o->ldap, o->answer);

	if ((dn = ldap_get_dn (o->ldap, e)) == NULL) {
		o->error = LDAP_LOCAL_ERROR;
		goto no_dn;
	}

	ok = ldap_check_role (o, dn);
	ok = ldap_auth_bind (o, dn, password) && ok;

	ldap_memfree (dn);
	return ok;
no_dn:
no_uniq:
	ldap_msgfree (o->answer);
	o->answer = NULL;
no_user:
	o->error = LDAP_INVALID_CREDENTIALS;
	return 0;
}
