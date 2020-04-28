/*
 * LDAP Authentication Helper Library
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdarg.h>
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

static int set_tls (struct ldap_auth *o)
{
	const char *tls = o->conf->tls;
	int opt;

	if (tls == NULL)
		return 1;

	if      (strcmp (tls, "never")  == 0) opt = LDAP_OPT_X_TLS_NEVER;
	else if (strcmp (tls, "allow")  == 0) opt = LDAP_OPT_X_TLS_ALLOW;
	else if (strcmp (tls, "try")    == 0) opt = LDAP_OPT_X_TLS_TRY;
	else if (strcmp (tls, "demand") == 0) opt = LDAP_OPT_X_TLS_DEMAND;
	else
		return 0;

	return ldap_auth_set_option (o, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt);
}

static int set_options (struct ldap_auth *o)
{
	const struct ldap_auth_conf *c = o->conf;

	if (!set_tls (o))
		return 0;

	if (c->cadir != NULL &&
	    !ldap_auth_set_option (o, LDAP_OPT_X_TLS_CACERTDIR, &c->cadir))
		return 0;

	if (c->ca != NULL &&
	    !ldap_auth_set_option (o, LDAP_OPT_X_TLS_CACERTFILE, &c->ca))
		return 0;

	if (c->cert != NULL &&
	    !ldap_auth_set_option (o, LDAP_OPT_X_TLS_CERTFILE, &c->cert))
		return 0;

	if (c->key != NULL &&
	    !ldap_auth_set_option (o, LDAP_OPT_X_TLS_KEYFILE, &c->key))
		return 0;

	return 1;
}

static int do_tls (struct ldap_auth *o)
{
	const struct ldap_auth_conf *c = o->conf;

	return	c->tls == NULL ||
		strncmp (c->uri, "ldaps://", 8) == 0 ||
		ldap_start_tls_s (o->ldap, NULL, NULL) == 0;
}

int ldap_auth_init (struct ldap_auth *o, const struct ldap_auth_conf *c)
{
	const int version = LDAP_VERSION3;
	struct berval cred;

	o->conf = c;
	o->error = LDAP_PARAM_ERROR;
	o->answer = NULL;

	if (c->uri == NULL ||
	    (o->error = ldap_initialize (&o->ldap, c->uri) != 0))
		return 0;

	if (!ldap_auth_set_option (o, LDAP_OPT_PROTOCOL_VERSION, &version) ||
	    !set_options (o) ||
	    !do_tls (o))
		goto error;

	if (c->user != NULL) {
		cred.bv_val = c->password == NULL ? "" : (void *) c->password;
		cred.bv_len = strlen (cred.bv_val);

		o->error = ldap_sasl_bind_s (o->ldap, c->user, LDAP_SASL_SIMPLE,
					     &cred, NULL, NULL, NULL);
		if (o->error != 0)
			goto error;
	}

	return 1;
error:
	ldap_destroy (o->ldap);
	return 0;
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

	o->answer = ldap_fetch (o, o->conf->userdn, NULL, filter, user);
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
	LDAPMessage *m, *e;
	int match;

	if (o->conf->role == NULL)
		return 1;

	m = ldap_fetch (o, o->conf->roledn, attrs, filter, o->conf->role, dn);
	e = ldap_first_entry (o->ldap, m);
	match = o->error == 0 && ldap_count_entries (o->ldap, e) > 0;
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
	struct berval cred;

	if (!ldap_get_user (o, user))
		return 0;

	if (ldap_count_entries (o->ldap, o->answer) != 1) {
		o->error = LDAP_NO_SUCH_OBJECT;
		goto no_user;
	}

	e = ldap_first_entry (o->ldap, o->answer);

	if ((dn = ldap_get_dn (o->ldap, e)) == NULL) {
		o->error = LDAP_LOCAL_ERROR;
		goto no_dn;
	}

	if (!ldap_check_role (o, dn))
		goto no_role;

	cred.bv_val = password == NULL ? "" : (void *) password;
	cred.bv_len = strlen (cred.bv_val);

	o->error = ldap_sasl_bind_s (o->ldap, dn, LDAP_SASL_SIMPLE, &cred,
				     NULL, NULL, NULL);
	if (o->error != 0)
		goto no_auth;

	ldap_memfree (dn);
	return 1;
no_auth:
no_role:
	ldap_memfree (dn);
no_dn:
no_user:
	ldap_msgfree (o->answer);
	o->answer = NULL;
	return 0;
}

char *ldap_auth_get (struct ldap_auth *o, const char *attrs[])
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
