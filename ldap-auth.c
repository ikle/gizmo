/*
 * LDAP Authentication Helper Library
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

static int set_ldap_option (struct ldap_auth *o, int option, const void *v)
{
	o->error = ldap_set_option (o->ldap, option, v);
	return o->error == 0;
}

static int start_tls (struct ldap_auth *o)
{
	return	(o->flags & LDAP_AUTH_LDAPS) != 0 ||
		(o->flags & LDAP_AUTH_STARTTLS) == 0 ||
		(o->error = ldap_start_tls_s (o->ldap, NULL, NULL)) == 0;
}

int ldap_auth_init_va (struct ldap_auth *o, const char *uri, va_list ap)
{
	const int version = LDAP_VERSION3;

	o->error = LDAP_PARAM_ERROR;
	o->answer = NULL;
	o->flags  = 0;

	if (uri == NULL || uri[strcspn (uri, " ,")] != '\0' ||
	    (o->error = ldap_initialize (&o->ldap, uri) != 0))
		return 0;

	if (strncmp (uri, "ldaps://", 8) == 0)
		o->flags |= LDAP_AUTH_LDAPS;

	if (!set_ldap_option (o, LDAP_OPT_PROTOCOL_VERSION, &version) ||
	    !ldap_auth_set_options_va (o, ap) ||
	    !start_tls (o))
		goto error;

	return 1;
error:
	ldap_destroy (o->ldap);
	return 0;
}

struct ldap_auth *ldap_auth_alloc_va (const char *uri, va_list ap)
{
	struct ldap_auth *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if (ldap_auth_init_va (o, uri, ap))
		return o;

	free (o);
	errno = EPROTO;
	return NULL;
}

struct ldap_auth *ldap_auth_alloc (const char *uri, ...)
{
	va_list ap;
	struct ldap_auth *o;

	va_start (ap, uri);
	o = ldap_auth_alloc_va (uri, ap);
	va_end (ap);
	return o;
}

void ldap_auth_free (struct ldap_auth *o)
{
	if (o == NULL)
		return;

	ldap_msgfree (o->answer);
	ldap_destroy (o->ldap);
	free (o);
}

const char *ldap_auth_error (const struct ldap_auth *o)
{
	return ldap_err2string (o->error);
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

int ldap_auth_get_user (struct ldap_auth *o, const char *user,
			const char *attrs[])
{
	static const char *def_attrs[] = { "uid", "sAMAccountName", };
	static const char *filter =
		"(|"
		"(&(cn=%1$s)(objectClass=person))"
		"(&(uid=%1$s)(objectClass=posixAccount))"
		"(&(sAMAccountName=%1$s)(ObjectClass=User))"
		")";

	if (attrs == NULL)
		attrs = def_attrs;

	o->answer = ldap_fetch (o, o->userdn, attrs, filter, user);
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
