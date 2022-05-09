/*
 * LDAP Access Helper Library
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

static int set_ldap_option (struct gizmo *o, int option, const void *v)
{
	o->error = ldap_set_option (o->ldap, option, v);
	return o->error == 0;
}

static int start_tls (struct gizmo *o)
{
	return	(o->flags & LDAP_AUTH_LDAPS) != 0 ||
		(o->flags & LDAP_AUTH_STARTTLS) == 0 ||
		(o->error = ldap_start_tls_s (o->ldap, NULL, NULL)) == 0;
}

int gizmo_init_va (struct gizmo *o, const char *uri, va_list ap)
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
	    !gizmo_set_options_va (o, ap) ||
	    !start_tls (o))
		goto error;

	return 1;
error:
	ldap_destroy (o->ldap);
	return 0;
}

struct gizmo *gizmo_open_va (const char *uri, va_list ap)
{
	struct gizmo *o;

	if ((o = malloc (sizeof (*o))) == NULL)
		return NULL;

	if (gizmo_init_va (o, uri, ap))
		return o;

	free (o);
	errno = EPROTO;
	return NULL;
}

struct gizmo *gizmo_open (const char *uri, ...)
{
	va_list ap;
	struct gizmo *o;

	va_start (ap, uri);
	o = gizmo_open_va (uri, ap);
	va_end (ap);
	return o;
}

void gizmo_close (struct gizmo *o)
{
	if (o == NULL)
		return;

	ldap_msgfree (o->answer);
	ldap_destroy (o->ldap);
	free (o);
}

const char *gizmo_error (const struct gizmo *o)
{
	return ldap_err2string (o->error);
}

int gizmo_bind (struct gizmo *o, const char *user, const char *password)
{
	struct berval cred;

	cred.bv_val = password == NULL ? "" : (void *) password;
	cred.bv_len = strlen (cred.bv_val);

	o->error = ldap_sasl_bind_s (o->ldap, user, LDAP_SASL_SIMPLE,
				     &cred, NULL, NULL, NULL);
	return o->error == 0;
}

static LDAPMessage *
ldap_fetch_va (struct gizmo *o, const char *basedn, const char *attrs[],
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

LDAPMessage *
gizmo_fetch (struct gizmo *o, const char *basedn, const char *attrs[],
		 const char *fmt, ...)
{
	va_list ap;
	LDAPMessage *m;

	va_start (ap, fmt);
	m = ldap_fetch_va (o, basedn, attrs, fmt, ap);
	va_end (ap);
	return m;
}

int gizmo_get_user (struct gizmo *o, const char *user, const char *attrs[])
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

	o->answer = gizmo_fetch (o, o->userdn, attrs, filter, user);
	return o->error == 0;
}
