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

	if (c->uri == NULL || ldap_initialize (&o->ldap, c->uri) != 0)
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
	ldap_destroy (o->ldap);
}

const char *ldap_auth_error (const struct ldap_auth *o)
{
	return ldap_err2string (o->error);
}

static LDAPMessage *ldap_get_user (struct ldap_auth *o, const char *user)
{
	const struct ldap_auth_conf *c = o->conf;
	int len;
	char *filter;
	LDAPMessage *m;

#define POSIX_FILTER	"(&(uid=%1$s)(objectClass=posixAccount))"
#define AD_FILTER	"(&(sAMAccountName=%1$s)(ObjectClass=User))"
#define FILTER		"(|" POSIX_FILTER AD_FILTER ")"

	len = snprintf (NULL, 0, FILTER, user) + 1;

	if ((filter = malloc (len)) == NULL)
		return NULL;

	snprintf (filter, len, FILTER, user);

	o->error = ldap_search_ext_s (o->ldap, c->userdn, LDAP_SCOPE_SUBTREE,
				      filter, NULL, 0,
				      NULL, NULL, NULL, LDAP_NO_LIMIT, &m);
	free (filter);

	if (o->error != 0)
		return NULL;

#undef FILTER
#undef AD_FILTER
#undef POSIX_FILTER

	return m;
}

LDAPMessage *ldap_auth_login (struct ldap_auth *o,
			      const char *user, const char *password)
{
	LDAPMessage *m, *e;
	char *dn;
	struct berval cred;

	if ((m = ldap_get_user (o, user)) == NULL)
		return NULL;

	if (ldap_count_entries (o->ldap, m) != 1) {
		o->error = LDAP_NO_SUCH_OBJECT;
		goto no_user;
	}

	e = ldap_first_entry (o->ldap, m);

	if ((dn = ldap_get_dn (o->ldap, e)) == NULL) {
		o->error = LDAP_LOCAL_ERROR;
		goto no_dn;
	}

	cred.bv_val = password == NULL ? "" : (void *) password;
	cred.bv_len = strlen (cred.bv_val);

	o->error = ldap_sasl_bind_s (o->ldap, dn, LDAP_SASL_SIMPLE, &cred,
				     NULL, NULL, NULL);
	ldap_memfree (dn);

	if (o->error != 0) {
		goto no_auth;
		o->error = LDAP_INVALID_CREDENTIALS;
	}

	return m;
no_auth:
no_dn:
no_user:
	ldap_msgfree (m);
	return NULL;
}
