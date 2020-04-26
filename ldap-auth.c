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

static int set_tls (LDAP *o, const char *tls)
{
	int opt;

	if (tls == NULL)
		return 1;

	if      (strcmp (tls, "never")  == 0) opt = LDAP_OPT_X_TLS_NEVER;
	else if (strcmp (tls, "allow")  == 0) opt = LDAP_OPT_X_TLS_ALLOW;
	else if (strcmp (tls, "try")    == 0) opt = LDAP_OPT_X_TLS_TRY;
	else if (strcmp (tls, "demand") == 0) opt = LDAP_OPT_X_TLS_DEMAND;
	else
		return 0;

	return ldap_set_option (o, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt) == 0;
}

static int set_options (LDAP *o, const struct ldap_auth_conf *c)
{
	if (!set_tls (o, c->tls))
		return 0;

	if (c->cadir != NULL &&
	    ldap_set_option (o, LDAP_OPT_X_TLS_CACERTDIR, &c->cadir) != 0)
		return 0;

	if (c->ca != NULL &&
	    ldap_set_option (o, LDAP_OPT_X_TLS_CACERTFILE, &c->ca) != 0)
		return 0;

	if (c->cert != NULL &&
	    ldap_set_option (o, LDAP_OPT_X_TLS_CERTFILE, &c->cert) != 0)
		return 0;

	if (c->key != NULL &&
	    ldap_set_option (o, LDAP_OPT_X_TLS_KEYFILE, &c->key) != 0)
		return 0;

	return 1;
}

static int do_tls (LDAP *o, const struct ldap_auth_conf *c)
{
	void *ctx;

	if (ldap_get_option (o, LDAP_OPT_X_TLS_SSL_CTX, &ctx) == 0 &&
	    ctx == NULL)
		return 1;  /* TLS started already */

	return	c->tls == NULL ||
		ldap_start_tls_s (o, NULL, NULL) == 0;
}

LDAP *ldap_auth_open (const struct ldap_auth_conf *c)
{
	LDAP *o;
	const int version = LDAP_VERSION3;
	int rc;
	struct berval cred;

	if (c->uri == NULL || ldap_initialize (&o, c->uri) != 0)
		return NULL;

	if (ldap_set_option (o, LDAP_OPT_PROTOCOL_VERSION, &version) != 0 ||
	    !set_options (o, c) ||
	    !do_tls (o, c))
		goto error;

	if (c->user != NULL) {
		cred.bv_val = c->password == NULL ? "" : (void *) c->password;
		cred.bv_len = strlen (cred.bv_val);

		rc = ldap_sasl_bind_s (o, c->user, LDAP_SASL_SIMPLE, &cred,
				       NULL, NULL, NULL);
		if (rc != 0)
			goto error;
	}

	return o;
error:
	ldap_destroy (o);
	return NULL;
}

void ldap_auth_close (LDAP *o)
{
	if (o == NULL)
		return;

	ldap_destroy (o);
}

static LDAPMessage *
ldap_get_user (LDAP *o, const struct ldap_auth_conf *c, const char *user)
{
	int len;
	char *filter;
	int rc;
	LDAPMessage *m;

#define POSIX_FILTER	"(&(uid=%1$s)(objectClass=posixAccount))"
#define AD_FILTER	"(&(sAMAccountName=%1$s)(ObjectClass=User))"
#define FILTER		"(|" POSIX_FILTER AD_FILTER ")"

	len = snprintf (NULL, 0, FILTER, user) + 1;

	if ((filter = malloc (len)) == NULL)
		return NULL;

	snprintf (filter, len, FILTER, user);

	rc = ldap_search_ext_s (o, c->userdn, LDAP_SCOPE_SUBTREE, filter,
				NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &m);
	free (filter);

	if (rc != 0)
		return NULL;

#undef FILTER
#undef AD_FILTER
#undef POSIX_FILTER

	return m;
}

LDAPMessage *
ldap_auth_login (LDAP *o, const struct ldap_auth_conf *c,
		 const char *user, const char *password)
{
	LDAPMessage *m, *e;
	char *dn;
	struct berval cred;
	int rc;

	if ((m = ldap_get_user (o, c, user)) == NULL)
		return NULL;

	if (ldap_count_entries (o, m) > 1)
		goto no_unique;

	e = ldap_first_entry (o, m);

	if ((dn = ldap_get_dn (o, e)) == NULL)
		goto no_dn;

	cred.bv_val = password == NULL ? "" : (void *) password;
	cred.bv_len = strlen (cred.bv_val);

	rc = ldap_sasl_bind_s (o, dn, LDAP_SASL_SIMPLE, &cred,
			       NULL, NULL, NULL);
	ldap_memfree (dn);

	if (rc != 0)
		goto no_auth;

	return m;
no_auth:
no_dn:
no_unique:
	ldap_msgfree (m);
	return NULL;
}
