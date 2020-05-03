/*
 * LDAP Authentication Helper Library
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LDAP_AUTH
#define LDAP_AUTH  1

#include <stdarg.h>

struct ldap_auth *ldap_auth_alloc_va (const char *uri, va_list ap);
struct ldap_auth *ldap_auth_alloc    (const char *uri, ...);
void ldap_auth_free (struct ldap_auth *o);

const char *ldap_auth_error (const struct ldap_auth *o);

int ldap_auth_login (struct ldap_auth *o,
		     const char *user, const char *password);

#endif  /* LDAP_AUTH */
