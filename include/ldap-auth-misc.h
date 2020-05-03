/*
 * LDAP Auth, Miscellaneous Helpers
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LDAP_AUTH_MISC
#define LDAP_AUTH_MISC  1

#include <stdio.h>

#include <ldap-auth.h>

void ldap_auth_dump_entries (const struct ldap_auth *o, FILE *to);

#endif  /* LDAP_AUTH_MISC */
