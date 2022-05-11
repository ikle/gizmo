/*
 * LDAP Access Helper Library, Internals
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef GIZMO_INT_H
#define GIZMO_INT_H  1

#include <gizmo.h>
#include <ldap.h>

enum gizmo_flags {
	LDAP_AUTH_LDAPS		= 1 << 0,
	LDAP_AUTH_STARTTLS	= 1 << 1,
};

struct gizmo {
	LDAP *ldap;
	int error;
	LDAPMessage *answer;

	int flags;
	char *dn;		/* logged in user DN */

	const char *user;	/* bind DN */
	const char *password;

	const char *userdn;
	const char *role;	/* CN of group or role DN needed for auth */
	const char *roledn;	/* group or role base DN */
};

LDAPMessage *
gizmo_fetch (struct gizmo *o, const char *basedn, const char *attrs[],
	     const char *fmt, ...);

int gizmo_set_options_va (struct gizmo *o, va_list ap);

int gizmo_get_user (struct gizmo *o, const char *user, const char *attrs[]);


#endif  /* GIZMO_INT_H */
