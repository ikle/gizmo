/*
 * LDAP Access Helper Library
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef GIZMO_H
#define GIZMO_H  1

#include <stdarg.h>

struct gizmo *gizmo_open_va (const char *uri, va_list ap);
struct gizmo *gizmo_open    (const char *uri, ...);
void gizmo_close (struct gizmo *o);

const char *gizmo_error (const struct gizmo *o);

int gizmo_bind  (struct gizmo *o, const char *user, const char *password);
int gizmo_login (struct gizmo *o, const char *user, const char *password);

enum gizmo_scope {
	GIZMO_BASE	= 0,
	GIZMO_ONE	= 1,
	GIZMO_SUB	= 2,
};

int gizmo_fetch (struct gizmo *o, const char *basedn, const char *attrs[],
		 int scope, const char *fmt, ...);

#endif  /* GIZMO_H */
