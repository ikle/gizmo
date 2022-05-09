/*
 * LDAP Access Helper Library, UNIX helpers
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef GIZMO_UNIX_H
#define GIZMO_UNIX_H  1

#if defined (__unix__) || defined (__unix) || defined (unix)

#include <pwd.h>

#else  /* not unix */

struct passwd {
	char	*pw_name;
	char	*pw_passwd;
	int	 pw_uid;
	int	 pw_gid;
	char	*pw_gecos;
	char	*pw_dir;
	char	*pw_shell;
};

#endif  /* not unix */

#include <gizmo.h>

int gizmo_getent (struct gizmo *o, const char *user, struct passwd *p);

#endif  /* GIZMO_UNIX_H */
