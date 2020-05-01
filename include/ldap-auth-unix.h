/*
 * LDAP Authentication Helper Library
 *
 * Copyright (c) 2020 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LDAP_AUTH_UNIX
#define LDAP_AUTH_UNIX  1

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

#include <ldap-auth.h>

int ldap_auth_getent (struct ldap_auth *o, const char *user, struct passwd *p);

#endif  /* LDAP_AUTH_UNIX */
