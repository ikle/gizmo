/*
 * LDAP Access Helper Library Sample
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gizmo.h>
#include <gizmo-misc.h>

static char *get_sep (char *uri)
{
	char *p;

	if ((p = strchr (uri, ':')) == NULL || p[1] != '/' || p[2] != '/')
		return NULL;

	return strchr (p + 3, '/');
}

int main (int argc, char *argv[])
{
	struct gizmo *o;
	char *uri = argv[1], *slash;
	const char *tls;

	if (argc != 2 || (slash = get_sep (uri)) == NULL) {
		fprintf (stderr, "usage:\n\tgizmo-req <req-uri>\n");
		return 1;
	}

	tls = (strncmp (uri, "ldap:", 5) == 0) ? "off" : "demand";

	*slash = '\0';

	if ((o = gizmo_open (uri, "tls", tls, NULL)) == NULL) {
		perror ("E: Cannot open LDAP connection");
		return 1;
	}

	*slash = '/';

	if (!gizmo_request (o, uri)) {
		fprintf (stderr, "E: %s\n", gizmo_error (o));
		goto no_req;
	}

	gizmo_dump_entries (o, stdout);

	gizmo_close (o);
	return 0;
no_req:
	gizmo_close (o);
	return 1;
}
