/*
 * LDAP Access Helper Library, URI helpers
 *
 * Copyright (c) 2020-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "gizmo-int.h"

int gizmo_request (struct gizmo *o, const char *req)
{
	LDAPURLDesc *desc;

	if ((o->error = ldap_url_parse (req, &desc)) != 0)
		return 0;

	if (desc->lud_filter != NULL)
		gizmo_fetch (o, desc->lud_dn, (const char **) desc->lud_attrs,
			     desc->lud_scope, "%s", desc->lud_filter);
	else
		gizmo_fetch (o, desc->lud_dn, (const char **) desc->lud_attrs,
			     desc->lud_scope, NULL);

	ldap_free_urldesc (desc);
	return o->error == 0;
}
