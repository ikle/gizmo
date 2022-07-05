/*
 * Base64 Filter
 *
 * Copyright (c) 2011 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef BASE64_FILTER_H
#define BASE64_FILTER_H  1

#include <stdio.h>

struct b64_filter {
	long saved;
	int count, column;
	FILE *file;
	const char *sep;
};

void b64_init (struct b64_filter *f, FILE *file, const char *prefix);
/* putc/fini returns EOF on error */
int b64_putc (struct b64_filter *f, int c);
int b64_fini (struct b64_filter *f);

#endif  /* BASE64_FILTER_H */
