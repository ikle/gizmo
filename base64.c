/*
 * Base64 Filter
 *
 * Copyright (c) 2011-2022 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "base64.h"

static char *b64_table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

void b64_init (struct b64_filter *o, FILE *file, const char *sep)
{
	o->saved = 0;  /* need not to be initialized, make compiler happy */
	o->count = 0;
	o->column = 0;
	o->file = file;
	o->sep = (sep == NULL) ? "\r\n" : sep;
}

int b64_putc (struct b64_filter *o, int c)
{
	/* save data */
	o->saved <<= 8;
	o->saved |= (0xff & c);
	++o->count;

	if (o->count < 3)
		return 0;

	/* flush full quantum */
	fputc (b64_table[0x3f & (o->saved >> 18)], o->file);
	fputc (b64_table[0x3f & (o->saved >> 12)], o->file);
	fputc (b64_table[0x3f & (o->saved >>  6)], o->file);
	fputc (b64_table[0x3f & (o->saved      )], o->file);

	/* f->saved = 0; */
	o->count = 0;
	o->column += 4;

	if (o->column >= 76) {
		fputs (o->sep != NULL ? o->sep : "\r\n", o->file);
		o->column = 0;
	}

	return ferror (o->file) ? EOF : 0;
}

int b64_fini (struct b64_filter *o)
{
	switch (o->count) {
	case 1:
		o->saved <<= 16;  /* pad with zeros */

		fputc (b64_table[0x3f & (o->saved >> 18)], o->file);
		fputc (b64_table[0x3f & (o->saved >> 12)], o->file);
		fputc ('=', o->file);
		fputc ('=', o->file);
		break;
	case 2:
		o->saved <<= 8;  /* pad with zeros */

		fputc (b64_table[0x3f & (o->saved >> 18)], o->file);
		fputc (b64_table[0x3f & (o->saved >> 12)], o->file);
		fputc (b64_table[0x3f & (o->saved >>  6)], o->file);
		fputc ('=', o->file);
		break;
	default:
		return EOF;
	}

	if (o->sep == NULL)
		fputs ("\r\n", o->file);

	o->count = 0;
	return ferror (o->file) ? EOF : 0;
}
