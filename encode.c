/*
 * Whitespace encoding routines for the SNOW steganography program.
 *
 * Copyright (C) 1999 Matthew Kwan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * For license text, see https://spdx.org/licenses/Apache-2.0>.
 */

#include <string.h>

#include "snow.h"


/*
 * Local variables used for encoding.
 */

static int		encode_bit_count;
static int		encode_value;
static char		encode_buffer[BUFSIZ];
static BOOL		encode_buffer_loaded;
static int		encode_buffer_length;
static int		encode_buffer_column;
static BOOL		encode_first_tab;
static BOOL		encode_needs_tab;
static unsigned long	encode_bits_used;
static unsigned long	encode_bits_available;
static unsigned long	encode_lines_extra;


/*
 * Return the next tab position.
 */

static int
tabpos (
	int	n
) {
	return ((n + 8) & ~7);
}


/*
 * Read a line of text, like fgets, but strip off trailing whitespace.
 */

static char *
wsgets (
	char		*buf,
	int		size,
	FILE		*fp
) {
	int		n;

	if (fgets (buf, BUFSIZ, fp) == NULL)
	    return (NULL);

	n = strlen (buf) - 1;
	while (n >= 0 && (buf[n] == ' ' || buf[n] == '\t' || buf[n] == '\n'
							|| buf[n] == '\r')) {
	    buf[n] = '\0';
	    n--;
	}

	return (buf);
}


/*
 * Write a line of text, adding a newline.
 * Return FALSE if the write fails.
 */

static BOOL
wsputs (
	char		*buf,
	FILE		*fp
) {
	int		len = strlen (buf);

	buf[len++] = '\n';
	if (fwrite (buf, sizeof (char), len, fp) != len) {
	    perror ("Text output");
	    return (FALSE);
	}

	return (TRUE);
}


/*
 * Calculate, approximately, how many bits can be stored in the line.
 */

static void
whitespace_storage (
	const char	*buf,
	unsigned long	*n_lo,
	unsigned long	*n_hi
) {
	int		n, len = strlen (buf);

	if (len > line_length - 2)
	    return;

	if (len / 8 == line_length / 8) {
	    *n_hi += 3;
	    return;
	}

	if ((len & 7) > 0) {
	    *n_hi += 3;
	    len = tabpos (len);
	}
	if ((line_length & 7) > 0)
	    *n_hi += 3;

	n = ((line_length - len) / 8) * 3;
	*n_hi += n;
	*n_lo += n;
}


/*
 * Load the encode buffer.
 * If there is no text to read, make it empty.
 */

static void
encode_buffer_load (
	FILE		*fp
) {
	int		i;

	if (wsgets (encode_buffer, BUFSIZ, fp) == NULL) {
	    encode_buffer[0] = '\0';
	    encode_lines_extra++;
	}

	encode_buffer_length = strlen (encode_buffer);

	encode_buffer_column = 0;
	for (i=0; encode_buffer[i] != '\0'; i++)
	    if (encode_buffer[i] == '\t')
		encode_buffer_column = tabpos (encode_buffer_column);
	    else
		encode_buffer_column++;

	encode_buffer_loaded = TRUE;
	encode_needs_tab = FALSE;
}


/*
 * Append whitespace to the loaded buffer, if there is room.
 */

static BOOL
encode_append_whitespace (
	int		nsp
) {
	int		col = encode_buffer_column;

	if (encode_needs_tab)
	    col = tabpos (col);

	if (nsp == 0)
	    col = tabpos (col);
	else
	    col += nsp;

	if (col >= line_length)
	    return (FALSE);

	if (encode_needs_tab) {
	    encode_buffer[encode_buffer_length++] = '\t';
	    encode_buffer_column = tabpos (encode_buffer_column);
	}

	if (nsp == 0) {
	    encode_buffer[encode_buffer_length++] = '\t';
	    encode_buffer_column = tabpos (encode_buffer_column);
	    encode_needs_tab = FALSE;
	} else {
	    int		i;

	    for (i=0; i<nsp; i++) {
		encode_buffer[encode_buffer_length++] = ' ';
		encode_buffer_column++;
	    }

	    encode_needs_tab = TRUE;
	}

	encode_buffer[encode_buffer_length] = '\0';

	return (TRUE);
}


/*
 * Write a value into the text.
 */

static BOOL
encode_write_value (
	int		val,
	FILE		*inf,
	FILE		*outf
) {
	int		nspc;

	if (!encode_buffer_loaded)
	    encode_buffer_load (inf);

	if (!encode_first_tab) {	/* Tab shows start of data */
	    while (tabpos (encode_buffer_column) >= line_length) {
		if (!wsputs (encode_buffer, outf))
		    return (FALSE);
		encode_buffer_load (inf);
	    }

	    encode_buffer[encode_buffer_length++] = '\t';
	    encode_buffer[encode_buffer_length] = '\0';
	    encode_buffer_column = tabpos (encode_buffer_column);
	    encode_first_tab = TRUE;
	}

			/* Reverse the bit ordering */
	nspc = ((val & 1) << 2) | (val & 2) | ((val & 4) >> 2);

	while (!encode_append_whitespace (nspc)) {
	    if (!wsputs (encode_buffer, outf))
		return (FALSE);
	    encode_buffer_load (inf);
	}

	if (encode_lines_extra == 0)
	    encode_bits_available += 3;

	return (TRUE);
}


/*
 * Flush the rest of the text to the output.
 */

static BOOL
encode_write_flush (
	FILE		*inf,
	FILE		*outf
) {
	char		buf[BUFSIZ];
	unsigned long	n_lo = 0, n_hi = 0;

	if (encode_buffer_loaded) {
	    if (!wsputs (encode_buffer, outf))
		return (FALSE);
	    encode_buffer_loaded = FALSE;
	    encode_buffer_length = 0;
	    encode_buffer_column = 0;
	}

	while (wsgets (buf, BUFSIZ, inf) != NULL) {
	    whitespace_storage (buf, &n_lo, &n_hi);
	    if (!wsputs (buf, outf))
		return (FALSE);
	}

	encode_bits_available += (n_lo + n_hi) / 2;

	return (TRUE);
}


/*
 * Initialize the encoding routines.
 */

void
encode_init (void)
{
	encode_bit_count = 0;
	encode_value = 0;
	encode_buffer_loaded = FALSE;
	encode_buffer_length = 0;
	encode_buffer_column = 0;
	encode_first_tab = FALSE;
	encode_bits_used = 0;
	encode_bits_available = 0;
	encode_lines_extra = 0;
}


/*
 * Encode a single bit.
 */

BOOL
encode_bit (
	int		bit,
	FILE		*inf,
	FILE		*outf
) {
	encode_value = (encode_value << 1) | bit;
	encode_bits_used++;

	if (++encode_bit_count == 3) {
	    if (!encode_write_value (encode_value, inf, outf))
		return (FALSE);

	    encode_value = 0;
	    encode_bit_count = 0;
	}

	return (TRUE);
}


/*
 * Flush the contents of the encoding routines.
 */

BOOL
encode_flush (
	FILE		*inf,
	FILE		*outf
) {
	if (encode_bit_count > 0) {
	    while (encode_bit_count < 3) {	/* Pad to 3 bits */
		encode_value <<= 1;
		encode_bit_count++;
	    }

	    if (!encode_write_value (encode_value, inf, outf))
		return (FALSE);
	}

	if (!encode_write_flush (inf, outf))
	    return (FALSE);

	if (!quiet_flag) {
	    if (encode_lines_extra > 0) {
		fprintf (stderr,
	"Message exceeded available space by approximately %.2f%%.\n",
	((double) encode_bits_used / encode_bits_available - 1.0) * 100.0);

		fprintf (stderr, "An extra %ld lines were added.\n",
							encode_lines_extra);
	    } else {
		fprintf (stderr,
		"Message used approximately %.2f%% of available space.\n",
		(double) encode_bits_used / encode_bits_available * 100.0);
	    }
	}

	return (TRUE);
}


/*
 * Decode the space count into actual bits.
 */

static BOOL
decode_bits (
	int		spc,
	FILE		*outf
) {
	int		b1 = 0, b2 = 0, b3 = 0;

	if (spc > 7) {
	    fprintf (stderr, "Illegal encoding of %d spaces\n", spc);
	    return (FALSE);
	}

	if ((spc & 1) != 0)
	    b1 = 1;
	if ((spc & 2) != 0)
	    b2 = 1;
	if ((spc & 4) != 0)
	    b3 = 1;

	if (!decrypt_bit (b1, outf))
	    return (FALSE);
	if (!decrypt_bit (b2, outf))
	    return (FALSE);
	if (!decrypt_bit (b3, outf))
	    return (FALSE);

	return (TRUE);
}


/*
 * Decode the whitespace contained in the string.
 */

static BOOL
decode_whitespace (
	const char	*s,
	FILE		*outf
) {
	int		spc = 0;

	for (;; s++) {
	    if (*s == ' ') {
		spc++;
	    } else if (*s == '\t') {
		if (!decode_bits (spc, outf))
		    return (FALSE);
		spc = 0;
	    } else if (*s == '\0') {
		if (spc > 0 && !decode_bits (spc, outf))
		    return (FALSE);
		return (TRUE);
	    }
	}
}


/*
 * Extract a message from the input stream.
 */

BOOL
message_extract (
	FILE		*inf,
	FILE		*outf
) {
	char		buf[BUFSIZ];
	BOOL		start_tab_found = FALSE;

	decrypt_init ();

	while (fgets (buf, BUFSIZ, inf) != NULL) {
	    char	*s, *last_ws = NULL;

	    for (s = buf; *s != '\0' && *s != '\n' && *s != '\r'; s++) {
		if (*s != ' ' && *s != '\t')
		    last_ws = NULL;
		else if (last_ws == NULL)
		    last_ws = s;
	    }

	    if (*s == '\n' || *s == '\r')
		*s = '\0';

	    if (last_ws == NULL)
		continue;

	    if (!start_tab_found && *last_ws == ' ')
		continue;

	    if (!start_tab_found && *last_ws == '\t') {
		start_tab_found = TRUE;
		last_ws++;
		if (*last_ws == '\0')
		    continue;
	    }

	    if (!decode_whitespace (last_ws, outf))
		return (FALSE);
	}

	return (decrypt_flush (outf));
}


/*
 * Calculate the amount of covert information that can be stored
 * in the file.
 */

void
space_calculate (
	FILE		*fp
) {
	unsigned long	n_lo = 0, n_hi = 0;
	char		buf[BUFSIZ];

	while (wsgets (buf, BUFSIZ, fp) != NULL)
	    whitespace_storage (buf, &n_lo, &n_hi);

	if (n_lo > 0) {		/* Allow for initial tab */
	    n_lo--;
	    n_hi--;
	}

	if (n_lo == n_hi) {
	    printf ("File has storage capacity of %ld bits (%ld bytes)\n",
							n_lo, n_lo / 8);
	} else {
	    printf ("File has storage capacity of between %ld and %ld bits.\n",
								n_lo, n_hi);
	    printf ("Approximately %ld bytes.\n", (n_lo + n_hi) / 16);
	}
}
