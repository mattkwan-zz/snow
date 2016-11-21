/*
 * Compression routines for the SNOW steganography program.
 * Uses simple Huffman coding.
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

#include "snow.h"

#include <string.h>


/*
 * The Huffman codes.
 */

static const char	*huffcodes[256] = {
#include "huffcode.h"
};


/*
 * Local variables used for compression.
 */

static int		compress_bit_count;
static int		compress_value;
static unsigned long	compress_bits_in;
static unsigned long	compress_bits_out;


/*
 * Initialize the compression routines.
 */

void
compress_init (void)
{
	compress_bit_count = 0;
	compress_value = 0;
	compress_bits_in = 0;
	compress_bits_out = 0;

	encrypt_init ();
}


/*
 * Compress a single bit.
 */

BOOL
compress_bit (
	int		bit,
	FILE		*inf,
	FILE		*outf
) {
	if (!compress_flag)
	    return (encrypt_bit (bit, inf, outf));

	compress_bits_in++;
	compress_value = (compress_value << 1) | bit;

	if (++compress_bit_count == 8) {
	    const char	*s;

	    for (s = huffcodes[compress_value]; *s != '\0'; s++) {
		int	bit;

		if (*s == '1')
		    bit = 1;
		else if (*s == '0')
		    bit = 0;
		else {
		    fprintf (stderr, "Illegal Huffman character '%c'\n", *s);
		    return (FALSE);
		}

		if (!encrypt_bit (bit, inf, outf))
		    return (FALSE);
		compress_bits_out++;
	    }

	    compress_value = 0;
	    compress_bit_count = 0;
	}

	return (TRUE);
}


/*
 * Flush the contents of the compression routines.
 */

BOOL
compress_flush (
	FILE		*inf,
	FILE		*outf
) {
	if (compress_bit_count != 0 && !quiet_flag)
	    fprintf (stderr, "Warning: residual of %d bits not compressed\n",
							compress_bit_count);

	if (compress_bits_out > 0 && !quiet_flag) {
	    double	cpc = (double) (compress_bits_in - compress_bits_out)
					/ (double) compress_bits_in * 100.0;

	    if (cpc < 0.0)
		fprintf (stderr,
"Compression enlarged data by %.2f%% - recommend not using compression\n",
								-cpc);
	    else
		fprintf (stderr, "Compressed by %.2f%%\n", cpc);
	}

	return (encrypt_flush (inf, outf));
}


/*
 * Local variables used for output.
 */

static int	output_bit_count;
static int	output_value;


/*
 * Initialize the output variables.
 */

static void
output_init (void)
{
	output_bit_count = 0;
	output_value = 0;
}


/*
 * Output a single bit.
 */

static BOOL
output_bit (
	int		bit,
	FILE		*outf
) {
	output_value = (output_value << 1) | bit;

	if (++output_bit_count == 8) {
	    if (fputc (output_value, outf) == EOF) {
		perror ("Output file");
		return (FALSE);
	    }

	    output_value = 0;
	    output_bit_count = 0;
	}

	return (TRUE);
}


/*
 * Flush the contents of the output routines.
 */

static BOOL
output_flush (
	FILE		*outf
) {
	if (output_bit_count > 2 && !quiet_flag)
	    fprintf (stderr, "Warning: residual of %d bits not output\n",
							output_bit_count);

	return (TRUE);
}


/*
 * Local variables used for uncompression.
 */

static int	uncompress_bit_count;
static char	uncompress_value[256];


/*
 * Initialize the uncompression routines.
 */

void
uncompress_init (void)
{
	uncompress_bit_count = 0;

	output_init ();
}


/*
 * Find the Huffman code string that matches.
 */

static int
huffcode_find (
	const char	*str
) {
	int		i;

	for (i=0; i<256; i++)
	    if (strcmp (str, huffcodes[i]) == 0)
		return (i);

	return (-1);
}


/*
 * Uncompress a single bit.
 */

BOOL
uncompress_bit (
	int		bit,
	FILE		*outf
) {
	int		code;

	if (!compress_flag)
	    return (output_bit (bit, outf));

	uncompress_value[uncompress_bit_count++] = bit ? '1' : '0';
	uncompress_value[uncompress_bit_count] = '\0';

	if ((code = huffcode_find (uncompress_value)) >= 0) {
	    int		i;

	    for (i=0; i<8; i++) {
		int	b = ((code & (128 >> i)) != 0) ? 1 : 0;

		if (!output_bit (b, outf))
		    return (FALSE);
	    }

	    uncompress_bit_count = 0;
	}

	if (uncompress_bit_count >= 255) {
	    fprintf (stderr, "Error: Huffman uncompress buffer overflow\n");
	    return (FALSE);
	}

	return (TRUE);
}


/*
 * Flush the contents of the uncompression routines.
 */

BOOL
uncompress_flush (
	FILE		*outf
) {
	if (uncompress_bit_count > 2 && !quiet_flag)
	    fprintf (stderr, "Warning: residual of %d bits not uncompressed\n",
							uncompress_bit_count);

	return (output_flush (outf));
}
