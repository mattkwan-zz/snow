/*
 * Encryption routines for the SNOW steganography program.
 * Uses the ICE encryption algorithm in 1-bit cipher-feedback (CFB) mode.
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
#include "ice.h"


/*
 * The key to use for encryption/decryption.
 */

static ICE_KEY		*ice_key = NULL;
static unsigned char	encrypt_iv_block[8];


/*
 * Build the ICE key from the supplied password.
 * Only uses the lower 7 bits from each character.
 */

void
password_set (
	const char	*passwd
) {
	int		i, level;
	unsigned char	buf[1024];

	level = (strlen (passwd) * 7 + 63) / 64;

	if (level == 0) {
	    if (!quiet_flag)
		fprintf (stderr, "Warning: an empty password is being used\n");
	    level = 1;
	} else if (level > 128) {
	    if (!quiet_flag)
		fprintf (stderr, "Warning: password truncated to 1170 chars\n");
	    level = 128;
	}

	if ((ice_key = ice_key_create (level)) == NULL) {
	    if (!quiet_flag)
		fprintf (stderr, "Warning: failed to set password\n");
	    return;
	}

	for (i=0; i<1024; i++)
	    buf[i] = 0;

	i = 0;
	while (*passwd != '\0') {
	    unsigned char	c = *passwd & 0x7f;
	    int			idx = i / 8;
	    int			bit = i & 7;

	    if (bit == 0) {
		buf[idx] = (c << 1);
	    } else if (bit == 1) {
		buf[idx] |= c;
	    } else {
		buf[idx] |= (c >> (bit - 1));
		buf[idx + 1] = (c << (9 - bit));
	    }

	    i += 7;
	    passwd++;

	    if (i > 8184)
		break;
	}

	ice_key_set (ice_key, buf);

		/* Set the initialization vector with the key
		 * with itself.
		 */
	ice_key_encrypt (ice_key, buf, encrypt_iv_block);
}


/*
 * Initialize the encryption routines.
 */

void
encrypt_init (void)
{
	encode_init ();
}


/*
 * Encrypt a single bit.
 */

BOOL
encrypt_bit (
	int		bit,
	FILE		*inf,
	FILE		*outf
) {
	int		i;
	unsigned char	buf[8];

	if (ice_key == NULL)
	    return (encode_bit (bit, inf, outf));

	ice_key_encrypt (ice_key, encrypt_iv_block, buf);
	if ((buf[0] & 128) != 0)
	    bit = !bit;

			/* Rotate the IV block one bit left */
	for (i=0; i<8; i++) {
	    encrypt_iv_block[i] <<= 1;
	    if (i < 7 && (encrypt_iv_block[i+1] & 128) != 0)
		encrypt_iv_block[i] |= 1;
	}
	encrypt_iv_block[7] |= bit;

	return (encode_bit (bit, inf, outf));
}


/*
 * Flush the contents of the encryption routines.
 */

BOOL
encrypt_flush (
	FILE		*inf,
	FILE		*outf
) {
	ice_key_destroy (ice_key);

	return (encode_flush (inf, outf));
}


/*
 * Initialize the decryption routines.
 */

void
decrypt_init (void)
{
	uncompress_init ();
}


/*
 * Decrypt a single bit.
 */

BOOL
decrypt_bit (
	int		bit,
	FILE		*outf
) {
	int		i;
	int		nbit;
	unsigned char	buf[8];

	if (ice_key == NULL)
	    return (uncompress_bit (bit, outf));

	ice_key_encrypt (ice_key, encrypt_iv_block, buf);
	if ((buf[0] & 128) != 0)
	    nbit = !bit;
	else
	    nbit = bit;

			/* Rotate the IV block one bit left */
	for (i=0; i<8; i++) {
	    encrypt_iv_block[i] <<= 1;
	    if (i < 7 && (encrypt_iv_block[i+1] & 128) != 0)
		encrypt_iv_block[i] |= 1;
	}
	encrypt_iv_block[7] |= bit;

	return (uncompress_bit (nbit, outf));
}


/*
 * Flush the contents of the decryption routines.
 */

BOOL
decrypt_flush (
	FILE		*outf
) {
	ice_key_destroy (ice_key);

	return (uncompress_flush (outf));
}
