/*
 * Header file for the SNOW steganography program.
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

#ifndef _SNOW_H
#define _SNOW_H

#include <stdio.h>


/*
 * Define boolean types.
 */

typedef int	BOOL;

#ifndef FALSE
#define FALSE	0
#endif

#ifndef TRUE
#define TRUE	1
#endif


/*
 * Define global variables.
 */

extern BOOL	compress_flag;
extern BOOL	quiet_flag;
extern int	line_length;


/*
 * Define external functions.
 */

extern void	password_set (const char *passwd);
extern BOOL	message_extract (FILE *inf, FILE *outf);
extern void	space_calculate (FILE *inf);

extern void	compress_init (void);
extern BOOL	compress_bit (int bit, FILE *inf, FILE *outf);
extern BOOL	compress_flush (FILE *inf, FILE *outf);

extern void	uncompress_init (void);
extern BOOL	uncompress_bit (int bit, FILE *outf);
extern BOOL	uncompress_flush (FILE *outf);

extern void	encrypt_init (void);
extern BOOL	encrypt_bit (int bit, FILE *inf, FILE *outf);
extern BOOL	encrypt_flush (FILE *inf, FILE *outf);

extern void	decrypt_init (void);
extern BOOL	decrypt_bit (int bit, FILE *outf);
extern BOOL	decrypt_flush (FILE *outf);

extern void	encode_init (void);
extern BOOL	encode_bit (int bit, FILE *inf, FILE *outf);
extern BOOL	encode_flush (FILE *inf, FILE *outf);

#endif
