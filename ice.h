/*
 * Header file for the ICE encryption library.
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

#ifndef _ICE_H
#define _ICE_H

typedef struct ice_key_struct	ICE_KEY;

#if __STDC__
#define P_(x) x
#else
#define P_(x) ()
#endif

extern ICE_KEY	*ice_key_create P_((int n));
extern void	ice_key_destroy P_((ICE_KEY *ik));
extern void	ice_key_set P_((ICE_KEY *ik, const unsigned char *k));
extern void	ice_key_encrypt P_((const ICE_KEY *ik,
			const unsigned char *ptxt, unsigned char *ctxt));
extern void	ice_key_decrypt P_((const ICE_KEY *ik,
			const unsigned char *ctxt, unsigned char *ptxt));

#undef P_

#endif
