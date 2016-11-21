# Rudimentary makefile for the SNOW steganography program.
#
# Copyright (C) 1999 Matthew Kwan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# For license text, see https://spdx.org/licenses/Apache-2.0>.

CC     ?= gcc
CFLAGS ?= -O

OBJ =		main.o encrypt.o ice.o compress.o encode.o

snow:		$(OBJ)
		$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ)

clean:
		rm -f $(OBJ) snow
# End of file
