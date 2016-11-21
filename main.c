/*
 * COPYRIGHT AND LICENSE
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
 *
 * DESCRIPTION
 *
 * Command-line program for hiding and extracting messages within
 * the whitespace of text files.
 *
 * Usage: snow [-C][-Q][-S][-p passwd][-l line-len] [-f file | -m message]
 *					[infile [outfile]]
 *
 *	-C : Use compression
 *	-Q : Be quiet
 *	-S : Calculate the space available in the file
 *	-l : Maximum line length allowable
 *	-p : Specify the password to encrypt the message
 *
 *	-f : Insert the message contained in the file
 *	-m : Insert the message given
 *
 * If the program is executed without either of the -f or -m options
 * then the program will attempt to extract a concealed message.
 * The output will go to outfile if specified, stdout otherwise.
 */

#include "snow.h"


/*
 * Declaration of global variables.
 */

BOOL	compress_flag = FALSE;
BOOL	quiet_flag = FALSE;
int	line_length = 80;


/*
 * Encode a single character.
 */

static BOOL
character_encode (
	unsigned char	c,
	FILE		*infile,
	FILE		*outfile
) {
	int		i;

	for (i=0; i<8; i++) {
	    int		bit = ((c & (128 >> i)) != 0) ? 1 : 0;

	    if (!compress_bit (bit, infile, outfile))
		return (FALSE);
	}

	return (TRUE);
}


/*
 * Encode a string of characters.
 */

static BOOL
message_string_encode (
	const char	*msg,
	FILE		*infile,
	FILE		*outfile
) {
	compress_init ();

	while (*msg != '\0') {
	    if (!character_encode (*msg, infile, outfile))
		return (FALSE);
	    msg++;
	}

	return (compress_flush (infile, outfile));
}


/*
 * Encode the contents of a file.
 */

static BOOL
message_fp_encode (
	FILE		*msg_fp,
	FILE		*infile,
	FILE		*outfile
) {
	int		c;

	compress_init ();

	while ((c = fgetc (msg_fp)) != EOF)
	    if (!character_encode (c, infile, outfile))
		return (FALSE);

	if (ferror (msg_fp) != 0) {
	    perror ("Message file");
	    return (FALSE);
	}

	return (compress_flush (infile, outfile));
}


/*
 * Display usage.
 */

static void
showUsage (
	const char	*argv0
) {
	printf ("Usage: %s [-C] [-Q] [-S] [-V | --version] [-h | --help]\n",
								argv0);
	printf ("\t[-p passwd] [-l line-len] [-f file | -m message]\n");
	printf ("\t[infile [outfile]]\n");
}


/*
 * Display version info.
 */

static void
showVersion () {
	printf (
"20130616 Apache-2.0 Copyright (C) Matthew Kwan <mkwan@darkside.com.au>\n");
}


/*
 * Program's starting point.
 * Processes command-line args and starts things running.
 */

int
main (
	int		argc,
	char		*argv[]
) {
	int		c;
	int		optind;
	BOOL		errflag = FALSE;
	BOOL		space_flag = FALSE;
	char		*passwd = NULL;
	char		*message_string = NULL;
	FILE		*message_fp = NULL;
	FILE		*infile = stdin;
	FILE		*outfile = stdout;

	optind = 1;
	for (optind = 1; optind < argc
#ifdef unix
			&& argv[optind][0] == '-';
#else
			&& (argv[optind][0] == '-' || argv[optind][0] == '/');
#endif
						optind++) {
	    char	c = argv[optind][1];
	    char	*optarg;

	    if (strcmp (argv[optind], "--help") == 0) {
		showUsage (argv[0]);
		return 0;
	    } else if (strcmp (argv[optind], "--version") == 0) {
		showVersion ();
		return 0;
	    }

	    switch (c) {
		case 'C':
		    compress_flag = TRUE;
		    break;
		case 'Q':
		    quiet_flag = TRUE;
		    break;
		case 'S':
		    space_flag = TRUE;
		    break;
		case 'V':
		    showVersion ();
		    return 0;
		case 'f':
		    if (argv[optind][2] != '\0')
			optarg = &argv[optind][2];
		    else if (++optind == argc) {
			errflag = TRUE;
			break;
		    } else
			optarg = argv[optind];

		    if ((message_fp = fopen (optarg, "r")) == NULL) {
			perror (optarg);
			errflag = TRUE;
		    }
		    break;
		case 'h':
		    showUsage (argv[0]);
		    return 0;
		case 'l':
		    if (argv[optind][2] != '\0')
			optarg = &argv[optind][2];
		    else if (++optind == argc) {
			errflag = TRUE;
			break;
		    } else
			optarg = argv[optind];

		    if (sscanf (optarg, "%d", &line_length) != 1
							|| line_length < 8) {
			fprintf (stderr, "Illegal line length value '%s'\n",
								optarg);
			errflag = TRUE;
		    }
		    break;
		case 'm':
		    if (argv[optind][2] != '\0')
			optarg = &argv[optind][2];
		    else if (++optind == argc) {
			errflag = TRUE;
			break;
		    } else
			optarg = argv[optind];

		    message_string = optarg;
		    break;
		case 'p':
		    if (argv[optind][2] != '\0')
			optarg = &argv[optind][2];
		    else if (++optind == argc) {
			errflag = TRUE;
			break;
		    } else
			optarg = argv[optind];

		    passwd = optarg;
		    break;
		default:
		    fprintf (stderr, "Illegal option '%s'\n", argv[optind]);
		    errflag = TRUE;
		    break;
	    }

	    if (errflag)
		break;
	}

	if (message_string != NULL && message_fp != NULL) {
	    fprintf (stderr, "Cannot specify both message string and file\n");
	    errflag = TRUE;
	}

	if (errflag || optind < argc - 2) {
	    showUsage (argv[0]);
	    return 1;
	}

	if (passwd != NULL)
	    password_set (passwd);

	if (optind < argc) {
	    if ((infile = fopen (argv[optind], "r")) == NULL) {
		perror (argv[optind]);
		return 1;
	    }
	}

	if (optind + 1 < argc) {
	    if ((outfile = fopen (argv[optind + 1], "w")) == NULL) {
		perror (argv[optind + 1]);
		return 1;
	    }
	}

	if (space_flag) {
	    space_calculate (infile);
	} else if (message_string != NULL) {
	    if (!message_string_encode (message_string, infile, outfile))
		return 1;
	} else if (message_fp != NULL) {
	    if (!message_fp_encode (message_fp, infile, outfile))
		return 1;
	    fclose (message_fp);
	} else {
	    if (!message_extract (infile, outfile))
		return 1;
	}

	if (outfile != stdout)
	    fclose (outfile);
	if (infile != stdout)
	    fclose (infile);

	return 0;
}
