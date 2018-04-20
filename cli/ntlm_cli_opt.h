/*
 * Copyright (c), Edward Thomson <ethomson@edwardthomson.com>
 * All rights reserved.
 *
 * This file is part of adopt, distributed under the MIT license.
 * For full terms and conditions, see the included LICENSE file.
 */

#ifndef NTLM_OPT_H
#define NTLM_OPT_H

#include <stdio.h>
#include <stdint.h>

/**
 * The type of argument to be parsed.
 */
typedef enum {
	NTLM_OPT_NONE = 0,

	/**
	 * An argument that, when specified, sets a given value to true.
	 * This is useful for arguments like "--debug".  The `value` pointer
	 * in the returned option will be set to `1` when this is set.
	 */
	NTLM_OPT_BOOL,

	/**
	 * An argument that, when specified, sets the given `value_ptr`
	 * to the given `value`.
	 */
	NTLM_OPT_SWITCH,

	/** An argument that has a value ("-nvalue" or "--name value") */
	NTLM_OPT_VALUE,

	/** An argument that has an optional value ("-n" or "-n foo") */
	NTLM_OPT_VALUE_OPTIONAL,

	/** The literal arguments follow specifier, bare "--" */
	NTLM_OPT_LITERAL,

	/** A single "free" argument ("path") */
	NTLM_OPT_ARG,

	/** Unmatched arguments, a collection of "free" arguments ("paths...") */
	NTLM_OPT_ARGS,
} ntlm_opt_type_t;

/**
 * Usage information for an argument, to be displayed to the end-user.
 * This is only for display, the parser ignores this usage information.
 */
typedef enum {
	/** This argument is required. */
	NTLM_OPT_USAGE_REQUIRED = (1u << 0),

	/** This argument should not be displayed in usage. */
	NTLM_OPT_USAGE_HIDDEN = (1u << 1),

	/** This is a multiple choice argument, combined with the previous arg. */
	NTLM_OPT_USAGE_CHOICE = (1u << 2),

	/** In usage, show the long format instead of the abbreviated format. */
	NTLM_OPT_USAGE_SHOW_LONG = (1u << 3),
} ntlm_opt_usage_t;

/** Specification for an available option. */
typedef struct ntlm_opt_spec {
	/** Type of option expected. */
	ntlm_opt_type_t type;

	/** Name of the long option. */
	const char *name;

	/** The alias is the short (one-character) option alias. */
	const char alias;

	/**
	 * If this spec is of type `NTLM_OPT_BOOL`, this is a pointer to
	 * an `int` that will be set to `1` if the option is specified.
	 *
	 * If this spec is of type `NTLM_OPT_SWITCH`, this is a pointer to
	 * an `int` that will be set to the opt's `value` (below) when
	 * this option is specified.
	 *
	 * If this spec is of type `NTLM_OPT_VALUE` or `NTLM_OPT_VALUE_OPTIONAL`,
	 * this is a pointer to a `char *`, that will be set to the value
	 * specified on the command line.
	 */
	void *value;

	/**
	 * If this spec is of type `NTLM_OPT_SWITCH`, this is the value to
	 * set in the option's `value_ptr` pointer when it is specified.
	 * This is ignored for other opt types.
	 */
	int switch_value;

	/**
	 * The name of the value, provided when creating usage information.
	 * This is required only for the functions that display usage
	 * information and only when a spec is of type `NTLM_OPT_VALUE`.
	 */
	const char *value_name;

	/**
	 * Short description of the option, used when creating usage
	 * information.  This is only used when creating usage information.
	 */
	const char *help;

	/**
	 * Optional `ntlm_opt_usage_t`, used when creating usage information.
	 */
	ntlm_opt_usage_t usage;
} ntlm_opt_spec;

/** Return value for `ntlm_opt_parser_next`. */
typedef enum {
	/** Parsing is complete; there are no more arguments. */
	NTLM_OPT_STATUS_DONE = 0,

	/**
	 * This argument was parsed correctly; the `opt` structure is
	 * populated and the value pointer has been set.
	 */
	NTLM_OPT_STATUS_OK = 1,

	/**
	 * The argument could not be parsed correctly, it does not match
	 * any of the specifications provided.
	 */
	NTLM_OPT_STATUS_UNKNOWN_OPTION = 2,

	/**
	 * The argument matched a spec of type `NTLM_OPT_VALUE`, but no value
	 * was provided.
	 */
	NTLM_OPT_STATUS_MISSING_VALUE = 3,
} ntlm_opt_status_t;

/** An option provided on the command-line. */
typedef struct ntlm_opt {
	/** The status of parsing the most recent argument. */
	ntlm_opt_status_t status;

	/**
	 * The specification that was provided on the command-line, or
	 * `NULL` if the argument did not match an `ntlm_opt_spec`.
	 */
	const ntlm_opt_spec *spec;

	/**
	 * The argument as it was specified on the command-line, including
	 * dashes, eg, `-f` or `--foo`.
	 */
	char *arg;

	/**
	 * If the spec is of type `NTLM_OPT_VALUE` or `NTLM_OPT_VALUE_OPTIONAL`,
	 * this is the value provided to the argument.
	 */
	char *value;
} ntlm_opt;

/* The internal parser state.  Callers should not modify this structure. */
typedef struct ntlm_opt_parser {
	const ntlm_opt_spec *specs;
	char **args;
	size_t args_len;

	size_t idx;
	size_t arg_idx;
	int in_literal : 1,
	in_short : 1;
} ntlm_opt_parser;

/**
 * Initializes a parser that parses the given arguments according to the
 * given specifications.
 *
 * @param parser The `ntlm_opt_parser` that will be initialized
 * @param specs A NULL-terminated array of `ntlm_opt_spec`s that can be parsed
 * @param argv The arguments that will be parsed
 * @param args_len The length of arguments to be parsed
 */
void ntlm_opt_parser_init(
	ntlm_opt_parser *parser,
	const ntlm_opt_spec specs[],
	char **argv,
	size_t args_len);

/**
 * Parses the next command-line argument and places the information about
 * the argument into the given `opt` data.
 *
 * @param opt The `ntlm_opt` information parsed from the argument
 * @param parser An `ntlm_opt_parser` that has been initialized with
 *        `ntlm_opt_parser_init`
 * @return true if the caller should continue iterating, or 0 if there are
 *         no arguments left to process.
 */
ntlm_opt_status_t ntlm_opt_parser_next(
	ntlm_opt *opt,
	ntlm_opt_parser *parser);

/**
 * Prints the status after parsing the most recent argument.  This is
 * useful for printing an error message when an unknown argument was
 * specified, or when an argument was specified without a value.
 *
 * @param file The file to print information to
 * @param opt The option that failed to parse
 * @return 0 on success, -1 on failure
 */
int ntlm_opt_status_fprint(
	FILE *file,
	const ntlm_opt *opt);

/**
 * Prints usage information to the given file handle.
 *
 * @param file The file to print information to
 * @param command The name of the command to use when printing
 * @param specs The specifications allowed by the command
 * @return 0 on success, -1 on failure
 */
int ntlm_opt_usage_fprint(
	FILE *file,
	const char *command,
	const ntlm_opt_spec specs[]);

#endif /* NTLM_OPT_H */
