/*
 * Copyright (c), Edward Thomson <ethomson@edwardthomson.com>
 * All rights reserved.
 *
 * This file is part of adopt, distributed under the MIT license.
 * For full terms and conditions, see the included LICENSE file.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "ntlm_cli_opt.h"

#ifdef _WIN32
# include <Windows.h>
#else
# include <fcntl.h>
# include <sys/ioctl.h>
#endif

#ifdef _MSC_VER
# define INLINE(type) static __inline type
#else
# define INLINE(type) static inline type
#endif

#define spec_is_named_type(x) \
	((x)->type == NTLM_OPT_BOOL || \
	 (x)->type == NTLM_OPT_SWITCH || \
	 (x)->type == NTLM_OPT_VALUE || \
	 (x)->type == NTLM_OPT_VALUE_OPTIONAL)

INLINE(const ntlm_opt_spec *) spec_byname(
	ntlm_opt_parser *parser, const char *name, size_t namelen)
{
	const ntlm_opt_spec *spec;

	for (spec = parser->specs; spec->type; ++spec) {
		if (spec->type == NTLM_OPT_LITERAL && namelen == 0)
			return spec;

		if (spec_is_named_type(spec) &&
			spec->name &&
			strlen(spec->name) == namelen &&
			strncmp(name, spec->name, namelen) == 0)
			return spec;
	}

	return NULL;
}

INLINE(const ntlm_opt_spec *) spec_byalias(ntlm_opt_parser *parser, char alias)
{
	const ntlm_opt_spec *spec;

	for (spec = parser->specs; spec->type; ++spec) {
		if (spec_is_named_type(spec) && alias == spec->alias)
			return spec;
	}

	return NULL;
}

INLINE(const ntlm_opt_spec *) spec_nextarg(ntlm_opt_parser *parser)
{
	const ntlm_opt_spec *spec;
	size_t args = 0;

	for (spec = parser->specs; spec->type; ++spec) {
		if (spec->type == NTLM_OPT_ARG) {
			if (args == parser->arg_idx) {
				parser->arg_idx++;
				return spec;
			}

			args++;
		}

		if (spec->type == NTLM_OPT_ARGS && args == parser->arg_idx)
			return spec;
	}

	return NULL;
}

static ntlm_opt_status_t parse_long(ntlm_opt *opt, ntlm_opt_parser *parser)
{
	const ntlm_opt_spec *spec;
	char *arg = parser->args[parser->idx++], *name = arg + 2, *eql;
	size_t namelen;

	namelen = (eql = strrchr(arg, '=')) ? (size_t)(eql - name) : strlen(name);

	opt->arg = arg;

	if ((spec = spec_byname(parser, name, namelen)) == NULL) {
		opt->spec = NULL;
		opt->status = NTLM_OPT_STATUS_UNKNOWN_OPTION;
		goto done;
	}

	opt->spec = spec;

	/* Future options parsed as literal */
	if (spec->type == NTLM_OPT_LITERAL)
		parser->in_literal = 1;

	if (spec->type == NTLM_OPT_BOOL && spec->value)
		*((int *)spec->value) = 1;

	if (spec->type == NTLM_OPT_SWITCH && spec->value)
		*((int *)spec->value) = spec->switch_value;

	/* Parse values as "--foo=bar" or "--foo bar" */
	if (spec->type == NTLM_OPT_VALUE || spec->type == NTLM_OPT_VALUE_OPTIONAL) {
		if (eql && *(eql+1))
			opt->value = eql + 1;
		else if ((parser->idx + 1) <= parser->args_len)
			opt->value = parser->args[parser->idx++];

		if (spec->value)
			*((char **)spec->value) = opt->value;
	}

	/* Required argument was not provided */
	if (spec->type == NTLM_OPT_VALUE && !opt->value)
		opt->status = NTLM_OPT_STATUS_MISSING_VALUE;
	else
		opt->status = NTLM_OPT_STATUS_OK;

done:
	return opt->status;
}

static ntlm_opt_status_t parse_short(ntlm_opt *opt, ntlm_opt_parser *parser)
{
	const ntlm_opt_spec *spec;
	char *arg = parser->args[parser->idx++], alias = *(arg + 1);

	opt->arg = arg;

	if ((spec = spec_byalias(parser, alias)) == NULL) {
		opt->spec = NULL;
		opt->status = NTLM_OPT_STATUS_UNKNOWN_OPTION;
		goto done;
	}

	opt->spec = spec;

	if (spec->type == NTLM_OPT_BOOL && spec->value)
		*((int *)spec->value) = 1;

	if (spec->type == NTLM_OPT_SWITCH && spec->value)
		*((int *)spec->value) = spec->switch_value;

	/* Parse values as "-ifoo" or "-i foo" */
	if (spec->type == NTLM_OPT_VALUE || spec->type == NTLM_OPT_VALUE_OPTIONAL) {
		if (strlen(arg) > 2)
			opt->value = arg + 2;
		else if ((parser->idx + 1) <= parser->args_len)
			opt->value = parser->args[parser->idx++];

		if (spec->value)
			*((char **)spec->value) = opt->value;
	}

	/* Required argument was not provided */
	if (spec->type == NTLM_OPT_VALUE && !opt->value)
		opt->status = NTLM_OPT_STATUS_MISSING_VALUE;
	else
		opt->status = NTLM_OPT_STATUS_OK;

done:
	return opt->status;
}

static ntlm_opt_status_t parse_arg(ntlm_opt *opt, ntlm_opt_parser *parser)
{
	const ntlm_opt_spec *spec = spec_nextarg(parser);

	opt->spec = spec;
	opt->arg = parser->args[parser->idx++];

	if (spec && spec->value)
		*((char **)spec->value) = opt->arg;

	opt->status = spec ? NTLM_OPT_STATUS_OK : NTLM_OPT_STATUS_UNKNOWN_OPTION;
	return opt->status;
}

void ntlm_opt_parser_init(
	ntlm_opt_parser *parser,
	const ntlm_opt_spec specs[],
	char **args,
	size_t args_len)
{
	assert(parser);

	memset(parser, 0x0, sizeof(ntlm_opt_parser));

	parser->specs = specs;
	parser->args = args;
	parser->args_len = args_len;
}

ntlm_opt_status_t ntlm_opt_parser_next(ntlm_opt *opt, ntlm_opt_parser *parser)
{
	assert(opt && parser);

	memset(opt, 0x0, sizeof(ntlm_opt));

	if (parser->idx >= parser->args_len)
		return NTLM_OPT_STATUS_DONE;

	/* Handle arguments in long form, those beginning with "--" */
	if (strncmp(parser->args[parser->idx], "--", 2) == 0 &&
		!parser->in_literal)
		return parse_long(opt, parser);

	/* Handle arguments in short form, those beginning with "-" */
	else if (strncmp(parser->args[parser->idx], "-", 1) == 0 &&
		!parser->in_literal)
		return parse_short(opt, parser);

	/* Handle "free" arguments, those without a dash */
	else
		return parse_arg(opt, parser);
}

int ntlm_opt_status_fprint(
	FILE *file,
	const ntlm_opt *opt)
{
	int error;

	switch (opt->status) {
	case NTLM_OPT_STATUS_DONE:
		error = fprintf(file, "Finished processing arguments (no error)\n");
		break;
	case NTLM_OPT_STATUS_OK:
		error = fprintf(file, "No error\n");
		break;
	case NTLM_OPT_STATUS_UNKNOWN_OPTION:
		error = fprintf(file, "Unknown option: %s\n", opt->arg);
		break;
	case NTLM_OPT_STATUS_MISSING_VALUE:
		if (strncmp(opt->arg, "--", 2) == 0)
			error = fprintf(file, "Option '%s' requires a value.\n",
				opt->spec->name);
		else
			error = fprintf(file, "Switch '%c' requires a value.\n",
				opt->spec->alias);
		break;
	default:
		error = fprintf(file, "Unknown status: %d\n", opt->status);
		break;
	}

	return error;
}

int ntlm_opt_usage_fprint(
	FILE *file,
	const char *command,
	const ntlm_opt_spec specs[])
{
	const ntlm_opt_spec *spec;
	int choice = 0;
	int error;

	if ((error = fprintf(file, "usage: %s", command)) < 0)
		goto done;

	for (spec = specs; spec->type; ++spec) {
		int optional = !(spec->usage & NTLM_OPT_USAGE_REQUIRED);

		if (spec->usage & NTLM_OPT_USAGE_HIDDEN)
			continue;

		if (choice)
			error = fprintf(file, "|");
		else
			error = fprintf(file, " ");

		if (error < 0)
			goto done;

		if (optional && !choice && (error = fprintf(file, "[")) < 0)
			goto done;

		if (spec->type == NTLM_OPT_VALUE && spec->alias)
			error = fprintf(file, "-%c <%s>", spec->alias, spec->value_name);
		else if (spec->type == NTLM_OPT_VALUE)
			error = fprintf(file, "--%s=<%s>", spec->name, spec->value_name);
		else if (spec->type == NTLM_OPT_VALUE_OPTIONAL && spec->alias)
			error = fprintf(file, "-%c [<%s>]", spec->alias, spec->value_name);
		else if (spec->type == NTLM_OPT_VALUE_OPTIONAL)
			error = fprintf(file, "--%s[=<%s>]", spec->name, spec->value_name);
		else if (spec->type == NTLM_OPT_ARG)
			error = fprintf(file, "<%s>", spec->value_name);
		else if (spec->type == NTLM_OPT_ARGS)
			error = fprintf(file, "<%s...>", spec->value_name);
		else if (spec->type == NTLM_OPT_LITERAL)
			error = fprintf(file, "--");
		else if (spec->alias && !(spec->usage & NTLM_OPT_USAGE_SHOW_LONG))
			error = fprintf(file, "-%c", spec->alias);
		else
			error = fprintf(file, "--%s", spec->name);

		if (error < 0)
			goto done;

		choice = !!((spec+1)->usage & NTLM_OPT_USAGE_CHOICE);

		if (optional && !choice && (error = fprintf(file, "]")) < 0)
			goto done;
	}

	error = fprintf(file, "\n");

done:
	error = (error < 0) ? -1 : 0;
	return error;
}

