#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "ntlmclient.h"
#include "ntlm_cli_opt.h"
#include "base64.h"

#define die(msg) do { \
	fprintf(stderr, "Error: %s\n", msg); \
	exit(1); \
} while(0)

enum ntlm_cli_type {
	NTLM_CLI_NEGOTIATE,
	NTLM_CLI_RESPONSE
};

static void read_challenge(unsigned char **out, size_t *out_len, int raw)
{
	unsigned char *msg, *base64;
	size_t msg_len = 0, base64_len, remain = 10240;
	int ret = 1;

	if ((msg = malloc(remain)) == NULL)
		die("out of memory");

	while (remain) {
		ret = read(STDIN_FILENO, msg + msg_len, remain);

		if (ret < 0)
			die("could not read challenge");
		else if (ret == 0)
			break;

		msg_len += ret;
		remain -= ret;
	}

	if (raw) {
		*out = msg;
		*out_len = msg_len;
	} else {
		if ((base64 = base64_decode(msg, msg_len, &base64_len)) == NULL)
			die("out of memory");
		else if (base64 == BASE64_INVALID)
			die("invalid base64-encoded challenge message");

		free(msg);

		*out = base64;
		*out_len = base64_len;
	}
}

static void show_message(const unsigned char *msg, size_t msg_len, int raw)
{
	unsigned char *base64 = NULL;
	size_t base64_len;

	if (!raw) {
		if ((base64 = base64_encode(msg, msg_len, &base64_len)) == NULL)
			die("out of memory");

		msg = base64;
		msg_len = base64_len;
	}

	write(STDOUT_FILENO, msg, msg_len);
	free(base64);
}

int main(int argc, char **argv)
{
	char *target = NULL, *username = NULL, *domain = NULL, *password = NULL;
	int enable_lm = 0, enable_ntlm = 0, disable_ntlm2 = 0;
	int raw = 0, help = 0;
	int type = NTLM_CLI_NEGOTIATE;

	ntlm_client *ntlm = NULL;
	ntlm_client_flags ntlm_flags = 0;
	const unsigned char *message;
	unsigned char *challenge = NULL;
	size_t challenge_len, message_len;

	ntlm_opt_parser opt_parser;
	ntlm_opt opt;

	ntlm_opt_spec opt_specs[] = {
		{ NTLM_OPT_TYPE_SWITCH, "negotiate", 'n', &type, NTLM_CLI_NEGOTIATE,
		  NTLM_OPT_USAGE_SHOW_LONG, NULL, "produce a negotiate package" },
		{ NTLM_OPT_TYPE_SWITCH, "response", 'r', &type, NTLM_CLI_RESPONSE,
		  NTLM_OPT_USAGE_CHOICE | NTLM_OPT_USAGE_SHOW_LONG,
		  NULL, "produce a response to a challenge (required)" },

		{ NTLM_OPT_TYPE_VALUE, "target", 't', &target, 0,
		  0, "target", "sets the target (the remote hostname)" },
		{ NTLM_OPT_TYPE_VALUE, "username", 'u', &username, 0,
		  0, "username", "sets the username for authentication" },
		{ NTLM_OPT_TYPE_VALUE, "domain", 'd', &domain, 0,
		  0, "domain", "sets the user's domain" },
		{ NTLM_OPT_TYPE_VALUE,  "password", 'p', &password, 0,
		  0, "password", "sets the user's password" },

		{ NTLM_OPT_TYPE_BOOL, "enable-lm", 0, &enable_lm, 0,
		  0, NULL, "enable LM authentication" },
		{ NTLM_OPT_TYPE_BOOL, "enable-ntlm", 0, &enable_ntlm, 0,
		  0, NULL, "enable NTLM authentication" },
		{ NTLM_OPT_TYPE_BOOL, "disable-ntlm2", 0, &disable_ntlm2, 0,
		  0, NULL, "disable NTLM2 authentication" },

		{ NTLM_OPT_TYPE_BOOL, "raw", 0, &raw, 0,
		  0, NULL, "read and write raw binary (instead of base64)" },
		{ NTLM_OPT_TYPE_SWITCH, "help", 0, &help, 0,
		  0, NULL, "display help" },

		{ NTLM_OPT_TYPE_NONE, NULL, 0, NULL, 0, 0, NULL, NULL }
	};

	ntlm_opt_parser_init(&opt_parser, opt_specs, argv + 1, argc - 1, 0);

	while (ntlm_opt_parser_next(&opt, &opt_parser)) {
		if (!opt.spec) {
			ntlm_opt_status_fprint(stderr, NULL, &opt);
			ntlm_opt_usage_fprint(stderr, argv[0], opt_specs);
			return 129;
		}
	}

	if (enable_lm)
		ntlm_flags |= NTLM_CLIENT_ENABLE_LM;

	if (enable_ntlm)
		ntlm_flags |= NTLM_CLIENT_ENABLE_LM;

	if (disable_ntlm2)
		ntlm_flags |= NTLM_CLIENT_DISABLE_NTLM2;


	if ((ntlm = ntlm_client_init(ntlm_flags)) == NULL)
		die("out of memory");

	if (ntlm_client_set_target(ntlm, target) ||
		ntlm_client_set_credentials(ntlm, username, domain, password))
		die(ntlm_client_errmsg(ntlm));

	if (type == NTLM_CLI_NEGOTIATE) {
		if (ntlm_client_negotiate(&message, &message_len, ntlm))
			die(ntlm_client_errmsg(ntlm));
	} else {
		read_challenge(&challenge, &challenge_len, raw);

		if (ntlm_client_set_challenge(ntlm, challenge, challenge_len) ||
			ntlm_client_response(&message, &message_len, ntlm))
			die(ntlm_client_errmsg(ntlm));
	}

	show_message(message, message_len, raw);

	ntlm_client_free(ntlm);
	return 0;
}
