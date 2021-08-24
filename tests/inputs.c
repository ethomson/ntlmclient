#include "clar.h"
#include "ntlm.h"
#include "ntlm_tests.h"

static ntlm_client *ntlm;

void test_inputs__initialize(void)
{
	cl_assert((ntlm = ntlm_client_init(NTLM_CLIENT_DEFAULTS)) != NULL);
}

void test_inputs__cleanup(void)
{
	ntlm_client_free(ntlm);
}

void test_inputs__null(void)
{
	const unsigned char *msg;
	size_t msg_len;

	cl_assert(ntlm_client_errmsg(NULL) != NULL);

	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_set_hostname(NULL, "hostname", "HOSTDOMAIN"));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_set_credentials(NULL, "user", "DOMAIN", "pass!"));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_set_target(NULL, "target"));

	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_negotiate(NULL, &msg_len, ntlm));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_negotiate(&msg, NULL, ntlm));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_negotiate(&msg, &msg_len, NULL));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_negotiate(NULL, NULL, NULL));

	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_set_challenge(NULL, (const unsigned char *)"foo", 3));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_set_challenge(ntlm, NULL, 3));

	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_response(NULL, &msg_len, ntlm));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_response(&msg, NULL, ntlm));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_response(&msg, &msg_len, NULL));
	cl_must_fail_with(NTLM_CLIENT_ERROR_INVALID_INPUT, ntlm_client_response(NULL, NULL, NULL));
}

void test_inputs__set_hostname(void)
{
	cl_must_pass(ntlm_client_set_hostname(ntlm, "hostname", "HOSTDOMAIN"));
	cl_assert_equal_s("hostname", ntlm->hostname);
	cl_assert_equal_s("HOSTDOMAIN", ntlm->hostdomain);

	cl_must_pass(ntlm_client_set_hostname(ntlm, "hostname", NULL));
	cl_assert_equal_s("hostname", ntlm->hostname);
	cl_assert_equal_p(NULL, ntlm->hostdomain);

	cl_must_pass(ntlm_client_set_hostname(ntlm, NULL, NULL));
	cl_assert_equal_p(NULL, ntlm->hostname);
	cl_assert_equal_p(NULL, ntlm->hostdomain);
}

void test_inputs__set_credentials(void)
{
	cl_must_pass(ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "pass!"));
	cl_assert_equal_s("user", ntlm->username);
	cl_assert_equal_s("DOMAIN", ntlm->userdomain);
	cl_assert_equal_s("pass!", ntlm->password);

	cl_must_pass(ntlm_client_set_credentials(ntlm, "newuser", NULL, "SECRET!"));
	cl_assert_equal_s("newuser", ntlm->username);
	cl_assert_equal_p(NULL, ntlm->userdomain);
	cl_assert_equal_s("SECRET!", ntlm->password);
}

void test_inputs__set_credentials_unicode(void)
{
	cl_must_pass(ntlm_client_set_credentials(ntlm, "us\u00e9r", "DOMAIN", "pass!"));
	cl_assert_equal_s("us\u00e9r", ntlm->username);
	cl_assert_equal_s("DOMAIN", ntlm->userdomain);
	cl_assert_equal_s("pass!", ntlm->password);

	cl_must_pass(ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "p\u00e1ss!"));
	cl_assert_equal_s("user", ntlm->username);
	cl_assert_equal_s("DOMAIN", ntlm->userdomain);
	cl_assert_equal_s("p\u00e1ss!", ntlm->password);
}

void test_inputs__set_target(void)
{
	cl_must_pass(ntlm_client_set_target(ntlm, "target"));
	cl_assert_equal_s("target", ntlm->target);

	cl_must_pass(ntlm_client_set_target(ntlm, "newtarget"));
	cl_assert_equal_s("newtarget", ntlm->target);
}
