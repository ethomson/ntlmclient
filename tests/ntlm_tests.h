#ifndef PRIVATE_TESTS_NTLM_H__
#define PRIVATE_TESTS_NTLM_H__

#include "clar.h"
#include "ntlm.h"
#include "util.h"

#define cl_ntlm_pass(ntlm, expr) cl_ntlm_expect((ntlm), (expr), 0, __FILE__, __LINE__)

#define cl_ntlm_expect(ntlm, expr, expected, file, line) do { \
	int _ntlm_error; \
	if ((_ntlm_error = (expr)) != expected) \
		cl_ntlm_report_failure(ntlm, file, line, "Function call failed: " #expr); \
} while (0)

__attribute__((unused))
static void cl_ntlm_report_failure(
	ntlm_client *ntlm,
	const char *file,
	int line,
	const char *message)
{
	clar__fail(file, line, message, ntlm_client_errmsg(ntlm), 1);
}

#endif /* PRIVATE_TESTS_NTLM_H__ */
