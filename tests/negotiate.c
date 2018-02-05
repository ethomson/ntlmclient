#include "ntlm_tests.h"

/*
 * Most of this test data comes from Eric Glass'
 * "The NTLM Authentication Protocol and Security Support Provider".
 * http://davenport.sourceforge.net/ntlm.html
 */

void test_negotiate__initialize(void)
{
}

void test_negotiate__cleanup(void)
{
}

void test_negotiate__minimal(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *negotiate_msg;
	size_t negotiate_msg_len;

	flags |= NTLM_CLIENT_DISABLE_UNICODE;
	flags |= NTLM_CLIENT_ENABLE_NTLM;
	flags |= NTLM_CLIENT_DISABLE_NTLM2;
	flags |= NTLM_CLIENT_DISABLE_REQUEST_TARGET;

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_ntlm_pass(ntlm, ntlm_client_negotiate(&negotiate_msg,
		&negotiate_msg_len, ntlm));

	cl_assert_equal_i(16, negotiate_msg_len);

	/* NTLMSSP message header */
	cl_assert_equal_i(0x4e, negotiate_msg[0]);
	cl_assert_equal_i(0x54, negotiate_msg[1]);
	cl_assert_equal_i(0x4c, negotiate_msg[2]);
	cl_assert_equal_i(0x4d, negotiate_msg[3]);
	cl_assert_equal_i(0x53, negotiate_msg[4]);
	cl_assert_equal_i(0x53, negotiate_msg[5]);
	cl_assert_equal_i(0x50, negotiate_msg[6]);
	cl_assert_equal_i(0x00, negotiate_msg[7]);

	/* Message indicator */
	cl_assert_equal_i(0x01, negotiate_msg[8]);
	cl_assert_equal_i(0x00, negotiate_msg[9]);
	cl_assert_equal_i(0x00, negotiate_msg[10]);
	cl_assert_equal_i(0x00, negotiate_msg[11]);

	/* Flags: NEGOTIATE_NTLM | NEGOTIATE_OEM */
	cl_assert_equal_i(0x02, negotiate_msg[12]);
	cl_assert_equal_i(0x02, negotiate_msg[13]);
	cl_assert_equal_i(0x00, negotiate_msg[14]);
	cl_assert_equal_i(0x00, negotiate_msg[15]);

	ntlm_client_free(ntlm);
}

void test_negotiate__sample(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *negotiate_msg;
	size_t negotiate_msg_len;

	flags |= NTLM_CLIENT_ENABLE_NTLM;
	flags |= NTLM_CLIENT_DISABLE_NTLM2;

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_ntlm_pass(ntlm,
		ntlm_client_set_hostname(ntlm, "WORKSTATION", "DOMAIN"));
	cl_ntlm_pass(ntlm, ntlm_client_set_version(ntlm, 5, 0, 2195));
	cl_ntlm_pass(ntlm, ntlm_client_negotiate(&negotiate_msg,
		&negotiate_msg_len, ntlm));

	cl_assert_equal_i(57, negotiate_msg_len);

	/* NTLMSSP message header */
	cl_assert_equal_i(0x4e, negotiate_msg[0]);
	cl_assert_equal_i(0x54, negotiate_msg[1]);
	cl_assert_equal_i(0x4c, negotiate_msg[2]);
	cl_assert_equal_i(0x4d, negotiate_msg[3]);
	cl_assert_equal_i(0x53, negotiate_msg[4]);
	cl_assert_equal_i(0x53, negotiate_msg[5]);
	cl_assert_equal_i(0x50, negotiate_msg[6]);
	cl_assert_equal_i(0x00, negotiate_msg[7]);

	/* Message indicator */
	cl_assert_equal_i(0x01, negotiate_msg[8]);
	cl_assert_equal_i(0x00, negotiate_msg[9]);
	cl_assert_equal_i(0x00, negotiate_msg[10]);
	cl_assert_equal_i(0x00, negotiate_msg[11]);

	/* Flags: NEGOTIATE_OEM | NEGOTIATE_NTLM2 */
	cl_assert_equal_i(0x07, negotiate_msg[12]);
	cl_assert_equal_i(0x32, negotiate_msg[13]);
	cl_assert_equal_i(0x00, negotiate_msg[14]);
	cl_assert_equal_i(0x00, negotiate_msg[15]);

	/* Domain information */
	cl_assert_equal_i(0x06, negotiate_msg[16]);
	cl_assert_equal_i(0x00, negotiate_msg[17]);
	cl_assert_equal_i(0x06, negotiate_msg[18]);
	cl_assert_equal_i(0x00, negotiate_msg[19]);
	cl_assert_equal_i(0x33, negotiate_msg[20]);
	cl_assert_equal_i(0x00, negotiate_msg[21]);
	cl_assert_equal_i(0x00, negotiate_msg[22]);
	cl_assert_equal_i(0x00, negotiate_msg[23]);

	/* Workstation information */
	cl_assert_equal_i(0x0b, negotiate_msg[24]);
	cl_assert_equal_i(0x00, negotiate_msg[25]);
	cl_assert_equal_i(0x0b, negotiate_msg[26]);
	cl_assert_equal_i(0x00, negotiate_msg[27]);
	cl_assert_equal_i(0x28, negotiate_msg[28]);
	cl_assert_equal_i(0x00, negotiate_msg[29]);
	cl_assert_equal_i(0x00, negotiate_msg[30]);
	cl_assert_equal_i(0x00, negotiate_msg[31]);

	/* OS Version */
	cl_assert_equal_i(0x05, negotiate_msg[32]);
	cl_assert_equal_i(0x00, negotiate_msg[33]);
	cl_assert_equal_i(0x93, negotiate_msg[34]);
	cl_assert_equal_i(0x08, negotiate_msg[35]);
	cl_assert_equal_i(0x00, negotiate_msg[36]);
	cl_assert_equal_i(0x00, negotiate_msg[37]);
	cl_assert_equal_i(0x00, negotiate_msg[38]);
	cl_assert_equal_i(0x0f, negotiate_msg[39]);

	/* Workstation buffer */
	cl_assert_equal_i('W', negotiate_msg[40]);
	cl_assert_equal_i('O', negotiate_msg[41]);
	cl_assert_equal_i('R', negotiate_msg[42]);
	cl_assert_equal_i('K', negotiate_msg[43]);
	cl_assert_equal_i('S', negotiate_msg[44]);
	cl_assert_equal_i('T', negotiate_msg[45]);
	cl_assert_equal_i('A', negotiate_msg[46]);
	cl_assert_equal_i('T', negotiate_msg[47]);
	cl_assert_equal_i('I', negotiate_msg[48]);
	cl_assert_equal_i('O', negotiate_msg[49]);
	cl_assert_equal_i('N', negotiate_msg[50]);

	/* Domain buffer */
	cl_assert_equal_i('D', negotiate_msg[51]);
	cl_assert_equal_i('O', negotiate_msg[52]);
	cl_assert_equal_i('M', negotiate_msg[53]);
	cl_assert_equal_i('A', negotiate_msg[54]);
	cl_assert_equal_i('I', negotiate_msg[55]);
	cl_assert_equal_i('N', negotiate_msg[56]);

	ntlm_client_free(ntlm);
}
