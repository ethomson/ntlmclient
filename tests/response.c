#include "ntlm_tests.h"

/*
 * Most of this test data comes from Eric Glass'
 * "The NTLM Authentication Protocol and Security Support Provider".
 * http://davenport.sourceforge.net/ntlm.html
 */

void test_response__initialize(void)
{
}

void test_response__cleanup(void)
{
}

void test_response__fails_without_challenge(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *response_msg;
	size_t response_msg_len;

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_must_fail(ntlm_client_response(&response_msg,
		&response_msg_len, ntlm));
	ntlm_client_free(ntlm);
}

void test_response__fails_with_no_crypto_options(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *negotiate_msg, *response_msg;
	size_t negotiate_msg_len, response_msg_len;

	const unsigned char challenge_msg[] = {
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x01, 0x23, 0x45,
		0x67, 0x89, 0xab, 0xcd, 0xef,
	};

	flags |= NTLM_CLIENT_DISABLE_NTLM2;

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_ntlm_pass(ntlm,
		ntlm_client_set_hostname(ntlm, "WORKSTATION", "DOMAIN"));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "SecREt01"));
	cl_ntlm_pass(ntlm, ntlm_client_negotiate(&negotiate_msg, &negotiate_msg_len, ntlm));
	cl_ntlm_pass(ntlm, ntlm_client_set_challenge(ntlm,
		challenge_msg, sizeof(challenge_msg)));
	cl_must_fail(ntlm_client_response(&response_msg,
		&response_msg_len, ntlm));

	ntlm_client_free(ntlm);
}

void test_response__lm_only(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *negotiate_msg, *response_msg;
	size_t negotiate_msg_len, response_msg_len;

	const unsigned char challenge_msg[] = {
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x01, 0x23, 0x45,
		0x67, 0x89, 0xab, 0xcd, 0xef,
	};

	flags |= NTLM_CLIENT_ENABLE_LM;
	flags |= NTLM_CLIENT_DISABLE_NTLM2;

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_ntlm_pass(ntlm,
		ntlm_client_set_hostname(ntlm, "WORKSTATION", "DOMAIN"));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "SecREt01"));
	cl_ntlm_pass(ntlm, ntlm_client_negotiate(&negotiate_msg,
		&negotiate_msg_len, ntlm));
	cl_ntlm_pass(ntlm, ntlm_client_set_challenge(ntlm, challenge_msg,
		sizeof(challenge_msg)));
	cl_ntlm_pass(ntlm, ntlm_client_response(&response_msg,
		&response_msg_len, ntlm));

	cl_assert_equal_i(109, response_msg_len);

	/* NTLMSSP message header */
	cl_assert_equal_i(0x4e, response_msg[0]);
	cl_assert_equal_i(0x54, response_msg[1]);
	cl_assert_equal_i(0x4c, response_msg[2]);
	cl_assert_equal_i(0x4d, response_msg[3]);
	cl_assert_equal_i(0x53, response_msg[4]);
	cl_assert_equal_i(0x53, response_msg[5]);
	cl_assert_equal_i(0x50, response_msg[6]);
	cl_assert_equal_i(0x00, response_msg[7]);

	/* Message indicator */
	cl_assert_equal_i(0x03, response_msg[8]);
	cl_assert_equal_i(0x00, response_msg[9]);
	cl_assert_equal_i(0x00, response_msg[10]);
	cl_assert_equal_i(0x00, response_msg[11]);

	/* LM Response security buffer: length=24, alloc=24, offset=85 */
	cl_assert_equal_i(0x18, response_msg[12]);
	cl_assert_equal_i(0x00, response_msg[13]);
	cl_assert_equal_i(0x18, response_msg[14]);
	cl_assert_equal_i(0x00, response_msg[15]);
	cl_assert_equal_i(0x55, response_msg[16]);
	cl_assert_equal_i(0x00, response_msg[17]);
	cl_assert_equal_i(0x00, response_msg[18]);
	cl_assert_equal_i(0x00, response_msg[19]);

	/* NTLM Response security buffer: length=0, alloc=0, offset=0 */
	cl_assert_equal_i(0x00, response_msg[20]);
	cl_assert_equal_i(0x00, response_msg[21]);
	cl_assert_equal_i(0x00, response_msg[22]);
	cl_assert_equal_i(0x00, response_msg[23]);
	cl_assert_equal_i(0x6d, response_msg[24]);
	cl_assert_equal_i(0x00, response_msg[25]);
	cl_assert_equal_i(0x00, response_msg[26]);
	cl_assert_equal_i(0x00, response_msg[27]);

	/* Target name security buffer: length=6, alloc=6, offset=64 */
	cl_assert_equal_i(0x06, response_msg[28]);
	cl_assert_equal_i(0x00, response_msg[29]);
	cl_assert_equal_i(0x06, response_msg[30]);
	cl_assert_equal_i(0x00, response_msg[31]);
	cl_assert_equal_i(0x40, response_msg[32]);
	cl_assert_equal_i(0x00, response_msg[33]);
	cl_assert_equal_i(0x00, response_msg[34]);
	cl_assert_equal_i(0x00, response_msg[35]);

	/* Username security buffer: length=4, alloc=4, offset=70 */
	cl_assert_equal_i(0x04, response_msg[36]);
	cl_assert_equal_i(0x00, response_msg[37]);
	cl_assert_equal_i(0x04, response_msg[38]);
	cl_assert_equal_i(0x00, response_msg[39]);
	cl_assert_equal_i(0x46, response_msg[40]);
	cl_assert_equal_i(0x00, response_msg[41]);
	cl_assert_equal_i(0x00, response_msg[42]);
	cl_assert_equal_i(0x00, response_msg[43]);

	/* Workstation name security buffer: length=11, alloc=11, offset=74 */
	cl_assert_equal_i(0x0b, response_msg[44]);
	cl_assert_equal_i(0x00, response_msg[45]);
	cl_assert_equal_i(0x0b, response_msg[46]);
	cl_assert_equal_i(0x00, response_msg[47]);
	cl_assert_equal_i(0x4a, response_msg[48]);
	cl_assert_equal_i(0x00, response_msg[49]);
	cl_assert_equal_i(0x00, response_msg[50]);
	cl_assert_equal_i(0x00, response_msg[51]);

	/* Session key security buffer: length=0, alloc=0, offset=109 */
	cl_assert_equal_i(0x00, response_msg[52]);
	cl_assert_equal_i(0x00, response_msg[53]);
	cl_assert_equal_i(0x00, response_msg[54]);
	cl_assert_equal_i(0x00, response_msg[55]);
	cl_assert_equal_i(0x6d, response_msg[56]);
	cl_assert_equal_i(0x00, response_msg[57]);
	cl_assert_equal_i(0x00, response_msg[58]);
	cl_assert_equal_i(0x00, response_msg[59]);

	/* Flags: NEGOTIATE_OEM */
	cl_assert_equal_i(0x02, response_msg[60]);
	cl_assert_equal_i(0x00, response_msg[61]);
	cl_assert_equal_i(0x00, response_msg[62]);
	cl_assert_equal_i(0x00, response_msg[63]);

	/* Target name: "DOMAIN" */
	cl_assert_equal_i('D',  response_msg[64]);
	cl_assert_equal_i('O',  response_msg[65]);
	cl_assert_equal_i('M',  response_msg[66]);
	cl_assert_equal_i('A',  response_msg[67]);
	cl_assert_equal_i('I',  response_msg[68]);
	cl_assert_equal_i('N',  response_msg[69]);

	/* Username: "user" */
	cl_assert_equal_i('u',  response_msg[70]);
	cl_assert_equal_i('s',  response_msg[71]);
	cl_assert_equal_i('e',  response_msg[72]);
	cl_assert_equal_i('r',  response_msg[73]);

	/* Workstation name: "WORKSTATION" */
	cl_assert_equal_i('W',  response_msg[74]);
	cl_assert_equal_i('O',  response_msg[75]);
	cl_assert_equal_i('R',  response_msg[76]);
	cl_assert_equal_i('K',  response_msg[77]);
	cl_assert_equal_i('S',  response_msg[78]);
	cl_assert_equal_i('T',  response_msg[79]);
	cl_assert_equal_i('A',  response_msg[80]);
	cl_assert_equal_i('T',  response_msg[81]);
	cl_assert_equal_i('I',  response_msg[82]);
	cl_assert_equal_i('O',  response_msg[83]);
	cl_assert_equal_i('N',  response_msg[84]);

	/* LM Response Data */
	cl_assert_equal_i(0xc3, response_msg[85]);
	cl_assert_equal_i(0x37, response_msg[86]);
	cl_assert_equal_i(0xcd, response_msg[87]);
	cl_assert_equal_i(0x5c, response_msg[88]);
	cl_assert_equal_i(0xbd, response_msg[89]);
	cl_assert_equal_i(0x44, response_msg[90]);
	cl_assert_equal_i(0xfc, response_msg[91]);
	cl_assert_equal_i(0x97, response_msg[92]);
	cl_assert_equal_i(0x82, response_msg[93]);
	cl_assert_equal_i(0xa6, response_msg[94]);
	cl_assert_equal_i(0x67, response_msg[95]);
	cl_assert_equal_i(0xaf, response_msg[96]);
	cl_assert_equal_i(0x6d, response_msg[97]);
	cl_assert_equal_i(0x42, response_msg[98]);
	cl_assert_equal_i(0x7c, response_msg[99]);
	cl_assert_equal_i(0x6d, response_msg[100]);
	cl_assert_equal_i(0xe6, response_msg[101]);
	cl_assert_equal_i(0x7c, response_msg[102]);
	cl_assert_equal_i(0x20, response_msg[103]);
	cl_assert_equal_i(0xc2, response_msg[104]);
	cl_assert_equal_i(0xd3, response_msg[105]);
	cl_assert_equal_i(0xe7, response_msg[106]);
	cl_assert_equal_i(0x7c, response_msg[107]);
	cl_assert_equal_i(0x56, response_msg[108]);

	ntlm_client_free(ntlm);
}

void test_response__lm_and_ntlm(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *negotiate_msg, *response_msg;
	size_t negotiate_msg_len, response_msg_len;

	const unsigned char challenge_msg[] = {
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x01, 0x23, 0x45,
		0x67, 0x89, 0xab, 0xcd, 0xef,
	};

	flags |= NTLM_CLIENT_ENABLE_LM;
	flags |= NTLM_CLIENT_ENABLE_NTLM;
	flags |= NTLM_CLIENT_DISABLE_NTLM2;

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_ntlm_pass(ntlm,
		ntlm_client_set_hostname(ntlm, "WORKSTATION", "DOMAIN"));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "SecREt01"));
	cl_ntlm_pass(ntlm, ntlm_client_negotiate(&negotiate_msg,
		&negotiate_msg_len, ntlm));
	cl_ntlm_pass(ntlm, ntlm_client_set_challenge(ntlm,
		challenge_msg, sizeof(challenge_msg)));
	cl_ntlm_pass(ntlm, ntlm_client_response(&response_msg,
		&response_msg_len, ntlm));

	cl_assert_equal_i(133, response_msg_len);

	/* NTLMSSP message header */
	cl_assert_equal_i(0x4e, response_msg[0]);
	cl_assert_equal_i(0x54, response_msg[1]);
	cl_assert_equal_i(0x4c, response_msg[2]);
	cl_assert_equal_i(0x4d, response_msg[3]);
	cl_assert_equal_i(0x53, response_msg[4]);
	cl_assert_equal_i(0x53, response_msg[5]);
	cl_assert_equal_i(0x50, response_msg[6]);
	cl_assert_equal_i(0x00, response_msg[7]);

	/* Message indicator */
	cl_assert_equal_i(0x03, response_msg[8]);
	cl_assert_equal_i(0x00, response_msg[9]);
	cl_assert_equal_i(0x00, response_msg[10]);
	cl_assert_equal_i(0x00, response_msg[11]);

	/* LM Response security buffer: length=24, alloc=24, offset=85 */
	cl_assert_equal_i(0x18, response_msg[12]);
	cl_assert_equal_i(0x00, response_msg[13]);
	cl_assert_equal_i(0x18, response_msg[14]);
	cl_assert_equal_i(0x00, response_msg[15]);
	cl_assert_equal_i(0x55, response_msg[16]);
	cl_assert_equal_i(0x00, response_msg[17]);
	cl_assert_equal_i(0x00, response_msg[18]);
	cl_assert_equal_i(0x00, response_msg[19]);

	/* NTLM Response security buffer: length=24, alloc=24, offset=130 */
	cl_assert_equal_i(0x18, response_msg[20]);
	cl_assert_equal_i(0x00, response_msg[21]);
	cl_assert_equal_i(0x18, response_msg[22]);
	cl_assert_equal_i(0x00, response_msg[23]);
	cl_assert_equal_i(0x6d, response_msg[24]);
	cl_assert_equal_i(0x00, response_msg[25]);
	cl_assert_equal_i(0x00, response_msg[26]);
	cl_assert_equal_i(0x00, response_msg[27]);

	/* Target name security buffer: length=6, alloc=6, offset=64 */
	cl_assert_equal_i(0x06, response_msg[28]);
	cl_assert_equal_i(0x00, response_msg[29]);
	cl_assert_equal_i(0x06, response_msg[30]);
	cl_assert_equal_i(0x00, response_msg[31]);
	cl_assert_equal_i(0x40, response_msg[32]);
	cl_assert_equal_i(0x00, response_msg[33]);
	cl_assert_equal_i(0x00, response_msg[34]);
	cl_assert_equal_i(0x00, response_msg[35]);

	/* Username security buffer: length=4, alloc=4, offset=70 */
	cl_assert_equal_i(0x04, response_msg[36]);
	cl_assert_equal_i(0x00, response_msg[37]);
	cl_assert_equal_i(0x04, response_msg[38]);
	cl_assert_equal_i(0x00, response_msg[39]);
	cl_assert_equal_i(0x46, response_msg[40]);
	cl_assert_equal_i(0x00, response_msg[41]);
	cl_assert_equal_i(0x00, response_msg[42]);
	cl_assert_equal_i(0x00, response_msg[43]);

	/* Workstation name security buffer: length=11, alloc=11, offset=74 */
	cl_assert_equal_i(0x0b, response_msg[44]);
	cl_assert_equal_i(0x00, response_msg[45]);
	cl_assert_equal_i(0x0b, response_msg[46]);
	cl_assert_equal_i(0x00, response_msg[47]);
	cl_assert_equal_i(0x4a, response_msg[48]);
	cl_assert_equal_i(0x00, response_msg[49]);
	cl_assert_equal_i(0x00, response_msg[50]);
	cl_assert_equal_i(0x00, response_msg[51]);

	/* Session key security buffer: length=0, alloc=0, offset=133 */
	cl_assert_equal_i(0x00, response_msg[52]);
	cl_assert_equal_i(0x00, response_msg[53]);
	cl_assert_equal_i(0x00, response_msg[54]);
	cl_assert_equal_i(0x00, response_msg[55]);
	cl_assert_equal_i(0x85, response_msg[56]);
	cl_assert_equal_i(0x00, response_msg[57]);
	cl_assert_equal_i(0x00, response_msg[58]);
	cl_assert_equal_i(0x00, response_msg[59]);

	/* Flags: NEGOTIATE_OEM | NEGOTIATE_NTLM */
	cl_assert_equal_i(0x02, response_msg[60]);
	cl_assert_equal_i(0x02, response_msg[61]);
	cl_assert_equal_i(0x00, response_msg[62]);
	cl_assert_equal_i(0x00, response_msg[63]);

	/* Target name: "DOMAIN" */
	cl_assert_equal_i('D',  response_msg[64]);
	cl_assert_equal_i('O',  response_msg[65]);
	cl_assert_equal_i('M',  response_msg[66]);
	cl_assert_equal_i('A',  response_msg[67]);
	cl_assert_equal_i('I',  response_msg[68]);
	cl_assert_equal_i('N',  response_msg[69]);

	/* Username: "user" */
	cl_assert_equal_i('u',  response_msg[70]);
	cl_assert_equal_i('s',  response_msg[71]);
	cl_assert_equal_i('e',  response_msg[72]);
	cl_assert_equal_i('r',  response_msg[73]);

	/* Workstation name: "WORKSTATION" */
	cl_assert_equal_i('W',  response_msg[74]);
	cl_assert_equal_i('O',  response_msg[75]);
	cl_assert_equal_i('R',  response_msg[76]);
	cl_assert_equal_i('K',  response_msg[77]);
	cl_assert_equal_i('S',  response_msg[78]);
	cl_assert_equal_i('T',  response_msg[79]);
	cl_assert_equal_i('A',  response_msg[80]);
	cl_assert_equal_i('T',  response_msg[81]);
	cl_assert_equal_i('I',  response_msg[82]);
	cl_assert_equal_i('O',  response_msg[83]);
	cl_assert_equal_i('N',  response_msg[84]);

	/* LM Response Data */
	cl_assert_equal_i(0xc3, response_msg[85]);
	cl_assert_equal_i(0x37, response_msg[86]);
	cl_assert_equal_i(0xcd, response_msg[87]);
	cl_assert_equal_i(0x5c, response_msg[88]);
	cl_assert_equal_i(0xbd, response_msg[89]);
	cl_assert_equal_i(0x44, response_msg[90]);
	cl_assert_equal_i(0xfc, response_msg[91]);
	cl_assert_equal_i(0x97, response_msg[92]);
	cl_assert_equal_i(0x82, response_msg[93]);
	cl_assert_equal_i(0xa6, response_msg[94]);
	cl_assert_equal_i(0x67, response_msg[95]);
	cl_assert_equal_i(0xaf, response_msg[96]);
	cl_assert_equal_i(0x6d, response_msg[97]);
	cl_assert_equal_i(0x42, response_msg[98]);
	cl_assert_equal_i(0x7c, response_msg[99]);
	cl_assert_equal_i(0x6d, response_msg[100]);
	cl_assert_equal_i(0xe6, response_msg[101]);
	cl_assert_equal_i(0x7c, response_msg[102]);
	cl_assert_equal_i(0x20, response_msg[103]);
	cl_assert_equal_i(0xc2, response_msg[104]);
	cl_assert_equal_i(0xd3, response_msg[105]);
	cl_assert_equal_i(0xe7, response_msg[106]);
	cl_assert_equal_i(0x7c, response_msg[107]);
	cl_assert_equal_i(0x56, response_msg[108]);

	/* NTLM Response Data */
	cl_assert_equal_i(0x25, response_msg[109]);
	cl_assert_equal_i(0xa9, response_msg[110]);
	cl_assert_equal_i(0x8c, response_msg[111]);
	cl_assert_equal_i(0x1c, response_msg[112]);
	cl_assert_equal_i(0x31, response_msg[113]);
	cl_assert_equal_i(0xe8, response_msg[114]);
	cl_assert_equal_i(0x18, response_msg[115]);
	cl_assert_equal_i(0x47, response_msg[116]);
	cl_assert_equal_i(0x46, response_msg[117]);
	cl_assert_equal_i(0x6b, response_msg[118]);
	cl_assert_equal_i(0x29, response_msg[119]);
	cl_assert_equal_i(0xb2, response_msg[120]);
	cl_assert_equal_i(0xdf, response_msg[121]);
	cl_assert_equal_i(0x46, response_msg[122]);
	cl_assert_equal_i(0x80, response_msg[123]);
	cl_assert_equal_i(0xf3, response_msg[124]);
	cl_assert_equal_i(0x99, response_msg[125]);
	cl_assert_equal_i(0x58, response_msg[126]);
	cl_assert_equal_i(0xfb, response_msg[127]);
	cl_assert_equal_i(0x8c, response_msg[128]);
	cl_assert_equal_i(0x21, response_msg[129]);
	cl_assert_equal_i(0x3a, response_msg[130]);
	cl_assert_equal_i(0x9c, response_msg[131]);
	cl_assert_equal_i(0xc6, response_msg[132]);

	ntlm_client_free(ntlm);
}

void test_response__ntlm2(void)
{
	ntlm_client *ntlm;
	ntlm_client_flags flags = NTLM_CLIENT_DEFAULTS;
	const unsigned char *negotiate_msg, *response_msg;
	size_t negotiate_msg_len, response_msg_len;

	const unsigned char challenge_msg[] = {
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00,
		0x30, 0x00, 0x00, 0x00, 0x01, 0x02, 0x81, 0x00,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x62, 0x00, 0x62, 0x00, 0x3c, 0x00, 0x00, 0x00,
		0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00,
		0x49, 0x00, 0x4e, 0x00, 0x02, 0x00, 0x0c, 0x00,
		0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00,
		0x49, 0x00, 0x4e, 0x00, 0x01, 0x00, 0x0c, 0x00,
		0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x56, 0x00,
		0x45, 0x00, 0x52, 0x00, 0x04, 0x00, 0x14, 0x00,
		0x64, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00,
		0x69, 0x00, 0x6e, 0x00, 0x2e, 0x00, 0x63, 0x00,
		0x6f, 0x00, 0x6d, 0x00, 0x03, 0x00, 0x22, 0x00,
		0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
		0x65, 0x00, 0x72, 0x00, 0x2e, 0x00, 0x64, 0x00,
		0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00,
		0x6e, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00,
		0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	cl_assert((ntlm = ntlm_client_init(flags)) != NULL);
	cl_ntlm_pass(ntlm,
		ntlm_client_set_hostname(ntlm, "WORKSTATION", "DOMAIN"));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_credentials(ntlm, "user", "DOMAIN", "SecREt01"));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_target(ntlm, "DOMAIN"));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_timestamp(ntlm, 0x0090d336b734c301));
	cl_ntlm_pass(ntlm,
		ntlm_client_set_nonce(ntlm, 0xffffff0011223344));
	cl_ntlm_pass(ntlm,
		ntlm_client_negotiate(&negotiate_msg, &negotiate_msg_len, ntlm));
	cl_ntlm_pass(ntlm, ntlm_client_set_challenge(ntlm,
		challenge_msg, sizeof(challenge_msg)));
	cl_ntlm_pass(ntlm, ntlm_client_response(&response_msg,
		&response_msg_len, ntlm));

	cl_assert_equal_i(276, response_msg_len);

	/* NTLMSSP message header */
	cl_assert_equal_i(0x4e, response_msg[0]);
	cl_assert_equal_i(0x54, response_msg[1]);
	cl_assert_equal_i(0x4c, response_msg[2]);
	cl_assert_equal_i(0x4d, response_msg[3]);
	cl_assert_equal_i(0x53, response_msg[4]);
	cl_assert_equal_i(0x53, response_msg[5]);
	cl_assert_equal_i(0x50, response_msg[6]);
	cl_assert_equal_i(0x00, response_msg[7]);

	/* Message indicator */
	cl_assert_equal_i(0x03, response_msg[8]);
	cl_assert_equal_i(0x00, response_msg[9]);
	cl_assert_equal_i(0x00, response_msg[10]);
	cl_assert_equal_i(0x00, response_msg[11]);

	/* LMv2 Response security buffer: length=24, alloc=24, offset=106 */
	cl_assert_equal_i(0x18, response_msg[12]);
	cl_assert_equal_i(0x00, response_msg[13]);
	cl_assert_equal_i(0x18, response_msg[14]);
	cl_assert_equal_i(0x00, response_msg[15]);
	cl_assert_equal_i(0x6a, response_msg[16]);
	cl_assert_equal_i(0x00, response_msg[17]);
	cl_assert_equal_i(0x00, response_msg[18]);
	cl_assert_equal_i(0x00, response_msg[19]);

	/* NTLMv2 Response security buffer: length=146, alloc=146, offset=130 */
	cl_assert_equal_i(0x92, response_msg[20]);
	cl_assert_equal_i(0x00, response_msg[21]);
	cl_assert_equal_i(0x92, response_msg[22]);
	cl_assert_equal_i(0x00, response_msg[23]);
	cl_assert_equal_i(0x82, response_msg[24]);
	cl_assert_equal_i(0x00, response_msg[25]);
	cl_assert_equal_i(0x00, response_msg[26]);
	cl_assert_equal_i(0x00, response_msg[27]);

	/* Target name security buffer: length=12, alloc=12, offset=64 */
	cl_assert_equal_i(0x0c, response_msg[28]);
	cl_assert_equal_i(0x00, response_msg[29]);
	cl_assert_equal_i(0x0c, response_msg[30]);
	cl_assert_equal_i(0x00, response_msg[31]);
	cl_assert_equal_i(0x40, response_msg[32]);
	cl_assert_equal_i(0x00, response_msg[33]);
	cl_assert_equal_i(0x00, response_msg[34]);
	cl_assert_equal_i(0x00, response_msg[35]);

	/* Username security buffer: length=8, alloc=8, offset=76 */
	cl_assert_equal_i(0x08, response_msg[36]);
	cl_assert_equal_i(0x00, response_msg[37]);
	cl_assert_equal_i(0x08, response_msg[38]);
	cl_assert_equal_i(0x00, response_msg[39]);
	cl_assert_equal_i(0x4c, response_msg[40]);
	cl_assert_equal_i(0x00, response_msg[41]);
	cl_assert_equal_i(0x00, response_msg[42]);
	cl_assert_equal_i(0x00, response_msg[43]);

	/* Workstation name security buffer: length=22, alloc=22, offset=84 */
	cl_assert_equal_i(0x16, response_msg[44]);
	cl_assert_equal_i(0x00, response_msg[45]);
	cl_assert_equal_i(0x16, response_msg[46]);
	cl_assert_equal_i(0x00, response_msg[47]);
	cl_assert_equal_i(0x54, response_msg[48]);
	cl_assert_equal_i(0x00, response_msg[49]);
	cl_assert_equal_i(0x00, response_msg[50]);
	cl_assert_equal_i(0x00, response_msg[51]);

	/* Session key security buffer: length=0, alloc=0, offset=276 */
	cl_assert_equal_i(0x00, response_msg[52]);
	cl_assert_equal_i(0x00, response_msg[53]);
	cl_assert_equal_i(0x00, response_msg[54]);
	cl_assert_equal_i(0x00, response_msg[55]);
	cl_assert_equal_i(0x14, response_msg[56]);
	cl_assert_equal_i(0x01, response_msg[57]);
	cl_assert_equal_i(0x00, response_msg[58]);
	cl_assert_equal_i(0x00, response_msg[59]);

	/* Flags: NEGOTIATE_UNICODE | NEGOTIATE_NTLM */
	cl_assert_equal_i(0x01, response_msg[60]);
	cl_assert_equal_i(0x02, response_msg[61]);
	cl_assert_equal_i(0x00, response_msg[62]);
	cl_assert_equal_i(0x00, response_msg[63]);

	/* Target name: "DOMAIN" */
	cl_assert_equal_i('D',  response_msg[64]);
	cl_assert_equal_i(0x00, response_msg[65]);
	cl_assert_equal_i('O',  response_msg[66]);
	cl_assert_equal_i(0x00, response_msg[67]);
	cl_assert_equal_i('M',  response_msg[68]);
	cl_assert_equal_i(0x00, response_msg[69]);
	cl_assert_equal_i('A',  response_msg[70]);
	cl_assert_equal_i(0x00, response_msg[71]);
	cl_assert_equal_i('I',  response_msg[72]);
	cl_assert_equal_i(0x00, response_msg[73]);
	cl_assert_equal_i('N',  response_msg[74]);
	cl_assert_equal_i(0x00, response_msg[75]);

	/* Username: "user" */
	cl_assert_equal_i('u',  response_msg[76]);
	cl_assert_equal_i(0x00, response_msg[77]);
	cl_assert_equal_i('s',  response_msg[78]);
	cl_assert_equal_i(0x00, response_msg[79]);
	cl_assert_equal_i('e',  response_msg[80]);
	cl_assert_equal_i(0x00, response_msg[81]);
	cl_assert_equal_i('r',  response_msg[82]);
	cl_assert_equal_i(0x00, response_msg[83]);

	/* Workstation name: "WORKSTATION" */
	cl_assert_equal_i('W',  response_msg[84]);
	cl_assert_equal_i(0x00, response_msg[85]);
	cl_assert_equal_i('O',  response_msg[86]);
	cl_assert_equal_i(0x00, response_msg[87]);
	cl_assert_equal_i('R',  response_msg[88]);
	cl_assert_equal_i(0x00, response_msg[89]);
	cl_assert_equal_i('K',  response_msg[90]);
	cl_assert_equal_i(0x00, response_msg[91]);
	cl_assert_equal_i('S',  response_msg[92]);
	cl_assert_equal_i(0x00, response_msg[93]);
	cl_assert_equal_i('T',  response_msg[94]);
	cl_assert_equal_i(0x00, response_msg[95]);
	cl_assert_equal_i('A',  response_msg[96]);
	cl_assert_equal_i(0x00, response_msg[97]);
	cl_assert_equal_i('T',  response_msg[98]);
	cl_assert_equal_i(0x00, response_msg[99]);
	cl_assert_equal_i('I',  response_msg[100]);
	cl_assert_equal_i(0x00, response_msg[101]);
	cl_assert_equal_i('O',  response_msg[102]);
	cl_assert_equal_i(0x00, response_msg[103]);
	cl_assert_equal_i('N',  response_msg[104]);
	cl_assert_equal_i(0x00, response_msg[105]);

	/* LMv2 Response Data */
	cl_assert_equal_i(0xd6, response_msg[106]);
	cl_assert_equal_i(0xe6, response_msg[107]);
	cl_assert_equal_i(0x15, response_msg[108]);
	cl_assert_equal_i(0x2e, response_msg[109]);
	cl_assert_equal_i(0xa2, response_msg[110]);
	cl_assert_equal_i(0x5d, response_msg[111]);
	cl_assert_equal_i(0x03, response_msg[112]);
	cl_assert_equal_i(0xb7, response_msg[113]);
	cl_assert_equal_i(0xc6, response_msg[114]);
	cl_assert_equal_i(0xba, response_msg[115]);
	cl_assert_equal_i(0x66, response_msg[116]);
	cl_assert_equal_i(0x29, response_msg[117]);
	cl_assert_equal_i(0xc2, response_msg[118]);
	cl_assert_equal_i(0xd6, response_msg[119]);
	cl_assert_equal_i(0xaa, response_msg[120]);
	cl_assert_equal_i(0xf0, response_msg[121]);
	cl_assert_equal_i(0xff, response_msg[122]);
	cl_assert_equal_i(0xff, response_msg[123]);
	cl_assert_equal_i(0xff, response_msg[124]);
	cl_assert_equal_i(0x00, response_msg[125]);
	cl_assert_equal_i(0x11, response_msg[126]);
	cl_assert_equal_i(0x22, response_msg[127]);
	cl_assert_equal_i(0x33, response_msg[128]);
	cl_assert_equal_i(0x44, response_msg[129]);

	/* NTLMv2 Response Data */
	cl_assert_equal_i(0xcb, response_msg[130]);
	cl_assert_equal_i(0xab, response_msg[131]);
	cl_assert_equal_i(0xbc, response_msg[132]);
	cl_assert_equal_i(0xa7, response_msg[133]);
	cl_assert_equal_i(0x13, response_msg[134]);
	cl_assert_equal_i(0xeb, response_msg[135]);
	cl_assert_equal_i(0x79, response_msg[136]);
	cl_assert_equal_i(0x5d, response_msg[137]);
	cl_assert_equal_i(0x04, response_msg[138]);
	cl_assert_equal_i(0xc9, response_msg[139]);
	cl_assert_equal_i(0x7a, response_msg[140]);
	cl_assert_equal_i(0xbc, response_msg[141]);
	cl_assert_equal_i(0x01, response_msg[142]);
	cl_assert_equal_i(0xee, response_msg[143]);
	cl_assert_equal_i(0x49, response_msg[144]);
	cl_assert_equal_i(0x83, response_msg[145]);
	cl_assert_equal_i(0x01, response_msg[146]);
	cl_assert_equal_i(0x01, response_msg[147]);
	cl_assert_equal_i(0x00, response_msg[148]);
	cl_assert_equal_i(0x00, response_msg[149]);
	cl_assert_equal_i(0x00, response_msg[150]);
	cl_assert_equal_i(0x00, response_msg[151]);
	cl_assert_equal_i(0x00, response_msg[152]);
	cl_assert_equal_i(0x00, response_msg[153]);
	cl_assert_equal_i(0x00, response_msg[154]);
	cl_assert_equal_i(0x90, response_msg[155]);
	cl_assert_equal_i(0xd3, response_msg[156]);
	cl_assert_equal_i(0x36, response_msg[157]);
	cl_assert_equal_i(0xb7, response_msg[158]);
	cl_assert_equal_i(0x34, response_msg[159]);
	cl_assert_equal_i(0xc3, response_msg[160]);
	cl_assert_equal_i(0x01, response_msg[161]);
	cl_assert_equal_i(0xff, response_msg[162]);
	cl_assert_equal_i(0xff, response_msg[163]);
	cl_assert_equal_i(0xff, response_msg[164]);
	cl_assert_equal_i(0x00, response_msg[165]);
	cl_assert_equal_i(0x11, response_msg[166]);
	cl_assert_equal_i(0x22, response_msg[167]);
	cl_assert_equal_i(0x33, response_msg[168]);
	cl_assert_equal_i(0x44, response_msg[169]);
	cl_assert_equal_i(0x00, response_msg[170]);
	cl_assert_equal_i(0x00, response_msg[171]);
	cl_assert_equal_i(0x00, response_msg[172]);
	cl_assert_equal_i(0x00, response_msg[173]);
	cl_assert_equal_i(0x02, response_msg[174]);
	cl_assert_equal_i(0x00, response_msg[175]);
	cl_assert_equal_i(0x0c, response_msg[176]);
	cl_assert_equal_i(0x00, response_msg[177]);
	cl_assert_equal_i(0x44, response_msg[178]);
	cl_assert_equal_i(0x00, response_msg[179]);
	cl_assert_equal_i(0x4f, response_msg[180]);
	cl_assert_equal_i(0x00, response_msg[181]);
	cl_assert_equal_i(0x4d, response_msg[182]);
	cl_assert_equal_i(0x00, response_msg[183]);
	cl_assert_equal_i(0x41, response_msg[184]);
	cl_assert_equal_i(0x00, response_msg[185]);
	cl_assert_equal_i(0x49, response_msg[186]);
	cl_assert_equal_i(0x00, response_msg[187]);
	cl_assert_equal_i(0x4e, response_msg[188]);
	cl_assert_equal_i(0x00, response_msg[189]);
	cl_assert_equal_i(0x01, response_msg[190]);
	cl_assert_equal_i(0x00, response_msg[191]);
	cl_assert_equal_i(0x0c, response_msg[192]);
	cl_assert_equal_i(0x00, response_msg[193]);
	cl_assert_equal_i(0x53, response_msg[194]);
	cl_assert_equal_i(0x00, response_msg[195]);
	cl_assert_equal_i(0x45, response_msg[196]);
	cl_assert_equal_i(0x00, response_msg[197]);
	cl_assert_equal_i(0x52, response_msg[198]);
	cl_assert_equal_i(0x00, response_msg[199]);
	cl_assert_equal_i(0x56, response_msg[200]);
	cl_assert_equal_i(0x00, response_msg[201]);
	cl_assert_equal_i(0x45, response_msg[202]);
	cl_assert_equal_i(0x00, response_msg[203]);
	cl_assert_equal_i(0x52, response_msg[204]);
	cl_assert_equal_i(0x00, response_msg[205]);
	cl_assert_equal_i(0x04, response_msg[206]);
	cl_assert_equal_i(0x00, response_msg[207]);
	cl_assert_equal_i(0x14, response_msg[208]);
	cl_assert_equal_i(0x00, response_msg[209]);
	cl_assert_equal_i(0x64, response_msg[210]);
	cl_assert_equal_i(0x00, response_msg[211]);
	cl_assert_equal_i(0x6f, response_msg[212]);
	cl_assert_equal_i(0x00, response_msg[213]);
	cl_assert_equal_i(0x6d, response_msg[214]);
	cl_assert_equal_i(0x00, response_msg[215]);
	cl_assert_equal_i(0x61, response_msg[216]);
	cl_assert_equal_i(0x00, response_msg[217]);
	cl_assert_equal_i(0x69, response_msg[218]);
	cl_assert_equal_i(0x00, response_msg[219]);
	cl_assert_equal_i(0x6e, response_msg[220]);
	cl_assert_equal_i(0x00, response_msg[221]);
	cl_assert_equal_i(0x2e, response_msg[222]);
	cl_assert_equal_i(0x00, response_msg[223]);
	cl_assert_equal_i(0x63, response_msg[224]);
	cl_assert_equal_i(0x00, response_msg[225]);
	cl_assert_equal_i(0x6f, response_msg[226]);
	cl_assert_equal_i(0x00, response_msg[227]);
	cl_assert_equal_i(0x6d, response_msg[228]);
	cl_assert_equal_i(0x00, response_msg[229]);
	cl_assert_equal_i(0x03, response_msg[230]);
	cl_assert_equal_i(0x00, response_msg[231]);
	cl_assert_equal_i(0x22, response_msg[232]);
	cl_assert_equal_i(0x00, response_msg[233]);
	cl_assert_equal_i(0x73, response_msg[234]);
	cl_assert_equal_i(0x00, response_msg[235]);
	cl_assert_equal_i(0x65, response_msg[236]);
	cl_assert_equal_i(0x00, response_msg[237]);
	cl_assert_equal_i(0x72, response_msg[238]);
	cl_assert_equal_i(0x00, response_msg[239]);
	cl_assert_equal_i(0x76, response_msg[240]);
	cl_assert_equal_i(0x00, response_msg[241]);
	cl_assert_equal_i(0x65, response_msg[242]);
	cl_assert_equal_i(0x00, response_msg[243]);
	cl_assert_equal_i(0x72, response_msg[244]);
	cl_assert_equal_i(0x00, response_msg[245]);
	cl_assert_equal_i(0x2e, response_msg[246]);
	cl_assert_equal_i(0x00, response_msg[247]);
	cl_assert_equal_i(0x64, response_msg[248]);
	cl_assert_equal_i(0x00, response_msg[249]);
	cl_assert_equal_i(0x6f, response_msg[250]);
	cl_assert_equal_i(0x00, response_msg[251]);
	cl_assert_equal_i(0x6d, response_msg[252]);
	cl_assert_equal_i(0x00, response_msg[253]);
	cl_assert_equal_i(0x61, response_msg[254]);
	cl_assert_equal_i(0x00, response_msg[255]);
	cl_assert_equal_i(0x69, response_msg[256]);
	cl_assert_equal_i(0x00, response_msg[257]);
	cl_assert_equal_i(0x6e, response_msg[258]);
	cl_assert_equal_i(0x00, response_msg[259]);
	cl_assert_equal_i(0x2e, response_msg[260]);
	cl_assert_equal_i(0x00, response_msg[261]);
	cl_assert_equal_i(0x63, response_msg[262]);
	cl_assert_equal_i(0x00, response_msg[263]);
	cl_assert_equal_i(0x6f, response_msg[264]);
	cl_assert_equal_i(0x00, response_msg[265]);
	cl_assert_equal_i(0x6d, response_msg[266]);
	cl_assert_equal_i(0x00, response_msg[267]);
	cl_assert_equal_i(0x00, response_msg[268]);
	cl_assert_equal_i(0x00, response_msg[269]);
	cl_assert_equal_i(0x00, response_msg[270]);
	cl_assert_equal_i(0x00, response_msg[271]);
	cl_assert_equal_i(0x00, response_msg[272]);
	cl_assert_equal_i(0x00, response_msg[273]);
	cl_assert_equal_i(0x00, response_msg[274]);
	cl_assert_equal_i(0x00, response_msg[275]);

	ntlm_client_free(ntlm);
}
