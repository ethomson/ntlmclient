#include "ntlm_tests.h"

#include <string.h>

static ntlm_client *ntlm;

void test_unicode__initialize(void)
{
	cl_assert(ntlm = ntlm_client_init(NTLM_CLIENT_DEFAULTS));
	cl_assert(ntlm_unicode_init(ntlm));
}

void test_unicode__cleanup(void)
{
	ntlm_client_free(ntlm);
}

static inline void assert_utf16_to_8(
	ntlm_client *ntlm, char *utf8_expected, const char *utf16, size_t utf16_len)
{
	char *utf8;
	size_t utf8_len;

	cl_assert(ntlm_unicode_utf16_to_8(&utf8, &utf8_len, ntlm, utf16, utf16_len));
	cl_assert(!strcmp(utf8_expected, utf8));

	free(utf8);
}

static int utf16cmp(const char *a, const char *b)
{
	while ((*a || *(a+1)) && (*b || *(b+1))) {
		if (*a != *b)
			return *a - *b;
		if (*(a+1) != *(b+1))
			return *(a+1) - *(b+1);

		a += 2;
		b += 2;
	}

	return 0;
}

static inline void assert_utf8_to_16(
	ntlm_client *ntlm, char *utf16_expected, const char *utf8, size_t utf8_len)
{
	char *utf16;
	size_t utf16_len;

	cl_assert(ntlm_unicode_utf8_to_16(&utf16, &utf16_len, ntlm, utf8, utf8_len));
	cl_assert(!utf16cmp(utf16_expected, utf16));

	free(utf16);
}

void test_unicode__utf16to8_accepts_null(void)
{
	assert_utf16_to_8(ntlm, "", NULL, 0);
}

void test_unicode__utf16to8_zero_length_string(void)
{
	assert_utf16_to_8(ntlm, "", "", 0);
}

void test_unicode__utf16to8_simple(void)
{
	char a[] =         { 'a', 0, };
	char ab[] =        { 'a', 0, 'b', 0 };
	char abc[] =       { 'a', 0, 'b', 0, 'c', 0 };
	char abcd[] =      { 'a', 0, 'b', 0, 'c', 0, 'd', 0 };
	char abcde[] =     { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0 };
	char abcdef[] =    { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0 };
	char abcdefg[] =   { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 'g', 0 };
	char abcdefgh[] =  { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 'g', 0, 'h', 0 };
	char abcdefghi[] = { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 'g', 0, 'h', 0, 'i', 0 };

	assert_utf16_to_8(ntlm, "a", a, sizeof(a));
	assert_utf16_to_8(ntlm, "ab", ab, sizeof(ab));
	assert_utf16_to_8(ntlm, "abc", abc, sizeof(abc));
	assert_utf16_to_8(ntlm, "abcd", abcd, sizeof(abcd));
	assert_utf16_to_8(ntlm, "abcde", abcde, sizeof(abcde));
	assert_utf16_to_8(ntlm, "abcdef", abcdef, sizeof(abcdef));
	assert_utf16_to_8(ntlm, "abcdefg", abcdefg, sizeof(abcdefg));
	assert_utf16_to_8(ntlm, "abcdefgh", abcdefgh, sizeof(abcdefgh));
	assert_utf16_to_8(ntlm, "abcdefghi", abcdefghi, sizeof(abcdefghi));
}

void test_unicode__utf16to8_honors_length(void)
{
	char abcdefghijklmnop[] = {
		'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0,
		'g', 0, 'h', 0, 'i', 0, 'j', 0, 'k', 0, 'l', 0,
		'm', 0, 'n', 0, 'o', 0, 'p', 0 };

	assert_utf16_to_8(ntlm, "abcde", abcdefghijklmnop, 10);
}

void test_unicode__utf16to8_convers_nul(void)
{
	char utf16[] = { 'a', 0, 'b', 0, 0, 0, 'd', 0, 'e', 0 };
	char *utf8;
	size_t utf8_len;

	cl_assert(ntlm_unicode_utf16_to_8(&utf8, &utf8_len, ntlm, utf16, sizeof(utf16)));
	cl_assert_equal_i(5, utf8_len);
	cl_assert(!memcmp("ab\0de", utf8, 5));

	free(utf8);
}


void test_unicode__utf8to16_accepts_null(void)
{
	char str[] = { 0, 0 };

	assert_utf8_to_16(ntlm, str, NULL, 0);
}

void test_unicode__utf8to16_zero_length_string(void)
{
	char str[] = { 0, 0 };

	assert_utf8_to_16(ntlm, str, "", 0);
}

void test_unicode__utf8to16_simple(void)
{
	char a[] =         { 'a', 0, 0, 0 };
	char ab[] =        { 'a', 0, 'b', 0, 0, 0 };
	char abc[] =       { 'a', 0, 'b', 0, 'c', 0, 0, 0 };
	char abcd[] =      { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 0, 0 };
	char abcde[] =     { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 0, 0 };
	char abcdef[] =    { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 0, 0 };
	char abcdefg[] =   { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 'g', 0, 0, 0 };
	char abcdefgh[] =  { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 'g', 0, 'h', 0, 0, 0 };
	char abcdefghi[] = { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 'f', 0, 'g', 0, 'h', 0, 'i', 0, 0, 0 };

	assert_utf8_to_16(ntlm, a, "a", 1);
	assert_utf8_to_16(ntlm, ab, "ab", 2);
	assert_utf8_to_16(ntlm, abc, "abc", 3);
	assert_utf8_to_16(ntlm, abcd, "abcd", 4);
	assert_utf8_to_16(ntlm, abcde, "abcde", 5);
	assert_utf8_to_16(ntlm, abcdef, "abcdef", 6);
	assert_utf8_to_16(ntlm, abcdefg, "abcdefg", 7);
	assert_utf8_to_16(ntlm, abcdefgh, "abcdefgh", 8);
	assert_utf8_to_16(ntlm, abcdefghi, "abcdefghi", 9);
}

void test_unicode__utf8to16_honors_length(void)
{
	char abcde[] = { 'a', 0, 'b', 0, 'c', 0, 'd', 0, 'e', 0, 0, 0};

	assert_utf8_to_16(ntlm, abcde, "abcdefghijklmnop", 5);
}

void test_unicode__utf8to16_convers_nul(void)
{
	char utf16_expected[] = { 'a', 0, 'b', 0, 0, 0, 'd', 0, 'e', 0 };
	char *utf16;
	size_t utf16_len;

	cl_assert(ntlm_unicode_utf8_to_16(&utf16, &utf16_len, ntlm, "ab\0de", 5));
	cl_assert_equal_i(sizeof(utf16_expected), utf16_len);
	cl_assert(!memcmp(utf16_expected, utf16, utf16_len));

	free(utf16);
}
