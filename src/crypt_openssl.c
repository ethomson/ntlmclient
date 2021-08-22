/*
 * Copyright (c) Edward Thomson.  All rights reserved.
 *
 * This file is part of ntlmclient, distributed under the MIT license.
 * For full terms and copyright information, and for third-party
 * copyright information, see the included LICENSE.txt file.
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "ntlm.h"
#include "compat.h"
#include "util.h"
#include "crypt.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static inline HMAC_CTX *HMAC_CTX_new(void)
{
	return calloc(1, sizeof(HMAC_CTX));
}

static inline int HMAC_CTX_reset(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
	ntlm_memzero(ctx, sizeof(HMAC_CTX));
	return 1;
}

static inline void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx)
		HMAC_CTX_cleanup(ctx);

	free(ctx);
}
#endif

bool ntlm_crypt_init(ntlm_client *ntlm)
{
	return ((ntlm->crypt_ctx.hmac = HMAC_CTX_new()) != NULL);
}

bool ntlm_random_bytes(
	unsigned char *out,
	ntlm_client *ntlm,
	size_t len)
{
	int rc = RAND_bytes(out, len);

	if (rc != 1) {
		ntlm_client_set_errmsg(ntlm, ERR_lib_error_string(ERR_get_error()));
		return false;
	}

	return true;
}

bool ntlm_des_encrypt(
	ntlm_des_block *out,
	ntlm_client *ntlm,
	ntlm_des_block *plaintext,
	ntlm_des_block *key)
{
	DES_key_schedule keysched;

	NTLM_UNUSED(ntlm);

	memset(out, 0, sizeof(ntlm_des_block));

	DES_set_key(key, &keysched);
	DES_ecb_encrypt(plaintext, out, &keysched, DES_ENCRYPT);

	return true;
}

bool ntlm_md4_digest(
	unsigned char out[CRYPT_MD4_DIGESTSIZE],
	ntlm_client *ntlm,
	const unsigned char *in,
	size_t in_len)
{
	NTLM_UNUSED(ntlm);
	MD4(in, in_len, out);
	return true;
}

bool ntlm_hmac_md5_init(
	ntlm_client *ntlm,
	const unsigned char *key,
	size_t key_len)
{
	return HMAC_CTX_reset(ntlm->crypt_ctx.hmac) &&
	       HMAC_Init_ex(ntlm->crypt_ctx.hmac, key, key_len, EVP_md5(), NULL);
}

bool ntlm_hmac_md5_update(
	ntlm_client *ntlm,
	const unsigned char *in,
	size_t in_len)
{
	return HMAC_Update(ntlm->crypt_ctx.hmac, in, in_len);
}

bool ntlm_hmac_md5_final(
	unsigned char *out,
	size_t *out_len,
	ntlm_client *ntlm)
{
	unsigned int len;

	if (*out_len < CRYPT_MD5_DIGESTSIZE)
		return false;

	if (!HMAC_Final(ntlm->crypt_ctx.hmac, out, &len))
		return false;

	*out_len = len;
	return true;
}

void ntlm_crypt_shutdown(ntlm_client *ntlm)
{
	HMAC_CTX_free(ntlm->crypt_ctx.hmac);
	ntlm->crypt_ctx.hmac = NULL;
}
