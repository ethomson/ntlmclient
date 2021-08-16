/*
 * Copyright (c) Edward Thomson.  All rights reserved.
 *
 * This file is part of ntlmclient, distributed under the MIT license.
 * For full terms and copyright information, and for third-party
 * copyright information, see the included LICENSE.txt file.
 */

#ifndef PRIVATE_CRYPT_OPENSSL_H__
#define PRIVATE_CRYPT_OPENSSL_H__

#ifdef CRYPT_OPENSSL_DYNAMIC

# define HMAC_MAX_MD_CBLOCK 128

typedef void ENGINE;
typedef void EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef void EVP_PKEY_CTX;

struct env_md_ctx_st {
	const EVP_MD *digest;
	ENGINE *engine;
	unsigned long flags;
	void *md_data;
	EVP_PKEY_CTX *pctx;
	int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);
};

typedef struct {
	const EVP_MD *md;
	EVP_MD_CTX md_ctx;
	EVP_MD_CTX i_ctx;
	EVP_MD_CTX o_ctx;
	unsigned int key_length;
	unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;

typedef void ntlm_hmac_ctx;
#else
# include <openssl/hmac.h>

/* OpenSSL 1.1.0 uses opaque structs, we'll reuse these. */
# if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef struct hmac_ctx_st ntlm_hmac_ctx;
# else
#  define ntlm_hmac_ctx HMAC_CTX
# endif

#endif /* CRYPT_OPENSSL_DYNAMIC */

#endif /* PRIVATE_CRYPT_OPENSSL_H__ */
