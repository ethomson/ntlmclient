/*
 * Copyright (c) Edward Thomson.  All rights reserved.
 *
 * This file is part of ntlmclient, distributed under the MIT license.
 * For full terms and copyright information, and for third-party
 * copyright information, see the included LICENSE.txt file.
 */

#include <stdlib.h>
#include <string.h>

#ifndef CRYPT_OPENSSL_DYNAMIC
# include <openssl/rand.h>
# include <openssl/des.h>
# include <openssl/md4.h>
# include <openssl/hmac.h>
# include <openssl/err.h>
#endif

#include "ntlm.h"
#include "compat.h"
#include "util.h"
#include "crypt.h"

#ifdef CRYPT_OPENSSL_DYNAMIC
# include <dlfcn.h>
# include <pthread.h>

# define DES_ENCRYPT 1

static pthread_once_t openssl_lock = PTHREAD_ONCE_INIT;
static void *openssl_handle = NULL;

typedef unsigned char DES_cblock[8];

typedef struct {
	union {
		DES_cblock cblock;
		unsigned int deslong[2];
	} ks[16];
} DES_key_schedule;

void (*DES_ecb_encrypt)(const DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc);
int (*DES_set_key)(const DES_cblock *key, DES_key_schedule *schedule);
unsigned long (*ERR_get_error)(void);
const char *(*ERR_lib_error_string)(unsigned long e);
const EVP_MD *(*EVP_md5)(void);
void (*HMAC_CTX_cleanup)(HMAC_CTX *ctx);
HMAC_CTX *(*HMAC_CTX_new)(void);
int (*HMAC_CTX_reset)(HMAC_CTX *ctx);
void (*HMAC_CTX_free)(HMAC_CTX *ctx);
int (*HMAC_Init_ex)(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int (*HMAC_Update)(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int (*HMAC_Final)(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
unsigned char (*MD4)(const unsigned char *d, size_t n, unsigned char *md);
int (*RAND_bytes)(unsigned char *buf, int num);

static inline void HMAC_CTX_free__legacy(HMAC_CTX *ctx);
static inline int HMAC_CTX_reset__legacy(HMAC_CTX *ctx);
static inline HMAC_CTX *HMAC_CTX_new__legacy(void);

static void openssl_load(void)
{
	if ((openssl_handle = dlopen("libssl.so.1.1", RTLD_NOW)) == NULL &&
	    (openssl_handle = dlopen("libssl.so.10", RTLD_NOW)) == NULL)
		goto on_error;

	DES_ecb_encrypt = (void (*)(const DES_cblock *, DES_cblock *, DES_key_schedule *, int))dlsym(openssl_handle, "DES_ecb_encrypt");
	DES_set_key = (int (*)(const DES_cblock *, DES_key_schedule *))dlsym(openssl_handle, "DES_set_key");
	ERR_get_error = (unsigned long (*)(void))dlsym(openssl_handle, "ERR_get_error");
	ERR_lib_error_string = (const char *(*)(unsigned long e))dlsym(openssl_handle, "ERR_lib_error_string");
	EVP_md5 = (const EVP_MD *(*)(void))dlsym(openssl_handle, "EVP_md5");
	HMAC_CTX_cleanup = (void (*)(HMAC_CTX *ctx))dlsym(openssl_handle, "HMAC_CTX_cleanup");
	HMAC_CTX_new = (HMAC_CTX *(*)(void))dlsym(openssl_handle, "HMAC_CTX_new");
	HMAC_CTX_free = (void (*)(HMAC_CTX *ctx))dlsym(openssl_handle, "HMAC_CTX_free");
	HMAC_CTX_reset = (int (*)(HMAC_CTX *ctx))dlsym(openssl_handle, "HMAC_CTX_reset");
	HMAC_Final = (int (*)(HMAC_CTX *, unsigned char *, unsigned int *))dlsym(openssl_handle, "HMAC_Final");
	HMAC_Init_ex = (int (*)(HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *))dlsym(openssl_handle, "HMAC_Init_ex");
	HMAC_Update = (int (*)(HMAC_CTX *, const unsigned char *, size_t))dlsym(openssl_handle, "HMAC_Update");
	MD4 = (unsigned char (*)(const unsigned char *, size_t, unsigned char *))dlsym(openssl_handle, "MD4");
	RAND_bytes = (int (*)(unsigned char *, int))dlsym(openssl_handle, "RAND_bytes");

	if (!DES_ecb_encrypt || !DES_set_key || !ERR_get_error ||
	    !ERR_lib_error_string || !EVP_md5 ||
		!HMAC_Final || !HMAC_Init_ex || !HMAC_Update || !MD4 || !RAND_bytes)
		goto on_error;

	if (!HMAC_CTX_new)
		HMAC_CTX_new = HMAC_CTX_new__legacy;

	if (!HMAC_CTX_free) {
		if (!HMAC_CTX_cleanup)
			goto on_error;

		HMAC_CTX_free = HMAC_CTX_free__legacy;
	}

	if (!HMAC_CTX_reset) {
		if (!HMAC_CTX_cleanup)
			goto on_error;

		HMAC_CTX_reset = HMAC_CTX_reset__legacy;
	}

	return;

on_error:
	if (openssl_handle)
		dlclose(openssl_handle);

	openssl_handle = NULL;
	return;
}

static bool openssl_init(void)
{
	if (pthread_once(&openssl_lock, openssl_load) != 0 || !openssl_handle)
		return false;

	return true;
}
#else
static bool openssl_init(void)
{
	return true;
}
#endif

bool ntlm_random_bytes(
	ntlm_client *ntlm,
	unsigned char *out,
	size_t len)
{
	int rc;

	if (!openssl_init())
		return false;

	rc = RAND_bytes(out, len);

	if (rc != 1) {
		ntlm_client_set_errmsg(ntlm, ERR_lib_error_string(ERR_get_error()));
		return false;
	}

	return true;
}

bool ntlm_des_encrypt(
	ntlm_des_block *out,
	ntlm_des_block *plaintext,
	ntlm_des_block *key)
{
	DES_key_schedule keysched;

	if (!openssl_init())
		return false;

	memset(out, 0, sizeof(ntlm_des_block));

	DES_set_key(key, &keysched);
	DES_ecb_encrypt(plaintext, out, &keysched, DES_ENCRYPT);

	return true;
}

bool ntlm_md4_digest(
	unsigned char out[CRYPT_MD4_DIGESTSIZE],
	const unsigned char *in,
	size_t in_len)
{
	if (!openssl_init())
		return false;

	MD4(in, in_len, out);
	return true;
}

#if defined(CRYPT_OPENSSL_DYNAMIC) || OPENSSL_VERSION_NUMBER < 0x10100000L
static inline void HMAC_CTX_free__legacy(HMAC_CTX *ctx)
{
	if (ctx)
		HMAC_CTX_cleanup(ctx);

	free(ctx);
}

static inline int HMAC_CTX_reset__legacy(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
	ntlm_memzero(ctx, sizeof(HMAC_CTX));
	return 1;
}

static inline HMAC_CTX *HMAC_CTX_new__legacy(void)
{
	return calloc(1, sizeof(HMAC_CTX));
}
#endif

#if !defined(CRYPT_OPENSSL_DYNAMIC) && OPENSSL_VERSION_NUMBER < 0x10100000L
# define HMAC_CTX_new HMAC_CTX_new__legacy
# define HMAC_CTX_reset HMAC_CTX_reset__legacy
# define HMAC_CTX_free HMAC_CTX_free__legacy
#endif

ntlm_hmac_ctx *ntlm_hmac_ctx_init(void)
{
	if (!openssl_init())
		return NULL;

	return HMAC_CTX_new();
}

bool ntlm_hmac_ctx_reset(ntlm_hmac_ctx *ctx)
{
	if (!openssl_init())
		return false;

	return HMAC_CTX_reset(ctx);
}

bool ntlm_hmac_md5_init(
	ntlm_hmac_ctx *ctx,
	const unsigned char *key,
	size_t key_len)
{
	if (!openssl_init())
		return false;

	return HMAC_Init_ex(ctx, key, key_len, EVP_md5(), NULL);
}

bool ntlm_hmac_md5_update(
	ntlm_hmac_ctx *ctx,
	const unsigned char *in,
	size_t in_len)
{
	if (!openssl_init())
		return false;

	return HMAC_Update(ctx, in, in_len);
}

bool ntlm_hmac_md5_final(
	unsigned char *out,
	size_t *out_len,
	ntlm_hmac_ctx *ctx)
{
	unsigned int len;

	if (!openssl_init())
		return false;

	if (*out_len < CRYPT_MD5_DIGESTSIZE)
		return false;

	if (!HMAC_Final(ctx, out, &len))
		return false;

	*out_len = len;
	return true;
}

void ntlm_hmac_ctx_free(ntlm_hmac_ctx *ctx)
{
	openssl_init();
	HMAC_CTX_free(ctx);
}
