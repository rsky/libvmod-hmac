#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/opensslv.h>
#ifndef VMOD_HMAC_CLI
#include "vrt.h"
#include "bin/varnishd/cache.h"
#include "vcc_if.h"
#endif

static const char const hex[16] = "0123456789abcdef";

/* {{{ private function prototypes */

typedef char *(encode_func_t)(const unsigned char *, unsigned int);

static char *hmac(const EVP_MD *md,
                  const char *key, int key_len,
                  const unsigned char *data, int data_len,
                  encode_func_t encode);

static char *hmac_sha1(const char *key, const char *data, encode_func_t encode);
static char *hmac_sha256(const char *key, const char *data, encode_func_t encode);

static char *encode_base64(const unsigned char *digest, unsigned int len);
static char *encode_hex(const unsigned char *digest, unsigned int len);

#ifndef VMOD_HMAC_CLI
static char *vmod_hmac_finish(struct sess *sp, char *hash);
#endif

/* }}} */
#ifdef VMOD_HMAC_CLI
/* {{{ CLI */

int
main(int argc, const char *argv[])
{
	const char *key, *data;
	char *h[4];
	int i, e;

	if (argc != 3) {
		fprintf(stderr, "%s requires 2 arguments!\n", argv[0]);
		return -1;
	}

	key = argv[1];
	data = argv[2];

	h[0] = hmac_sha1(key, data, encode_hex);
	h[1] = hmac_sha1(key, data, encode_base64);
	h[2] = hmac_sha256(key, data, encode_hex);
	h[3] = hmac_sha256(key, data, encode_base64);

	e = 0;
	for (i = 0; i < 4; i++) {
		if (h[i]) {
			printf("%s\n", h[i]);
			free(h[i]);
		} else {
			printf("(NULL)\n");
			e++;
		}
	}

	return e;
}

/* }}}*/
#else
/* {{{ VMOD */

int
vmod_hmac_init(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return 0;
}

const char *
vmod_sha1_hex(struct sess *sp, const char *key, const char *data)
{
	return vmod_hmac_finish(sp, hmac_sha1(key, data, encode_hex));
}

const char *
vmod_sha1_base64(struct sess *sp, const char *key, const char *data)
{
	return vmod_hmac_finish(sp, hmac_sha1(key, data, encode_base64));
}

const char *
vmod_sha256_hex(struct sess *sp, const char *key, const char *data)
{
	return vmod_hmac_finish(sp, hmac_sha256(key, data, encode_hex));
}

const char *
vmod_sha256_base64(struct sess *sp, const char *key, const char *data)
{
	return vmod_hmac_finish(sp, hmac_sha256(key, data, encode_base64));
}

/* }}}*/
#endif
/* {{{ private function implementations */

static char *
hmac(const EVP_MD *md,
     const char *key, int key_len,
     const unsigned char *data, int data_len,
     encode_func_t encode)
{
	HMAC_CTX ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	char *h = NULL;
	unsigned int len = 0;

	HMAC_CTX_init(&ctx);
	HMAC_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_ONESHOT);
#if OPENSSL_VERSION_NUMBER < 0x100000afL
	HMAC_Init_ex(&ctx, key, key_len, md, NULL);
	HMAC_Update(&ctx, data, data_len);
	HMAC_Final(&ctx, digest, &len);
#else
	if (!HMAC_Init_ex(&ctx, key, key_len, md, NULL)) {
		HMAC_CTX_cleanup(&ctx);
		return NULL;
	}
	if (!HMAC_Update(&ctx, data, data_len)) {
		HMAC_CTX_cleanup(&ctx);
		return NULL;
	}
	if (!HMAC_Final(&ctx, digest, &len)) {
		HMAC_CTX_cleanup(&ctx);
		return NULL;
	}
#endif
	HMAC_CTX_cleanup(&ctx);

	if (encode != NULL) {
		h = encode(digest, len);
	} else {
		h = (char *)malloc(len + 1);
		if (h == NULL) {
			return NULL;
		}
		memcpy(h, md, len);
		h[len] = '\0';
	}

	return h;
}

static char *
hmac_sha1(const char *key, const char *data, encode_func_t encode)
{
	return hmac(EVP_sha1(), key, strlen(key),
	            (const unsigned char *)data, strlen(data), encode);
}

static char *
hmac_sha256(const char *key, const char *data, encode_func_t encode)
{
	return hmac(EVP_sha256(), key, strlen(key),
	            (const unsigned char *)data, strlen(data), encode);
}

static char *
encode_base64(const unsigned char *digest, unsigned int len)
{
	BIO *b64, *bmem, *wbio;
	BUF_MEM *bptr;
	char *buf;
	unsigned int siz;

	siz = ((len + 2) / 3) * 4 + 1;
	buf = (char *)malloc(siz);
	if (buf == NULL) {
		return NULL;
	}

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		free(buf);
		return NULL;
	}

	bmem = BIO_new(BIO_s_mem());
	if (bmem == NULL) {
		BIO_free(b64);
		free(buf);
		return NULL;
	}

	wbio = BIO_push(b64, bmem);
	BIO_write(wbio, digest, (int)len);
	(void)BIO_flush(wbio);
	BIO_get_mem_ptr(b64, &bptr);

	memcpy(buf, bptr->data, bptr->length - 1);
	buf[bptr->length - 1] = '\0';

	BIO_free(b64);
	BIO_free(bmem);

	return buf;
}

static char *
encode_hex(const unsigned char *digest, unsigned int len)
{
	char *buf, *ptr;
	unsigned int i, siz;

	siz = len * 2 + 1;
	buf = (char *)malloc(siz);
	if (buf == NULL) {
		return NULL;
	}
	ptr = buf;

	for (i = 0; i < len; i++) {
		unsigned int c = digest[i];
		*ptr++ = hex[c / 16U];
		*ptr++ = hex[c % 16U];
	}
	*ptr = '\0';

	return buf;
}

#ifndef VMOD_HMAC_CLI
static char *
vmod_hmac_finish(struct sess *sp, char *hash)
{
	char *p;
	unsigned int u, v;

	if (hash == NULL) {
		return NULL;
	}

	/* Reserve some work space */
	u = WS_Reserve(sp->wrk->ws, 0);
	/* Front of workspace area */
	p = sp->wrk->ws->f;
	v = snprintf(p, u, "%s", hash);
	v++;
	free(hash);

	if (v > u) {
		/* No space, reset and leave */
		WS_Release(sp->wrk->ws, 0);
		return NULL;
	}

	/* Update work space with what we've used */
	WS_Release(sp->wrk->ws, v);

	return p;
}
#endif

/* }}} */
