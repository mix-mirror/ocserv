/*
 * Copyright (C) 2026 Konstantin Satvaldyev
 *
 * This file is part of ocserv.
 *
 * ocserv is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The client's side of the external browser mode, for the test suite.
 *
 * A client asking for an external browser sends a P-256 public key in
 * X-AnyConnect-STRAP-DH-Pubkey, and receives the token encrypted to it:
 * ECDH with an ephemeral key of the server, HKDF-SHA256 with the info
 * "AC_ECIES", and AES-256-GCM, packed as a marker followed by
 * tag-length-value records, in base64. This is written from the client's
 * point of view, as openconnect's hpke.c does it, so that the test checks
 * the server against the format rather than against itself.
 *
 *   oidc-strap-client keygen <keyfile>
 *	generates a key, stores it in <keyfile> and prints the public part
 *	as the header carries it
 *   oidc-strap-client decrypt <keyfile> <blob>
 *	prints the token in <blob>, or fails if it cannot be decrypted
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#define TAG_PUBKEY 1
#define TAG_AEAD_TAG 2
#define TAG_CIPHERTEXT 3
#define TAG_IV 4
#define AEAD_TAG_SIZE 12
#define KEY_SIZE 32

static int keygen(const char *keyfile)
{
	gnutls_x509_privkey_t x509 = NULL;
	gnutls_privkey_t priv = NULL;
	gnutls_pubkey_t pub = NULL;
	gnutls_datum_t pem = { NULL, 0 };
	gnutls_datum_t der = { NULL, 0 };
	gnutls_datum_t b64 = { NULL, 0 };
	FILE *f;
	int ret = 1;

	if (gnutls_x509_privkey_init(&x509) < 0 ||
	    gnutls_x509_privkey_generate(
		    x509, GNUTLS_PK_EC,
		    GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0) < 0 ||
	    gnutls_x509_privkey_export2(x509, GNUTLS_X509_FMT_PEM, &pem) < 0)
		goto cleanup;

	f = fopen(keyfile, "w");
	if (f == NULL)
		goto cleanup;
	if (fwrite(pem.data, 1, pem.size, f) != pem.size) {
		fclose(f);
		goto cleanup;
	}
	fclose(f);

	/* the header carries the public key as DER, in base64 */
	if (gnutls_privkey_init(&priv) < 0 ||
	    gnutls_privkey_import_x509(priv, x509, 0) < 0 ||
	    gnutls_pubkey_init(&pub) < 0 ||
	    gnutls_pubkey_import_privkey(pub, priv, 0, 0) < 0 ||
	    gnutls_pubkey_export2(pub, GNUTLS_X509_FMT_DER, &der) < 0 ||
	    gnutls_base64_encode2(&der, &b64) < 0)
		goto cleanup;

	printf("%.*s\n", (int)b64.size, b64.data);
	ret = 0;

cleanup:
	gnutls_free(pem.data);
	gnutls_free(der.data);
	gnutls_free(b64.data);
	if (pub)
		gnutls_pubkey_deinit(pub);
	/* imported without GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE, so both go */
	if (priv)
		gnutls_privkey_deinit(priv);
	if (x509)
		gnutls_x509_privkey_deinit(x509);
	return ret;
}

/* Find the record with the given tag; returns 0 if it is there. */
static int find_record(const unsigned char *blob, size_t size, unsigned tag,
		       gnutls_datum_t *value)
{
	size_t pos = 2;

	while (pos + 4 <= size) {
		unsigned t = (blob[pos] << 8) | blob[pos + 1];
		unsigned len = (blob[pos + 2] << 8) | blob[pos + 3];

		if (pos + 4 + len > size)
			return -1;
		if (t == tag) {
			value->data = (unsigned char *)blob + pos + 4;
			value->size = len;
			return 0;
		}
		pos += 4 + len;
	}

	return -1;
}

static gnutls_privkey_t load_key(const char *keyfile)
{
	gnutls_privkey_t priv = NULL;
	gnutls_datum_t pem = { NULL, 0 };

	if (gnutls_load_file(keyfile, &pem) < 0)
		return NULL;

	if (gnutls_privkey_init(&priv) < 0 ||
	    gnutls_privkey_import_x509_raw(priv, &pem, GNUTLS_X509_FMT_PEM,
					   NULL, 0) < 0) {
		if (priv)
			gnutls_privkey_deinit(priv);
		priv = NULL;
	}

	gnutls_free(pem.data);
	return priv;
}

static int decrypt(const char *keyfile, const char *blob_b64)
{
	gnutls_privkey_t priv = NULL;
	gnutls_pubkey_t peer = NULL;
	gnutls_cipher_hd_t cipher = NULL;
	gnutls_datum_t in = { (unsigned char *)blob_b64, strlen(blob_b64) };
	gnutls_datum_t blob = { NULL, 0 };
	gnutls_datum_t secret = { NULL, 0 };
	gnutls_datum_t peer_der, tag, ct, iv;
	gnutls_datum_t prk_d, info_d, key_d;
	unsigned char prk[KEY_SIZE];
	unsigned char key[KEY_SIZE];
	unsigned char computed[AEAD_TAG_SIZE];
	unsigned char *pt = NULL;
	int ret = 1;

	if (gnutls_base64_decode2(&in, &blob) < 0 || blob.size < 2 ||
	    blob.data[0] != 0 || blob.data[1] != 1)
		goto cleanup;

	if (find_record(blob.data, blob.size, TAG_PUBKEY, &peer_der) < 0 ||
	    find_record(blob.data, blob.size, TAG_AEAD_TAG, &tag) < 0 ||
	    find_record(blob.data, blob.size, TAG_CIPHERTEXT, &ct) < 0 ||
	    find_record(blob.data, blob.size, TAG_IV, &iv) < 0 ||
	    tag.size != AEAD_TAG_SIZE)
		goto cleanup;

	priv = load_key(keyfile);
	if (priv == NULL)
		goto cleanup;

	if (gnutls_pubkey_init(&peer) < 0 ||
	    gnutls_pubkey_import(peer, &peer_der, GNUTLS_X509_FMT_DER) < 0 ||
	    gnutls_privkey_derive_secret(priv, peer, NULL, &secret, 0) < 0)
		goto cleanup;

	prk_d.data = prk;
	prk_d.size = sizeof(prk);
	info_d.data = (unsigned char *)"AC_ECIES";
	info_d.size = sizeof("AC_ECIES") - 1;
	if (gnutls_hkdf_extract(GNUTLS_MAC_SHA256, &secret, NULL, prk) < 0 ||
	    gnutls_hkdf_expand(GNUTLS_MAC_SHA256, &prk_d, &info_d, key,
			       sizeof(key)) < 0)
		goto cleanup;

	pt = malloc(ct.size + 1);
	if (pt == NULL)
		goto cleanup;

	key_d.data = key;
	key_d.size = sizeof(key);
	if (gnutls_cipher_init(&cipher, GNUTLS_CIPHER_AES_256_GCM, &key_d,
			       &iv) < 0 ||
	    gnutls_cipher_decrypt2(cipher, ct.data, ct.size, pt, ct.size) < 0 ||
	    gnutls_cipher_tag(cipher, computed, sizeof(computed)) < 0)
		goto cleanup;

	/* the tag is truncated to 12 bytes */
	if (gnutls_memcmp(computed, tag.data, AEAD_TAG_SIZE) != 0)
		goto cleanup;

	pt[ct.size] = 0;
	printf("%s\n", pt);
	ret = 0;

cleanup:
	if (cipher)
		gnutls_cipher_deinit(cipher);
	if (peer)
		gnutls_pubkey_deinit(peer);
	if (priv)
		gnutls_privkey_deinit(priv);
	gnutls_free(secret.data);
	gnutls_free(blob.data);
	free(pt);
	return ret;
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "keygen") == 0)
		return keygen(argv[2]);
	if (argc == 4 && strcmp(argv[1], "decrypt") == 0)
		return decrypt(argv[2], argv[3]);

	fprintf(stderr,
		"usage: %s keygen <keyfile>\n"
		"       %s decrypt <keyfile> <blob>\n",
		argv[0], argv[0]);
	return 2;
}
