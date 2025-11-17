//
// Type 6 decoder, largely based on information found in
//
//   https://github.com/CiscoDevNet/Type-6-Password-Encode/
//
// This is basically a decode-only C variant of the encode6.py found there.
//
// Usage:
//   decrypt_type6 <master_key> <encrypted_password>
//
// Compile:
//   cc -std=c99 -o decrypt_type6 decrypt_type6.c -lcrypto
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <openssl/md5.h>
#include <openssl/aes.h>
#endif

#define TYPE6_SALT_LEN 8
#define TYPE6_MAC_LEN 4

static __inline__ int base41_decode_block(const char *in, uint8_t *out)
{
    int val = 0;
    for (int i = 0; i < 3; i++) {
	if (in[i] < 'A')
		return -1;
	val *= 41;
	val += in[i] - 'A';
    }
    out[0] = (val >> 8) & 0xFF;
    out[1] = val & 0xFF;
    return 0;
}

static __inline__ int base41_decode(const char *in, uint8_t *out, size_t *out_len)
{
    size_t in_len = strlen(in);
    if (in_len % 3)
	return -1;

    size_t j = 0;
    for (size_t i = 0; i < in_len; i += 3) {
	if (base41_decode_block(in + i, out + j))
	    return -1;
	j += 2;
    }

    if (j < 4)
	return -1;
    if (!out[j - 1])
	j -= 1;
    else if (out[j - 1] == 1 && !out[j - 2])
	j -= 2;
    *out_len = j;
    return 0;
}

static void calculate_md5(const char *input, uint8_t *output)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000
    MD5((const unsigned char *) input, strlen(input), output);
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx) {
	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
	EVP_DigestUpdate(ctx, input, strlen(input));
	EVP_DigestFinal_ex(ctx, output, NULL);
	EVP_MD_CTX_free(ctx);
    }
#endif
}

static void aes_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(in, out, &aes_key);
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int out_len;
    EVP_EncryptUpdate(ctx, out, &out_len, in, 16);

    int final_len;
    EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);

    EVP_CIPHER_CTX_free(ctx);
#endif
}

static int verify_mac(const uint8_t *data, size_t data_len, const char *master_key)
{
    if (data_len < TYPE6_SALT_LEN + TYPE6_MAC_LEN)
	return -1;

    size_t enc_len = data_len - TYPE6_SALT_LEN - TYPE6_MAC_LEN;
    const uint8_t *salt = data;
    const uint8_t *encrypted = data + TYPE6_SALT_LEN;
    const uint8_t *mac = data + TYPE6_SALT_LEN + enc_len;

    uint8_t md5_digest[16];
    calculate_md5(master_key, md5_digest);

    uint8_t ka_input[16] = { 0 };
    memcpy(ka_input, salt, TYPE6_SALT_LEN);

    uint8_t ka[16];
    aes_ecb_encrypt(md5_digest, ka_input, ka);

    unsigned int hmac_len;
    uint8_t *digest = HMAC(EVP_sha1(), ka, 16, encrypted, enc_len, NULL, &hmac_len);
    if (!digest)
	return -1;

    return memcmp(digest, mac, TYPE6_MAC_LEN);
}

static char *decrypt_type6(const char *encoded, const char *master_key)
{
    uint8_t decoded[1024];
    uint8_t md5_digest[16];
    size_t decoded_len = 0;

    if (base41_decode(encoded, decoded, &decoded_len) || verify_mac(decoded, decoded_len, master_key))
	return NULL;
    calculate_md5(master_key, md5_digest);

    const uint8_t *salt = decoded;
    size_t enc_len = decoded_len - TYPE6_SALT_LEN - TYPE6_MAC_LEN;
    const uint8_t *encrypted_password = decoded + TYPE6_SALT_LEN;

    uint8_t ke_input[16] = { 0 };
    memcpy(ke_input, salt, TYPE6_SALT_LEN);
    ke_input[15] = 0x01;

    uint8_t ke[16];
    aes_ecb_encrypt(md5_digest, ke_input, ke);

#if OPENSSL_VERSION_NUMBER < 0x30000000
    AES_KEY aes_ke;
    AES_set_encrypt_key(ke, 128, &aes_ke);
#else
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, ke, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
#endif

    char *output = malloc(enc_len + 1);
    if (!output)
	return NULL;

    uint8_t ke_block[16] = { 0 };

    for (size_t i = 0; i < enc_len; ++i) {
	if (i % 16 == 0) {
	    uint8_t counter_block[16] = { 0 };
	    counter_block[3] = (uint8_t) (i / 16);
#if OPENSSL_VERSION_NUMBER < 0x30000000
	    AES_encrypt(counter_block, ke_block, &aes_ke);
#else
	    int out_len;
	    EVP_EncryptUpdate(ctx, ke_block, &out_len, counter_block, 16);
#endif
	}
	output[i] = encrypted_password[i] ^ ke_block[i % 16];
    }

    output[enc_len] = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000
    EVP_CIPHER_CTX_free(ctx);
#endif
    return output;
}

int main(int argc, char **argv)
{
    char *enc_pass_dflt = "XOUDEUYHeLGdB`UAZKX\\GK[iEgCWMZXEXN^dTGZ[UAAAB";
    char *master_key_dflt = "mySecretMasterkey";
    char *enc_pass = enc_pass_dflt;
    char *master_key = master_key_dflt;

    if (argc == 3) {
	master_key = argv[1];
	enc_pass = argv[2];
    } else {
	printf("Usage: %s <master_key> <encrypted_password>\n", argv[0]);
	printf("Example:\n# %s '%s' '%s'\n", argv[0], master_key_dflt, enc_pass_dflt);
    }

    char *decrypted = decrypt_type6(enc_pass, master_key);
    if (decrypted) {
	printf("Decrypted password: '%s'\n", decrypted);
	free(decrypted);
	exit(0);
    }

    fprintf(stderr, "Decryption failed.\n");
    exit(-1);
}
