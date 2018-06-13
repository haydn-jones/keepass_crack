#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include "decrypt.h"
#include "keepcrack.h"

void decrypt_database(struct header_values_t hv)
{
        size_t length;
        char input[4096];
        unsigned char composite_key[SHA256_DIGEST_LENGTH];
        unsigned char transform_key[SHA256_DIGEST_LENGTH];
        unsigned char masterkey[SHA256_DIGEST_LENGTH];
        unsigned char streamstart[hv.streamstartbytes_len];
        EVP_CIPHER_CTX ctx;
        int i, out_len;

        printf("\nEnter passphrase: ");
        fgets(input, 4096, stdin);
        length = strnlen(input, 4096) - 1;
        input[length] = '\0';

        generate_composite_key(input, length, composite_key);
        printf("   [-] Composite key: ");
        print_hex_stream(composite_key, SHA256_DIGEST_LENGTH, 1);

        EVP_EncryptInit(&ctx, EVP_aes_256_ecb(), hv.transformseed, 0);
        memcpy(transform_key, composite_key, SHA256_DIGEST_LENGTH);

        for(i = 0; i < hv.transformrounds; i++) {
                EVP_EncryptUpdate(&ctx, transform_key, &out_len, transform_key, SHA256_DIGEST_LENGTH);
        }
        SHA256(transform_key, SHA256_DIGEST_LENGTH, transform_key);

        printf("   [-] Transformkey:  ");
        print_hex_stream(transform_key, SHA256_DIGEST_LENGTH, 1);

        generate_master_key(masterkey, transform_key, hv);
        printf("   [-] Masterkey:     ");
        print_hex_stream(masterkey, SHA256_DIGEST_LENGTH, 1);

        EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), masterkey, hv.encryptioniv);
        EVP_DecryptUpdate(&ctx, streamstart, &out_len, hv.payload, hv.streamstartbytes_len);
        printf("   [-] Dec. Payload:  ");
        print_hex_stream(streamstart, hv.streamstartbytes_len, 1);

        if (!verify_decrypt(hv.streamstartbytes, streamstart, hv.streamstartbytes_len)) {
                printf("   [+] Successful decryption!\n");
        } else {
                printf("   [!] Failed to decrypt!\n");
        }
}

/* TODO
 * This is where you hash all keys then concatenate keys in the order: passphrase, keyfile, WUA
 * then rehash
 **/
int generate_composite_key(const char *passwd, int pw_len, unsigned char *composite_key)
{
        unsigned char passwd_hash[SHA256_DIGEST_LENGTH];

        printf("   [-] Hash:          ");
        SHA256((unsigned char *)passwd, pw_len, passwd_hash);
        print_hex_stream(passwd_hash, SHA256_DIGEST_LENGTH, 1);

        SHA256(passwd_hash, SHA256_DIGEST_LENGTH, composite_key);

        return 0;
}

int generate_master_key(unsigned char *mkey, const unsigned char *tnsfrm_key, struct header_values_t hv)
{
        memcpy(mkey, hv.masterseed, hv.masterseed_len);
        memcpy(mkey + hv.masterseed_len, tnsfrm_key, SHA256_DIGEST_LENGTH);
        SHA256(mkey, hv.masterseed_len + SHA256_DIGEST_LENGTH, mkey);

        return 0;
}

int verify_decrypt(const unsigned char *streamstartbytes, const unsigned char *dec_payload, uint16_t len)
{
        while (len--) {
                if (streamstartbytes[len] != dec_payload[len]) {
                        return 1;
                }
        }

        return 0;
}

