#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

int main() {
    EVP_PKEY_CTX *pctx;
    unsigned char key[32];
    size_t keylen = sizeof(key);
    const char *salt = "somesalt";
    const char *ikm = "inputkeymaterial";

    // 1. Создание контекста HKDF
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        printf("Error creating context\n");
        return 1;
    }

    // 2. Инициализация derive
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printf("Error init\n");
        return 1;
    }

    // 3. Настройка параметров
    if (
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, strlen(salt)) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, strlen(ikm)) <= 0
    ) {
        printf("Error setting parameters\n");
        return 1;
    }

    // 4. Первый вызов derive
    if (EVP_PKEY_derive(pctx, key, &keylen) <= 0) {
        printf("Error deriving key (first call)\n");
        return 1;
    }

    printf("First key: ");
    for (size_t i = 0; i < keylen; i++)
        printf("%02x", key[i]);
    printf("\n");

    // 5. Повторный вызов derive (без reinit)
    if (EVP_PKEY_derive(pctx, key, &keylen) <= 0) {
        printf("Error deriving key (second call) — context reused\n");
    } else {
        printf("Second key: ");
        for (size_t i = 0; i < keylen; i++)
            printf("%02x", key[i]);
        printf("\n");
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}
