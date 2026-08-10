#include "kofun/auth.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    KOFUN_AUTH_RANDOM_BYTES = 32,
    KOFUN_AUTH_BASE64URL_LENGTH = 43,
    KOFUN_AUTH_MAX_FIELD_LENGTH = 4096,
};

struct KofunAuthPending {
    char state[KOFUN_AUTH_BASE64URL_LENGTH + 1];
    char nonce[KOFUN_AUTH_BASE64URL_LENGTH + 1];
    char verifier[KOFUN_AUTH_BASE64URL_LENGTH + 1];
    char *authorization_url;
    atomic_bool exchanged;
};

static size_t bounded_length(const char *value, size_t maximum) {
    size_t length = 0;
    while (length <= maximum && value[length] != '\0') {
        length += 1;
    }
    return length;
}

static bool valid_field(const char *value) {
    if (value == NULL) {
        return false;
    }
    size_t length = bounded_length(value, KOFUN_AUTH_MAX_FIELD_LENGTH);
    return length > 0 && length <= KOFUN_AUTH_MAX_FIELD_LENGTH;
}

static bool is_https_url(const char *url) {
    if (!valid_field(url) || strncmp(url, "https://", 8) != 0) {
        return false;
    }
    const unsigned char *cursor = (const unsigned char *)url + 8;
    if (*cursor == '\0' || *cursor == '/' || *cursor == '?' || *cursor == '#') {
        return false;
    }
    for (; *cursor != '\0'; cursor += 1) {
        if (*cursor <= 0x20 || *cursor == 0x7f || *cursor == '#') {
            return false;
        }
    }
    return true;
}

static KofunAuthError random_base64url(char output[44]) {
    unsigned char random_bytes[KOFUN_AUTH_RANDOM_BYTES];
    unsigned char encoded[4 * ((KOFUN_AUTH_RANDOM_BYTES + 2) / 3) + 1];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
        return KOFUN_AUTH_RANDOM_FAILURE;
    }

    int length = EVP_EncodeBlock(encoded, random_bytes, sizeof(random_bytes));
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
    if (length != 44) {
        OPENSSL_cleanse(encoded, sizeof(encoded));
        return KOFUN_AUTH_CRYPTO_FAILURE;
    }
    for (int index = 0; index < length; index += 1) {
        if (encoded[index] == '+') {
            encoded[index] = '-';
        } else if (encoded[index] == '/') {
            encoded[index] = '_';
        }
    }
    while (length > 0 && encoded[length - 1] == '=') {
        length -= 1;
    }
    if (length != KOFUN_AUTH_BASE64URL_LENGTH) {
        OPENSSL_cleanse(encoded, sizeof(encoded));
        return KOFUN_AUTH_CRYPTO_FAILURE;
    }
    memcpy(output, encoded, (size_t)length);
    output[length] = '\0';
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return KOFUN_AUTH_OK;
}

static KofunAuthError challenge_for_verifier(const char *verifier, char output[44]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    if (EVP_Digest(verifier, strlen(verifier), digest, &digest_length, EVP_sha256(),
                   NULL) != 1 ||
        digest_length != KOFUN_AUTH_RANDOM_BYTES) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return KOFUN_AUTH_CRYPTO_FAILURE;
    }

    unsigned char encoded[45];
    int length = EVP_EncodeBlock(encoded, digest, digest_length);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (length != 44) {
        OPENSSL_cleanse(encoded, sizeof(encoded));
        return KOFUN_AUTH_CRYPTO_FAILURE;
    }
    for (int index = 0; index < length; index += 1) {
        if (encoded[index] == '+') {
            encoded[index] = '-';
        } else if (encoded[index] == '/') {
            encoded[index] = '_';
        }
    }
    while (length > 0 && encoded[length - 1] == '=') {
        length -= 1;
    }
    memcpy(output, encoded, (size_t)length);
    output[length] = '\0';
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return KOFUN_AUTH_OK;
}

static bool unreserved(unsigned char byte) {
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' ||
           byte == '~';
}

static char *percent_encode(const char *value) {
    static const char hex[] = "0123456789ABCDEF";
    size_t length = strlen(value);
    if (length > (SIZE_MAX - 1) / 3) {
        return NULL;
    }
    char *encoded = malloc(length * 3 + 1);
    if (encoded == NULL) {
        return NULL;
    }
    size_t cursor = 0;
    for (size_t index = 0; index < length; index += 1) {
        unsigned char byte = (unsigned char)value[index];
        if (unreserved(byte)) {
            encoded[cursor++] = (char)byte;
        } else {
            encoded[cursor++] = '%';
            encoded[cursor++] = hex[byte >> 4];
            encoded[cursor++] = hex[byte & 0x0f];
        }
    }
    encoded[cursor] = '\0';
    return encoded;
}

static KofunAuthError build_authorization_url(const KofunAuthPublicClient *client,
                                              const char *state, const char *nonce,
                                              const char *challenge, char **output) {
    static const char response_query[] = "response_type=code&client_id=";
    static const char separator_redirect[] = "&redirect_uri=";
    static const char separator_scope[] = "&scope=";
    static const char separator_state[] = "&state=";
    static const char separator_nonce[] = "&nonce=";
    static const char separator_challenge[] = "&code_challenge=";
    static const char suffix[] = "&code_challenge_method=S256";

    char *client_id = percent_encode(client->client_id);
    char *redirect_uri = percent_encode(client->redirect_uri);
    char *scope = percent_encode(client->scope);
    if (client_id == NULL || redirect_uri == NULL || scope == NULL) {
        free(client_id);
        free(redirect_uri);
        free(scope);
        return KOFUN_AUTH_OUT_OF_MEMORY;
    }

    size_t endpoint_length = strlen(client->authorization_endpoint);
    const char *query_separator = "?";
    if (strchr(client->authorization_endpoint, '?') != NULL) {
        char final = client->authorization_endpoint[endpoint_length - 1];
        query_separator = (final == '?' || final == '&') ? "" : "&";
    }
    size_t length = endpoint_length + strlen(query_separator) + strlen(response_query) +
                    strlen(client_id) + strlen(separator_redirect) +
                    strlen(redirect_uri) + strlen(separator_scope) + strlen(scope) +
                    strlen(separator_state) + strlen(state) + strlen(separator_nonce) +
                    strlen(nonce) + strlen(separator_challenge) + strlen(challenge) +
                    strlen(suffix) + 1;
    char *url = malloc(length);
    if (url == NULL) {
        free(client_id);
        free(redirect_uri);
        free(scope);
        return KOFUN_AUTH_OUT_OF_MEMORY;
    }

    char *cursor = url;
#define APPEND(value)                                                                  \
    do {                                                                               \
        size_t append_length = strlen(value);                                          \
        memcpy(cursor, value, append_length);                                          \
        cursor += append_length;                                                       \
    } while (0)
    APPEND(client->authorization_endpoint);
    APPEND(query_separator);
    APPEND(response_query);
    APPEND(client_id);
    APPEND(separator_redirect);
    APPEND(redirect_uri);
    APPEND(separator_scope);
    APPEND(scope);
    APPEND(separator_state);
    APPEND(state);
    APPEND(separator_nonce);
    APPEND(nonce);
    APPEND(separator_challenge);
    APPEND(challenge);
    APPEND(suffix);
#undef APPEND
    *cursor = '\0';

    free(client_id);
    free(redirect_uri);
    free(scope);
    *output = url;
    return KOFUN_AUTH_OK;
}

KofunAuthError kofun_auth_authorize(const KofunAuthPublicClient *client,
                                    KofunAuthPending **pending) {
    if (pending == NULL) {
        return KOFUN_AUTH_INVALID_ARGUMENT;
    }
    *pending = NULL;
    if (client == NULL || !valid_field(client->client_id) ||
        !valid_field(client->redirect_uri) || !valid_field(client->scope)) {
        return KOFUN_AUTH_INVALID_ARGUMENT;
    }
    if (!is_https_url(client->authorization_endpoint)) {
        return KOFUN_AUTH_INSECURE_AUTHORIZATION_ENDPOINT;
    }

    KofunAuthPending *created = calloc(1, sizeof(*created));
    if (created == NULL) {
        return KOFUN_AUTH_OUT_OF_MEMORY;
    }
    atomic_init(&created->exchanged, false);

    KofunAuthError error = random_base64url(created->state);
    if (error == KOFUN_AUTH_OK) {
        error = random_base64url(created->nonce);
    }
    if (error == KOFUN_AUTH_OK) {
        error = random_base64url(created->verifier);
    }
    char challenge[KOFUN_AUTH_BASE64URL_LENGTH + 1] = {0};
    if (error == KOFUN_AUTH_OK) {
        error = challenge_for_verifier(created->verifier, challenge);
    }
    if (error == KOFUN_AUTH_OK) {
        error = build_authorization_url(client, created->state, created->nonce,
                                        challenge, &created->authorization_url);
    }
    OPENSSL_cleanse(challenge, sizeof(challenge));
    if (error != KOFUN_AUTH_OK) {
        kofun_auth_pending_free(created);
        return error;
    }

    *pending = created;
    return KOFUN_AUTH_OK;
}

const char *kofun_auth_authorization_url(const KofunAuthPending *pending) {
    return pending == NULL ? NULL : pending->authorization_url;
}

KofunAuthError kofun_auth_exchange(KofunAuthPending *pending,
                                   const char *returned_state,
                                   const char *authorization_code,
                                   KofunAuthTokenExchange exchange, void *context) {
    if (pending == NULL || returned_state == NULL || !valid_field(authorization_code) ||
        exchange == NULL) {
        return KOFUN_AUTH_INVALID_ARGUMENT;
    }

    size_t expected_length = strlen(pending->state);
    size_t returned_length = bounded_length(returned_state, expected_length);
    if (returned_length != expected_length ||
        CRYPTO_memcmp(pending->state, returned_state, expected_length) != 0) {
        return KOFUN_AUTH_STATE_MISMATCH;
    }

    bool expected = false;
    if (!atomic_compare_exchange_strong(&pending->exchanged, &expected, true)) {
        return KOFUN_AUTH_ALREADY_EXCHANGED;
    }

    KofunAuthError result = exchange(context, authorization_code, pending->verifier);
    return result == KOFUN_AUTH_OK ? KOFUN_AUTH_OK : KOFUN_AUTH_TOKEN_EXCHANGE_FAILED;
}

void kofun_auth_pending_free(KofunAuthPending *pending) {
    if (pending == NULL) {
        return;
    }
    OPENSSL_cleanse(pending->state, sizeof(pending->state));
    OPENSSL_cleanse(pending->nonce, sizeof(pending->nonce));
    OPENSSL_cleanse(pending->verifier, sizeof(pending->verifier));
    free(pending->authorization_url);
    OPENSSL_cleanse(pending, sizeof(*pending));
    free(pending);
}

const char *kofun_auth_error_string(KofunAuthError error) {
    switch (error) {
    case KOFUN_AUTH_OK:
        return "ok";
    case KOFUN_AUTH_INVALID_ARGUMENT:
        return "invalid argument";
    case KOFUN_AUTH_INSECURE_AUTHORIZATION_ENDPOINT:
        return "authorization endpoint must use https";
    case KOFUN_AUTH_RANDOM_FAILURE:
        return "secure random generation failed";
    case KOFUN_AUTH_CRYPTO_FAILURE:
        return "cryptographic operation failed";
    case KOFUN_AUTH_OUT_OF_MEMORY:
        return "out of memory";
    case KOFUN_AUTH_STATE_MISMATCH:
        return "authorization state mismatch";
    case KOFUN_AUTH_ALREADY_EXCHANGED:
        return "authorization flow was already exchanged";
    case KOFUN_AUTH_TOKEN_EXCHANGE_FAILED:
        return "token exchange failed";
    default:
        return "unknown authentication error";
    }
}
