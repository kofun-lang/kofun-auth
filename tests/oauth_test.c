#include "kofun/auth.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                             \
    do {                                                                               \
        if (!(condition)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);       \
            exit(1);                                                                   \
        }                                                                              \
    } while (0)

typedef struct ExchangeObservation {
    int calls;
    int fail;
    char code[32];
    char verifier[64];
} ExchangeObservation;

static KofunAuthError observe_exchange(void *context, const char *authorization_code,
                                       const char *pkce_verifier) {
    ExchangeObservation *observation = context;
    observation->calls += 1;
    snprintf(observation->code, sizeof(observation->code), "%s", authorization_code);
    snprintf(observation->verifier, sizeof(observation->verifier), "%s", pkce_verifier);
    return observation->fail ? KOFUN_AUTH_TOKEN_EXCHANGE_FAILED : KOFUN_AUTH_OK;
}

static void query_value(const char *url, const char *name, char *output,
                        size_t capacity) {
    char needle[64];
    snprintf(needle, sizeof(needle), "%s=", name);
    const char *start = strstr(url, needle);
    REQUIRE(start != NULL);
    start += strlen(needle);
    const char *end = strchr(start, '&');
    size_t length = end == NULL ? strlen(start) : (size_t)(end - start);
    REQUIRE(length + 1 <= capacity);
    memcpy(output, start, length);
    output[length] = '\0';
}

static void assert_base64url_43(const char *value) {
    REQUIRE(strlen(value) == 43);
    for (const char *cursor = value; *cursor != '\0'; cursor += 1) {
        int valid =
            (*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
            (*cursor >= '0' && *cursor <= '9') || *cursor == '-' || *cursor == '_';
        REQUIRE(valid);
    }
}

static void challenge_for_verifier(const char *verifier, char output[64]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    REQUIRE(EVP_Digest(verifier, strlen(verifier), digest, &digest_length, EVP_sha256(),
                       NULL) == 1);
    REQUIRE(digest_length == 32);
    unsigned char encoded[64];
    int length = EVP_EncodeBlock(encoded, digest, digest_length);
    OPENSSL_cleanse(digest, sizeof(digest));
    REQUIRE(length == 44);
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
}

static KofunAuthPublicClient public_client(void) {
    KofunAuthPublicClient client = {
        .client_id = "desktop client",
        .authorization_endpoint = "https://issuer.example/authorize",
        .redirect_uri = "haniwa://oauth/callback",
        .scope = "openid profile",
    };
    return client;
}

static void authorization_url_has_mandatory_values(void) {
    KofunAuthPublicClient client = public_client();
    KofunAuthPending *pending = NULL;
    REQUIRE(kofun_auth_authorize(&client, &pending) == KOFUN_AUTH_OK);
    const char *url = kofun_auth_authorization_url(pending);
    REQUIRE(url != NULL);
    REQUIRE(strncmp(url, "https://issuer.example/authorize?", 33) == 0);
    REQUIRE(strstr(url, "response_type=code") != NULL);
    REQUIRE(strstr(url, "client_id=desktop%20client") != NULL);
    REQUIRE(strstr(url, "redirect_uri=haniwa%3A%2F%2Foauth%2Fcallback") != NULL);
    REQUIRE(strstr(url, "scope=openid%20profile") != NULL);
    REQUIRE(strstr(url, "code_challenge_method=S256") != NULL);
    REQUIRE(strstr(url, "client_secret") == NULL);

    char state[64];
    char nonce[64];
    char challenge[64];
    query_value(url, "state", state, sizeof(state));
    query_value(url, "nonce", nonce, sizeof(nonce));
    query_value(url, "code_challenge", challenge, sizeof(challenge));
    assert_base64url_43(state);
    assert_base64url_43(nonce);
    assert_base64url_43(challenge);
    kofun_auth_pending_free(pending);
}

static void state_is_checked_before_exchange(void) {
    KofunAuthPublicClient client = public_client();
    KofunAuthPending *pending = NULL;
    REQUIRE(kofun_auth_authorize(&client, &pending) == KOFUN_AUTH_OK);

    char state[64];
    query_value(kofun_auth_authorization_url(pending), "state", state, sizeof(state));
    char attacker_state[64];
    snprintf(attacker_state, sizeof(attacker_state), "%s", state);
    attacker_state[0] = attacker_state[0] == 'A' ? 'B' : 'A';

    ExchangeObservation observation = {0};
    REQUIRE(kofun_auth_exchange(pending, attacker_state, "code-1", observe_exchange,
                                &observation) == KOFUN_AUTH_STATE_MISMATCH);
    REQUIRE(observation.calls == 0);

    REQUIRE(kofun_auth_exchange(pending, state, "code-1", observe_exchange,
                                &observation) == KOFUN_AUTH_OK);
    REQUIRE(observation.calls == 1);
    REQUIRE(strcmp(observation.code, "code-1") == 0);
    assert_base64url_43(observation.verifier);
    char expected_challenge[64];
    char actual_challenge[64];
    challenge_for_verifier(observation.verifier, expected_challenge);
    query_value(kofun_auth_authorization_url(pending), "code_challenge",
                actual_challenge, sizeof(actual_challenge));
    REQUIRE(strcmp(expected_challenge, actual_challenge) == 0);

    REQUIRE(kofun_auth_exchange(pending, state, "code-2", observe_exchange,
                                &observation) == KOFUN_AUTH_ALREADY_EXCHANGED);
    REQUIRE(observation.calls == 1);
    kofun_auth_pending_free(pending);
}

static void callback_failure_still_consumes_code(void) {
    KofunAuthPublicClient client = public_client();
    KofunAuthPending *pending = NULL;
    REQUIRE(kofun_auth_authorize(&client, &pending) == KOFUN_AUTH_OK);
    char state[64];
    query_value(kofun_auth_authorization_url(pending), "state", state, sizeof(state));

    ExchangeObservation observation = {.fail = 1};
    REQUIRE(kofun_auth_exchange(pending, state, "burned", observe_exchange,
                                &observation) == KOFUN_AUTH_TOKEN_EXCHANGE_FAILED);
    observation.fail = 0;
    REQUIRE(kofun_auth_exchange(pending, state, "retry", observe_exchange,
                                &observation) == KOFUN_AUTH_ALREADY_EXCHANGED);
    REQUIRE(observation.calls == 1);
    kofun_auth_pending_free(pending);
}

static void insecure_endpoint_is_rejected(void) {
    KofunAuthPublicClient client = public_client();
    client.authorization_endpoint = "http://issuer.example/authorize";
    KofunAuthPending *pending = NULL;
    REQUIRE(kofun_auth_authorize(&client, &pending) ==
            KOFUN_AUTH_INSECURE_AUTHORIZATION_ENDPOINT);
    REQUIRE(pending == NULL);

    client.authorization_endpoint = "https:///missing-host";
    pending = (KofunAuthPending *)1;
    REQUIRE(kofun_auth_authorize(&client, &pending) ==
            KOFUN_AUTH_INSECURE_AUTHORIZATION_ENDPOINT);
    REQUIRE(pending == NULL);

    client.authorization_endpoint = "https://issuer.example/authorize#fragment";
    REQUIRE(kofun_auth_authorize(&client, &pending) ==
            KOFUN_AUTH_INSECURE_AUTHORIZATION_ENDPOINT);
    REQUIRE(pending == NULL);
}

static void endpoint_query_is_preserved(void) {
    KofunAuthPublicClient client = public_client();
    client.authorization_endpoint = "https://issuer.example/authorize?tenant=1";
    KofunAuthPending *pending = NULL;
    REQUIRE(kofun_auth_authorize(&client, &pending) == KOFUN_AUTH_OK);
    REQUIRE(strstr(kofun_auth_authorization_url(pending),
                   "?tenant=1&response_type=code") != NULL);
    kofun_auth_pending_free(pending);
}

int main(void) {
    authorization_url_has_mandatory_values();
    state_is_checked_before_exchange();
    callback_failure_still_consumes_code();
    insecure_endpoint_is_rejected();
    endpoint_query_is_preserved();
    puts("PASS: OAuth PKCE state-machine kernel");
    return 0;
}
