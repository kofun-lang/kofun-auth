#ifndef KOFUN_AUTH_H
#define KOFUN_AUTH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum KofunAuthError {
    KOFUN_AUTH_OK = 0,
    KOFUN_AUTH_INVALID_ARGUMENT,
    KOFUN_AUTH_INSECURE_AUTHORIZATION_ENDPOINT,
    KOFUN_AUTH_RANDOM_FAILURE,
    KOFUN_AUTH_CRYPTO_FAILURE,
    KOFUN_AUTH_OUT_OF_MEMORY,
    KOFUN_AUTH_STATE_MISMATCH,
    KOFUN_AUTH_ALREADY_EXCHANGED,
    KOFUN_AUTH_TOKEN_EXCHANGE_FAILED,
} KofunAuthError;

/* Public clients deliberately have no client-secret field. */
typedef struct KofunAuthPublicClient {
    const char *client_id;
    const char *authorization_endpoint;
    const char *redirect_uri;
    const char *scope;
} KofunAuthPublicClient;

/* The layout is private: callers can receive Pending but cannot construct it. */
typedef struct KofunAuthPending KofunAuthPending;

typedef KofunAuthError (*KofunAuthTokenExchange)(void *context,
                                                 const char *authorization_code,
                                                 const char *pkce_verifier);

/* Starts an S256-only authorization flow with generated state and nonce. */
KofunAuthError kofun_auth_authorize(const KofunAuthPublicClient *client,
                                    KofunAuthPending **pending);

/* Returns the immutable authorization URL owned by pending. */
const char *kofun_auth_authorization_url(const KofunAuthPending *pending);

/*
 * Verifies state before invoking exchange. A matching state consumes pending
 * exactly once, even when the token endpoint callback fails.
 */
KofunAuthError kofun_auth_exchange(KofunAuthPending *pending,
                                   const char *returned_state,
                                   const char *authorization_code,
                                   KofunAuthTokenExchange exchange, void *context);

void kofun_auth_pending_free(KofunAuthPending *pending);
const char *kofun_auth_error_string(KofunAuthError error);

#ifdef __cplusplus
}
#endif

#endif
