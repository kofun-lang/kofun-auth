#include "kofun/auth.h"

int main(void) {
    KofunAuthPublicClient client = {
        .client_id = "desktop",
        .client_secret = "this field must not exist",
        .authorization_endpoint = "https://issuer.example/authorize",
        .redirect_uri = "haniwa://oauth/callback",
        .scope = "openid",
    };
    return client.client_id == 0;
}
