# kofun-auth

Authentication and authorization for [Kofun](https://github.com/kofun-lang/kofun):
OAuth 2.1 clients, OpenID Connect, PKCE, token storage, JWT, sessions, and TOTP.

> **Status: Stage 0 in progress.** The first executable OAuth 2.1/PKCE kernel
> enforces the critical state transition behind a C ABI. The protocol will move
> into Kofun once the compiler enforces cross-file opacity. Read
> [docs/DESIGN.md](docs/DESIGN.md) and
> [docs/STAGE0.md](docs/STAGE0.md).

## Build the Stage 0 OAuth kernel

The current slice needs CMake 3.24+, a C11 compiler, and OpenSSL 3.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The configure step also compiles two negative contracts: code outside the
library must not be able to add a client secret to `KofunAuthPublicClient` or
construct `KofunAuthPending` directly.

## Why this exists

Every ecosystem that reaches practical use grows this layer early, because
almost no real application avoids it. Go has `golang.org/x/oauth2` and `goth`;
Rust has `oauth2`, `oxide-auth`, and `openidconnect`. A language without a
credible auth story cannot host a real product, however good its compiler is.

The goal is not to be the biggest such library. It is to make the safe path the
short one:

- **PKCE always.** The implicit flow and the resource-owner password flow are
  not implemented, and will not be. The current OAuth 2.1 draft omits them,
  following the OAuth Security BCP.
- **No secrets in public clients.** A desktop or CLI client that is asked for a
  client secret is a configuration error, and the API says so at the type level.
- **State and nonce are not optional parameters.** They are generated and
  verified by the library; a caller cannot forget them.
- **Tokens go to platform storage.** Keychain, Credential Manager, and Secret
  Service, not a file in the home directory, not the web view.

## Planned surface

| Area | Contents |
|---|---|
| OAuth 2.1 | authorization code + PKCE, client credentials, device authorization (RFC 8628), refresh, revocation (RFC 7009), introspection (RFC 7662) |
| OpenID Connect | discovery, ID token validation, JWKS fetch and rotation, UserInfo |
| Tokens | JWT sign and verify (HS256, RS256, ES256, EdDSA), typed claims, clock-skew policy |
| Storage | platform keychains, encrypted file fallback, in-memory for tests |
| Sessions | signed cookies, server-side sessions, rotation on privilege change |
| Second factor | TOTP (RFC 6238), HOTP (RFC 4226), recovery codes |
| Passwords | Argon2id with sane parameters, verification, rehash-on-login |
| Authorization | role checks and a policy hook, deliberately small |
| Providers | discovery-driven, with tested profiles for GitHub, Google, Microsoft, and generic OIDC |

## Non-goals

- Not an identity provider. This is a client and a verifier, not a server that
  issues its own tokens for third parties.
- Not a user database. Storing users is the application's decision.
- Not a policy engine. Anything past role checks belongs in a separate project.

## Relationship to Haniwa

Desktop applications need a redirect target, which is platform work, not
protocol work. [Haniwa](https://github.com/kofun-lang/haniwa) owns loopback
listeners and custom-scheme deep links and hands the authorization code here.
This repository never opens a window.

## Status of the language underneath

Kofun is a research compiler with a small executable slice. Cryptographic
primitives are expected to be C-ABI shims for a long time; what moves into Kofun
first is the protocol state machine, which is exactly the part that benefits
from a type system checking it. Issues state which side of that line each piece
is on.

## Security

The executable surface is currently limited to the Stage 0 PKCE kernel; token
transport, validation, and storage are not implemented yet. Report suspected
issues privately through GitHub Security Advisories on this repository rather
than in a public issue.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
