# kofun-auth

Authentication and authorization for [Kofun](https://github.com/kofun-lang/kofun):
OAuth 2.1 clients, OpenID Connect, PKCE, token storage, JWT, sessions, and TOTP.

> **Status: design and issues only.** No code yet. This repository exists so the
> protocol decisions are argued once, in the open, before anyone writes an
> `authorize` call. Read [docs/DESIGN.md](docs/DESIGN.md).

## Why this exists

Every ecosystem that reaches practical use grows this layer early, because
almost no real application avoids it. Go has `golang.org/x/oauth2` and `goth`;
Rust has `oauth2`, `oxide-auth`, and `openidconnect`. A language without a
credible auth story cannot host a real product, however good its compiler is.

The goal is not to be the biggest such library. It is to make the safe path the
short one:

- **PKCE always.** The implicit flow and the resource-owner password flow are
  not implemented, and will not be. OAuth 2.1 removed them for good reasons.
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

No implementation, so no vulnerabilities yet. When there is code, report
suspected issues privately through GitHub Security Advisories on this
repository rather than in a public issue.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
