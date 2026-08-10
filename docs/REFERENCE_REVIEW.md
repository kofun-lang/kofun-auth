# Reference review

Measured 2026-08-10. These projects are design evidence, not code sources.

## Standards baseline

OAuth 2.1 is still an active Internet-Draft, not an RFC. The current baseline
is [draft-ietf-oauth-v2-1-15](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15)
from 2026-03-02 together with the RFCs it consolidates, especially OAuth
Security BCP (RFC 9700), PKCE (RFC 7636), and OAuth for Native Apps (RFC 8252).
The draft omits the implicit and resource-owner-password grants and requires
the authorization-code flow to carry a PKCE challenge.

This repository uses "OAuth 2.1" as a moving profile name. Every implemented
slice must cite the exact draft/RFC baseline in its gate so a later draft
cannot silently change the claim.

## Implementations studied

### go-pkgz/auth

[go-pkgz/auth](https://github.com/go-pkgz/auth) demonstrates a small library
surface with provider handlers, middleware, cookie/JWT sessions, XSRF checks,
redirect delivery, and an application-supplied validator. Useful lessons:

- redirect allowlists must be explicit and enabled by the safe path;
- confirmation links need one-shot replay storage, shared across instances;
- provider display names such as a GitHub login or email address are not stable
  account identities;
- tokens and avatar/provider bearer URLs must not leak into rendering or logs;
- authentication, authorization middleware, and user storage are distinct
  responsibilities.

Kofun Auth intentionally does not copy its permissive default for redirect
hosts. Desktop redirect delivery belongs to Haniwa, and server integrations
must make their accepted origins explicit.

### SuperTokens

[SuperTokens Core](https://github.com/supertokens/supertokens-core) separates
frontend SDK, backend SDK, and a persistent auth core. It validates that login
UI/session transport, application integration, and credential persistence
benefit from independent contracts and tests.

Kofun Auth adopts the separation, not the service architecture. It remains a
client and verifier rather than an identity provider or user database. A
future server-side session package can sit above it without moving provider
tokens into a browser-facing process.

### Nova and BEAM applications

[Nova](https://github.com/novaframework/nova) keeps route security and
pre/post plugins at the dispatch boundary and carries authenticated data into
controllers as an explicit request value. That is a useful eventual integration
shape: Kofun Auth should return typed identity/session evidence; a Kofun web
framework should decide routing and policy.

OTP supervision is also a useful model for JWKS refreshers, device-flow
pollers, and credential refresh workers: isolate their lifecycle and restart
policy instead of hiding background work inside getters. This is a design
direction, not a BEAM dependency.

## Decisions for the current slice

- Public and confidential clients are different API types. The public type
  cannot contain a secret.
- `Pending` is opaque and has no public constructor.
- State mismatch is returned before the token-exchange callback can perform
  network I/O.
- One matching callback consumes the flow atomically; retries cannot race one
  authorization code.
- RNG, SHA-256, constant-time comparison, and cleansing come from OpenSSL 3.
  The project does not implement cryptographic primitives.
- Provider profiles, token persistence, cookies, sessions, roles, and user
  records remain outside this slice.
