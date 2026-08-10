# Design

## 1. What the library refuses to do

A security library is defined more by what it makes impossible than by what it
offers. These are settled:

| Refused | Reason |
|---|---|
| Implicit flow (`response_type=token`) | tokens in the URL; omitted by the current OAuth 2.1 draft and deprecated by RFC 9700 |
| Resource owner password credentials | the client sees the password |
| Authorization code without PKCE | code interception on public clients |
| Client secret in a public client | it is not a secret on a user's machine |
| `alg: none`, or algorithm taken from the JWT header | trivial verification bypass |
| Symmetric verification with a key fetched from JWKS | confused-deputy between HMAC and RSA |
| Disabling certificate verification | there is no legitimate caller |

None of these is behind a flag. A flag is an invitation.

## 2. Flow state machine

The authorization code flow is modelled as a type-state machine so that steps
cannot be skipped or reordered:

```
Configured ──authorize()──▶ Pending ──exchange(code, state)──▶ Tokens
                              │
                              └─ carries verifier, state, nonce, PKCE method
```

`Pending` holds the PKCE verifier, the `state`, and the OIDC `nonce`. There is
no public constructor for it, so the only way to reach `exchange` is through
`authorize`. `exchange` verifies `state` before touching the network and fails
with a distinct error when it mismatches, because that error means an attack,
not a typo.

## 3. ID token validation

Validation is a fixed list, all of it mandatory:

1. signature, against a JWKS key selected by `kid`, with the algorithm taken
   from the discovered provider metadata rather than the token header
2. `iss` exactly equals the discovered issuer
3. `aud` contains the client id; `azp` checked when multiple audiences present
4. `exp` and `iat` within the configured clock skew, default 60 seconds
5. `nonce` equals the one generated for this flow
6. `at_hash` when an access token was returned alongside

JWKS responses are cached with the provider's `Cache-Control`, refreshed once on
unknown `kid` with a rate limit, so key rotation heals without a restart and an
unknown-`kid` flood cannot be turned into a request amplifier.

## 4. Token storage

The trust order:

1. platform keychain — Keychain Services, Windows Credential Manager, Secret
   Service
2. encrypted file, key derived from a passphrase with Argon2id, used only where
   no keychain exists (headless Linux, containers)
3. in-memory, for tests, and it says so in its type name

Refresh tokens never reach a web view or a rendering process. Access tokens are
handed out with the shortest lifetime the provider permits.

## 5. Refresh

Refresh is serialised per credential: concurrent callers awaiting the same
expired token perform one refresh, not N. Rotating refresh tokens are stored
before the old one is discarded, so a crash mid-refresh does not log the user
out. A refresh that fails with `invalid_grant` clears the credential rather than
retrying, because retrying a revoked grant is how an application locks an
account out.

## 6. Device authorization

For CLIs and anything without a browser. Polling honours `interval`, backs off
on `slow_down`, and stops on `expired_token`. The user code is displayed with a
character set chosen to survive being read aloud.

## 7. Passwords and second factor

Argon2id, with parameters written down here rather than left to a caller:
memory 64 MiB, iterations 3, parallelism 1, as a floor, tuned upward at
deployment. Verification is constant-time and rehashes when the stored
parameters are below the current floor.

TOTP follows RFC 6238 with a default 30-second step and a ±1 step window.
Verified codes are recorded so the same code cannot be replayed inside its
window — a detail that most implementations skip and attackers do not.

## 8. Layering against the language

- **Stage 0** — a narrow C11 kernel makes the public-client and one-shot PKCE
  boundaries enforceable while Kofun still lacks cross-file opacity. OpenSSL
  supplies RNG, SHA-256, constant-time comparison, and cleansing.
- **Stage 1** — once Kofun enforces module and FFI boundaries, the protocol
  state machine and error taxonomy move into Kofun. HTTP client and JSON
  handling follow as the standard library stabilises.
- **Stage 2** — reconsider primitives. Reimplementing crypto is not a goal; it
  becomes reasonable only with constant-time guarantees in the language.

Each issue states its stage and, when it is blocked, names the compiler
diagnostic that blocks it.
