# Stage 0 implementation boundary

The first executable slice is a small C11 kernel behind a stable C ABI. It
exists to validate the OAuth security ordering while Kofun's cross-file module
boundary is still incomplete.

Measured against `kofun-lang/kofun` commit
`8cd8bfd2d831ec70e642727690453a04c87b78ed`:

```sh
sh tests/conformance/modules/visibility-syntax/run.sh
# PASS: pub/internal/private syntax and same-file execution
```

The gate's own README records that it performs no cross-file, import,
signature-leak, FFI, or linker visibility enforcement. A Kofun `private type
Pending` would therefore look opaque without making construction impossible to
another module. Shipping that surface as a type-state guarantee would be a
security claim the compiler does not yet enforce.

The C kernel makes the equivalent boundary real today:

- `KofunAuthPending` is an incomplete public type with no public constructor;
- `KofunAuthPublicClient` has no client-secret field;
- `state` is compared before the token-exchange callback can run;
- a correct-state exchange is atomic and one-shot;
- PKCE is generated internally with a CSPRNG and SHA-256, and only S256 exists;
- secrets are cleansed when the pending flow is freed.

OpenSSL 3 supplies the cryptographic primitives. The project does not
reimplement them. Once Kofun enforces the required module and FFI boundaries,
the protocol state transitions move into Kofun and this kernel narrows to RNG,
SHA-256, constant-time comparison, and secret cleansing.
