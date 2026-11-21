# Test-only recovery-friend OpenPGP keys

Throwaway keys made with GnuPG 2.4 for `src/core/social.rs` tests. They protect nothing and
must never be used for a real vault.

| File | Primary key | Encryption subkey | Accepted? |
|------|-------------|-------------------|-----------|
| `gina.*.asc` | ed25519 | cv25519 | yes (GnuPG's modern default) |
| `rita.*.asc` | rsa2048 | rsa2048 | no: RSA |
| `max.pub.asc` | ed25519 | rsa2048 | no: RSA subkey |
| `pat.pub.asc` | nistp256 | nistp256 | no: only Curve25519 keys are accepted |
| `eve.*.asc` | ed448 (GnuPG v5) | cv448 | no: Ed448/X448 reach `crypto-bigint` |

The Ed448/X448 tests in the RFC 9580 format generate their keys at run time with the `pgp` crate.
