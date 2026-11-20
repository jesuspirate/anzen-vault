# Test-only recovery-friend OpenPGP keys

Throwaway keys made with GnuPG 2.4 for `src/core/social.rs` tests. They protect nothing and
must never be used for a real vault.

| File | Primary key | Encryption subkey | Accepted? |
|------|-------------|-------------------|-----------|
| `gina.*.asc` | ed25519 | cv25519 | yes (GnuPG's modern default) |
| `rita.*.asc` | rsa2048 | rsa2048 | no: RSA |
| `max.pub.asc` | ed25519 | rsa2048 | no: RSA subkey |
| `pat.pub.asc` | nistp256 | nistp256 | no: only the 25519/448 family is accepted |
