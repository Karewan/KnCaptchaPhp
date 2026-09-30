v2.0.0 (2026-09-30)
----------------------------
First release as a standalone library, for the KnCaptcha 2 widget. Solutions of version 1 are not accepted.

* **Stateless challenges:** a random salt, the puzzle parameters and an expiry signed with an HMAC, bound to a scope. Issuing one costs about 1 µs and stores nothing.
* **Equihash proofs of work:** a solution is checked with 2^k + 2 SHA-256 per proof, about 25 µs with the default difficulty. Only `ext-hash` is needed.
* **Single use:** the `markUsed` closure remembers the challenges of valid solutions until their expiry. `Store` has ready-made closures for phpredis, Predis, APCu, Memcached, PDO and the process memory.
* **Difficulty:** bits and proofs per challenge, `low()`, `medium()`, `high()` presets.
* **Result:** why a solution is refused (malformed, bad signature, expired, invalid proof, replayed).
