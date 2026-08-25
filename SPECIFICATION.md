# RecoverBull Reference Profile 1

This document is the normative interoperability specification for the existing RecoverBull implementation. It is deliberately separate from the conceptual whitepaper. The words MUST, MUST NOT, SHOULD, and MAY are normative.

## Scope and data flow

The Client owns a wallet mnemonic and creates a Backup File. A cloud or other artifact store holds that file. A Key Server stores an encrypted copy of the Backup Key. The user supplies the password and the Backup File during recovery; the Client derives the two password keys, fetches and decrypts the Backup Key, then decrypts the mnemonic. The server never receives the mnemonic. The client package accepts the Backup Key, and the integrating wallet performs the BIP85 derivation.

## Backup File

The Profile 1 JSON object has these fields:

* `created_at`: integer milliseconds since the Unix epoch.
* `id`: exactly 32 identifier bytes, encoded as lower-case hexadecimal.
* `salt`: exactly 16 bytes, encoded as lower-case hexadecimal.
* `ciphertext`: base64 of `IV || ciphertext || HMAC`.
* `path`: optional string, used to record the Backup Key derivation path.

The Profile 1 format has no version field. A future incompatible profile MUST add an explicit version before introducing a new interpretation; Profile 1 implementations MUST NOT infer a version from incidental fields.

## Backup Key derivation

Profile 1 uses the BIP85 construction ([BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)). The full path is `m/83696968'/1608'/0'/index`, with a final apostrophe on `index` according to the mode. The stored path accepts the historical optional `m/` prefix and the app-relative forms `1608'/0'/index` or `1608'/0'/index'`. The legacy `LegacyUnhardened` mode (no final apostrophe) MUST remain derivable for existing backups. New generations use `Hardened` (final apostrophe). Generated indices are in `[0, 2^31-2]`. The Backup Key is the first 32 bytes of BIP85 output. The client package accepts the Backup Key, and the integrating wallet performs the BIP85 derivation.

## Password-derived keys

Argon2id version 1.3 MUST use `t=2`, `m=19456 KiB`, `p=1`, and output 64 bytes. The password is encoded as UTF-8 without implicit Unicode normalization. The first 32 bytes are the Authentication Key and the last 32 bytes are the Encryption Key.

The mnemonic is encrypted under the Backup Key. The Backup Key is encrypted under the password-derived Encryption Key.

## Profile 1 authenticated encryption

The legacy Profile 1 construction is AES-256-CBC with PKCS7 padding. It uses a 16-byte cryptographically secure random IV. HMAC-SHA256 covers the exact byte string `IV || ciphertext`; the same 32-byte key is used for AES and HMAC. A recipient MUST verify the HMAC with a constant-time comparison before attempting CBC decryption.

This legacy profile remains valid for interoperability. A future profile SHOULD use versioned AEAD and key separation, but MUST NOT silently change Profile 1. Profile 1 backup metadata (`created_at`, `id`, `salt`, and `path`) is not authenticated by the ciphertext. A future profile MUST bind its metadata as AEAD associated data (or an equivalent authenticated encoding).

## Key Server identifiers and operations

For `/store`, `/fetch`, and `/trash`, the server computes:

`secret_id = SHA256(ASCII(lowerhex(identifier) || lowerhex(authentication_key)))`.

The `/attempts` extension hashes an identifier as `id_hash = SHA256(raw identifier bytes)`. The hash is not reversible without the identifier. It reports derived identifier hashes with recent lookup activity retained in the rate-limit map, including before any configured attempt limit is saturated. A holder of the Backup File does know the identifier and can recognize its hash and observe this activity; this telemetry is intentional detection, not anonymity.

`/store` accepts the identifier, Authentication Key, and encrypted Backup Key. `/fetch` returns the encrypted Backup Key for a matching record and `/trash` deletes it for a matching request. `/attempts` is an extension of the reference server, not a required Profile 1 recovery operation.

### Candidate budget and observable responses

The reference server counts distinct authentication candidates within a configurable window/cooldown. `/fetch` and `/trash` share this budget. Replays do not add a candidate, but increment `total_requests` and remain activity; success does not reset counters. Failed candidates still consume a candidate.

An exhausted targeted budget returns HTTP `429 Too Many Requests` with `Retry-After`. Global pressure or inability to process lookup activity returns HTTP `503 Service Unavailable` with `Retry-After`. Clients classify these conditions by HTTP status only, never by response-body text. `429` is an accepted targeted lockout and availability risk; `503` represents global pressure or unavailability. Rate limiting is an operational control, not cryptographic proof.

Successful `/fetch` and `/trash` responses from the Profile 1 reference server include version-1 `attempt_status`. Clients supporting older servers MAY tolerate its absence. In version 1, `version` is `1`; `total_attempts` is the number of distinct candidates in the current window; `failed_attempts` is the number of distinct candidates that failed authentication; `remaining_attempts` is the configured budget minus `total_attempts`, saturating at zero; `total_requests` counts every `/fetch` and `/trash` request associated with the active entry for the target, including replays, duplicate pending requests, and targeted saturation rejections. A request rejected before an entry is created or associated because of global pressure is not counted. `window_started_at` is the exact UTC window start; `previous_attempt_at` is the exact UTC timestamp of the preceding distinct candidate or `null` (also `null` for replays); and `resets_at` is the exact UTC expiry measured from the most recent distinct candidate.

The reference deployment is single-instance. Rate-limit and telemetry state is in memory, not shared between instances, and is logically wiped every 24 hours; expired entries MAY be removed earlier. A restart resets budgets and renews `collection_started_at`; the value is also renewed after every global wipe.

`/attempts` is an optional, consultative detection/confidentiality tradeoff, not a required Profile 1 operation. A compromised server can lie; clients MUST NOT take automatic deletion, rotation, or recovery actions solely from it. Version 1 has root fields `version`, `collection_started_at`, and `entries`. Each entry has `id_hash`, `total_attempts`, `failed_attempts`, `total_requests`, `window_started_at`, and `last_attempt_at`; `last_attempt_at` is the last distinct candidate, never a replay. The server renews `collection_started_at` at startup and after every global wipe. All public timestamps in this snapshot, including `collection_started_at`, are truncated to the hour.

`GET /attempts` returns gzip-compressed JSON (`Content-Encoding: gzip`), an `ETag`, and `Cache-Control` for snapshot freshness. A client MAY send the ETag as `If-None-Match`; a matching validator returns `304 Not Modified` with no body. Clients MAY cache the snapshot. Rate-limit and telemetry state has no server-side persistence, distinct from the encrypted Backup Key row persisted in the database.

## Threat guarantees and limits

* **Database only:** the encrypted Backup Key and server identifiers do not reveal the mnemonic without the password; the salt is not necessarily present.
* **Cloud artifact only:** the encrypted mnemonic does not reveal the mnemonic without the Backup Key.
* **Cloud plus database:** when an attacker has both the cloud Backup File and the Key Server database, password guesses can be tested offline against the two artifacts. This guarantee is conditional on password entropy; a weak PIN is intentionally vulnerable to this colluding/offline case.
* **Profile 1 Backup File integrity:** an attacker able to alter the cloud artifact can change `id`, `salt`, `path`, or `created_at` and cause recovery loss or denial of service without detection by the ciphertext HMAC. This does not claim that confidentiality is compromised: the current Profile 1 construction authenticates neither the outer envelope nor its metadata. An operational mitigation is to keep an independent copy of the Backup File. A future profile MUST use versioned AEAD/AAD to authenticate the envelope and its metadata.
* **Malicious server:** it can deny service, lie about telemetry, retain request data, and return tampered ciphertext (which the client must reject by HMAC). It does not receive the mnemonic from the Profile 1 protocol.
* **Compromised device:** this profile cannot protect secrets exposed to a compromised Client, including a password, mnemonic, or Backup Key.

The profile provides conditional pseudonymity as a deployment goal, not a state-level or universal anonymity guarantee. Identifier entropy and CSPRNG quality are required for the intended unlinkability. A warrant canary is best effort signalling, not proof of absence of legal process. Social recovery is not implemented by the server.

## Rotation and rollback

Rotation means creating a new Backup Key and Backup File and destroying or revoking the old artifacts. In Profile 1 it is conceptual: there is no atomic cross-store operation or rollback protocol, so interruption can leave old and new artifacts with different availability or exposure. Deleting a server record does not delete a cloud copy, and restoring an old Backup File can restore the old key if its server record still exists. `/trash` removes only the active matching database row; it does not guarantee purging database logs, backups, replicas, snapshots, or other retained copies. Rotation is not integrated into Bull Wallet, and social recovery is not integrated either.

## Reproducible vectors

The reproducible vectors cover BIP85 legacy and hardened modes, the password KDF, encryption and MAC, server hashes, and deterministic values for cross-implementation comparison. Fixed IVs and identifiers are reserved for tests. The base64 field contains `IV || ciphertext || HMAC`, while separate hex fields expose the ciphertext and HMAC.
