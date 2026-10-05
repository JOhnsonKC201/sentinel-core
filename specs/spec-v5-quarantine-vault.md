# Specification v5: Cryptographic Quarantine Vault

- **Module**: `crates/sentinel-daemon/src/quarantine.rs`
- **Status**: APPROVED
- **Author**: SentinelCore Engineering
- **Date**: 2026-10-05

## 1. Overview
The Cryptographic Quarantine Vault renders detected malicious payloads completely inert on the host filesystem by encrypting the binary content with authenticated AES-256-GCM, storing metadata in an isolated datastore, and securely unlinking the original file handle.

## 2. Vault Packaging Specification (`.qvault`)
Each quarantined payload is stored under `C:\ProgramData\SentinelCore\Vault\{UUID}.qvault`.

### Binary Layout
```
+-------------------------------------------------------------------------------+
| Bytes 0..11   | 12-byte Random Nonce / IV (generated via CryptGenRandom / ring)|
+---------------+---------------------------------------------------------------+
| Bytes 12..N   | AES-256-GCM Encrypted Ciphertext                              |
+---------------+---------------------------------------------------------------+
| Bytes N..N+15 | 16-byte Poly1305 Authentication Tag (appended by GCM cipher)   |
+-------------------------------------------------------------------------------+
```

## 3. Metadata Datastore
Metadata is maintained in an embedded SQLite/RocksDB table to ensure full reversibility for false positives:
- `VaultFileId`: UUID v4 string identifier.
- `OriginalPath`: Normalized NT path of the intercepted binary.
- `OriginalSize`: Size in bytes.
- `Sha256Digest`: 32-byte cryptographic hash.
- `QuarantineTimestamp`: UTC ISO-8601 timestamp.
- `DetectionTactic`: MITRE ATT&CK technique ID (e.g. `T1486 Data Encrypted for Impact`).
- `OriginalAcl`: Preserved Windows Security Descriptor for accurate restoration.

## 4. Atomic Isolation & Restoration
1. **Isolation Sequence**:
   - Read source payload into memory buffer.
   - Encrypt buffer using master vault key and fresh 12-byte nonce.
   - Flush `.qvault` container to disk with synchronous `FlushFileBuffers`.
   - Record metadata entry in database.
   - Unlink and delete source file using `FILE_DISPOSITION_FLAG_DELETE`.
2. **Restoration Sequence**:
   - Verify integrity tag using AES-256-GCM.
   - Decrypt payload into memory.
   - Write back to `OriginalPath` with restored Security Descriptor.
   - Remove `.qvault` archive and update database state.
