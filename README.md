# TimeLock Encrypt - Dual RSA Puzzle + PBKDF2 Brute-Delay

Time-lock file encryption that combines an RSA time-lock puzzle (sequential squaring) with a PBKDF2-based brute-delay. Optionally add a user password. Produces both binary and hex-encoded outputs.

- Core: RSA TLP ensures a minimum, sequential, non-parallelizable delay.
- Wrapper: PBKDF2 layer adds configurable brute-force time.
- Optional: Password layer (AES-256-CBC) for user-controlled access.

## Features

- RSA time-lock puzzle (sequential squaring), calibrated to target seconds.
- PBKDF2 delay via index search across a defined range.
- Optional password layer for extra security.
- AES-256-CBC for symmetric encryption.
- Versioned headers and magic bytes for robust parsing.
- Outputs:
  - Binary: .tloc.enc
  - Hex: .tloc.hex.enc
- Progress indicators (tqdm) and fast header sanity checks.

## How It Works

1) Time-Lock Puzzle (TLP)
- Generates N = p·q (default 1024 bits), random base a, and computes v = a^(2^T) mod N.
- Derives a mask from v and a secret “key part” to wrap a random AES-256 key (capsule).
- Encrypts the file using AES-256-CBC with that key.
- Stores a TLP header: magic, version, modulus size, N, a, T, capsule, IV.

2) PBKDF2 Brute-Delay Layer
- Picks a random index in [0, max_index).
- Derives a key from an HMAC(seed, index)-based construction and PBKDF2.
- Encrypts the TLP blob with AES-256-CBC.
- Decryption must iterate indices until a valid TLP header is found.

3) Optional Password Layer
- If provided, wraps the PBKDF2 ciphertext using a password-derived AES-256-CBC key via PBKDF2.

Decryption reverses:
- If password used: decrypt outer layer first.
- Brute-force PBKDF2 indices to recover the TLP blob.
- Perform T sequential squarings to recover the AES key and decrypt the original file.

## Security Notes

- TLP delay is designed to be sequential; it resists parallel speedups but specialized hardware can affect wall-clock times.
- Default modulus size is 1024 bits for speed; consider increasing for stronger parameters when feasible.
- PBKDF2 Layer can be sped up if multiple machines or increased CPU are working on brute forcing it, as such the PBKDF2 layer is more of an add-on protection for the TLP layer (which is more accurate in time) as the time provided can be 10x faster or 10x slower depending on computing resources.
- PBKDF2 delay depends on your iterations setting, defualt is 10,000,000 if not provided, the target iterations to provide is the number of iterations that a computer can try per second, if you are timelocking for high end computers or multiple CPUs parrelel unlocking the PBKDF layer then this would be much higher, however if you are timelocking for a single consumer device the default is enough.
- Keep the password safe if used—without it, decryption is not possible.
- Files are version-locked; mismatched versions will not decrypt.

### Why include the PBKDF2 layer if it’s not a precise “time lock”?
- The RSA time-lock puzzle enforces a mostly non-parallelizable, wall‑clock delay. PBKDF2 is different: it’s parallelizable, so the “time” it imposes depends on available compute. That’s a feature here-Use TLP to guarantee a baseline delay for everyone, then add PBKDF2 to create an adjustable, market-based delay:
     - If an attacker with a single standard machine tries to brute-force the PBKDF2 index space you set, it could take months or a year.
     - If you need emergency access, you can rent parallel cloud compute (multiple CPUs/GPUs/instances) and spread the index search to reduce your own unlock time to days or hours.
In short: TLP provides a minimum, non-parallelizable delay for everyone; PBKDF2 adds a tunable, parallelizable layer that makes unauthorized access expensive while letting the legitimate owner “buy time” back with burst compute.

## Installation

- Python 3.8+
- Dependencies:
  - pycryptodome
  - tqdm

Install:
- pip install pycryptodome tqdm

## Usage

Encrypt a file:
- python3 Timelock_encrypt.py encrypt path/to/file \
  --tlp-time 3600 \
  --pbkdf-time 7200 \
  --iterations "optional" \
  --password "optional"

- --tlp-time: target seconds for the RSA time-lock puzzle. For more precise time locking, use tlp-time which how long you want to lock something 
- --pbkdf-time: max index count for PBKDF2 brute-delay (index range size). it is much less accurate and depdendent on hardware, however serves as an extra delayed layer for the TLP layer.
- --iterations: PBKDF2 iterations that you are targeting can be done i second (tune to your hardware, defaults to 10,000,000 if not provided).
- --password: optional; adds a password-protected outer layer.

Decrypt a file:
- python3 Timelock_encrypt.py decrypt path/to/file.tloc.enc \
  --password "optional if used" \
  --start-index "optional"

- --start-index: resume brute-force at a given index.

Outputs:
- file.tloc.enc (binary)
- file.tloc.hex.enc (hex-encoded)

## File Format (Outer Layer)

- Prefix: v{VERSION}enc
- Fields (big-endian where applicable):
  - VERSION (uint32)
  - PBKDF2 iterations (uint32)
  - max_index (uint64)
  - salt (16 bytes)
  - seed (32 bytes)
  - key_part_encoded (32 bytes)
  - iv (16 bytes)
  - PASSWORD_REQ (1 byte)
  - ciphertext (remaining bytes; may be password-wrapped)

## TLP Header (Inner Layer)

- MAGIC_TLP = TIME_TLP_V3_AAKB2
- VERSION_TLP = 4
- Fields:
  - magic
  - version
  - mod_bits (uint32)
  - nlen (uint32) + N
  - alen (uint32) + a
  - T (uint64)
  - capsule (32 bytes)
  - iv (16 bytes)
  - ciphertext

## Examples

- Fast test with small delays:
  - python3 Timelock_encrypt.py encrypt sample.bin --tlp-time 60 --pbkdf-time 120 --iterations 12000000
  - python3 Timelock_encrypt.py decrypt sample.bin.tloc.enc

- Password-protected:
  - python3 Timelock_encrypt.py encrypt secrets.txt --tlp-time 150 --pbkdf-time 120 --iterations 10000000 --password "CorrectHorseBatteryStaple"
  - python3 Timelock_encrypt.py decrypt secrets.txt.tloc.enc --password "CorrectHorseBatteryStaple"

## Performance Tips

- Increase --iterations to strengthen PBKDF2 at the cost of time.
- Increase --pbkdf-time to enlarge the index space and prolong brute-force.
- Increase --tlp-time for longer TLP delays; note T scales with calibrated squaring time and modulus size.
- Consider larger mod_bits for stronger TLPs if you can tolerate slower encryption.

## Status

- Version: 4
- Magic: TIME_TLP_V3_AAKB2
- Outputs: .tloc.enc and .tloc.hex.enc
- Includes progress bars, header checks, and version enforcement.

## Disclaimer

This project is for educational and experimental use. Cryptography is subtle—before using in production, review parameters, threat models, and conduct a thorough security analysis.
