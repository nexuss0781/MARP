# MAPR Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Active          |
| < 1.0   | ❌ Not supported   |

## Reporting a Vulnerability

If you discover a security vulnerability in MAPR, please report it responsibly:

1. **Do not** create a public GitHub issue
2. Email the details to: **security@mapr.dev** (or the maintainer's email)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security Measures

### Supply Chain Security

- **SLSA Level 2 Provenance**: All releases include SLSA Level 2 provenance attestations
- **Signed Releases**: All release artifacts are GPG-signed
- **SBOM**: CycloneDX SBOM included with every release
- **Dependency Scanning**: Automated scanning for vulnerable dependencies

### Build Security

- **Reproducible Builds**: Builds are deterministic and verifiable
- **Sanitizers**: ASan, UBSan, MSan, TSan enabled in CI
- **Fuzzing**: libFuzzer integration with OSS-Fuzz
- **Formal Verification**: Frama-C/ACSL for critical paths

### Runtime Security

- **Memory Safety**: Bounds checking, no use-after-free
- **Integer Overflow Protection**: Checked arithmetic
- **Input Validation**: Strict validation of all container formats
- **Resource Limits**: Configurable memory and time budgets

## Cryptographic Standards

| Algorithm | Standard | Usage |
|-----------|----------|-------|
| SHA-256 | FIPS 180-4 | Stream integrity, content addressing |
| CRC-32 | IEEE 802.3 | Frame integrity, error detection |
| SplitMix64 | - | Hashing, randomization |

No custom cryptography is used. All cryptographic primitives follow established standards.

## Threat Model

### In Scope

- Malformed `.mapr` files causing:
  - Buffer overflows
  - Integer overflows
  - Out-of-bounds reads/writes
  - Infinite loops
  - Excessive resource consumption
- Stream corruption leading to:
  - Incorrect decompression
  - Data integrity violations
  - Denial of service

### Out of Scope

- Attacks on the host OS/hardware
- Side-channel attacks (timing, cache)
- Physical access attacks
- Compromised build environment

## Vulnerability Disclosure Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | 48 hours |
| Initial Assessment | 1 week |
| Fix Development | 2-4 weeks |
| Release | Within 1 week of fix |
| Public Disclosure | After release + 2 weeks |

## Security Contacts

- **Primary**: nexuss0781@example.com
- **GPG Key**: Available on keyservers (search for nexuss0781)

## Hall of Fame

We thank the following researchers for responsible disclosure:

*None yet - be the first!*

---

*This policy is based on industry best practices and will be updated as needed.*