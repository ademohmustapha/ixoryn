# IXORYN Threat Model

## 1. Assets Protected
- Confidential user data
- Encrypted files
- Steganographic payloads
- Audit logs
- Domain intelligence results

## 2. Adversary Types
- Malicious user supplying malformed input
- External attacker probing CLI/GUI
- Insider abusing forensic tooling
- Network-based attacker (DNS manipulation)

## 3. Attack Surfaces
- File input (image/audio/files)
- Password entry
- URL/domain input
- Dependency resolution

## 4. Mitigations
- Strict input validation (fail-closed)
- Lossless format enforcement
- Typed exception handling
- No custom cryptography
- Deterministic logging
- No network listening services

## 5. Non-Goals
- Real-time intrusion prevention
- Network packet interception
- Anonymous communication

## 6. Residual Risks
- ML false positives
- User-supplied weak passwords
- External dependency compromise (mitigated via pinning)

## 7. Security Posture
IXORYN is a defensive analysis framework designed for controlled execution
environments and forensic workflows.

