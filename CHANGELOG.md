# Changelog

All notable changes to the VCP TradingView RTA Reference Implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-01-17

### Added
- Initial release of VCP TradingView Reference Implementation
- VCP v1.1 Silver Tier compliance
- Three-layer architecture implementation:
  - Layer 1: Event Integrity (SHA-256 + Ed25519)
  - Layer 2: Collection Integrity (RFC 6962 Merkle Tree)
  - Layer 3: External Verifiability (OpenTimestamps/Bitcoin anchoring)
- FastAPI-based sidecar for webhook reception
- Pine Script v5 strategy template (`vcp_silver_strategy.pine`)
- Complete evidence pack with verification tools
- Tamper detection test suite
- Docker deployment configuration
- Bilingual documentation (English/Japanese)

### Features
- Canonical JSON serialization (RFC 8785 JCS)
- Ed25519 digital signatures
- RFC 6962 compliant Merkle Tree with domain separation
- Multiple anchor providers (OpenTimestamps, Bitcoin, TSA, Local)
- Webhook-based event capture from TradingView
- RESTful API for event verification and proof retrieval

### Compliance
- VCP v1.1 Silver Tier requirements
- External anchoring REQUIRED (24-hour interval)
- Policy identification support
- Completeness guarantee support

### Documentation
- VERIFICATION_GUIDE.md for step-by-step verification
- INTEGRATION.md for TradingView setup
- architecture.md explaining three-layer design
- Inline code documentation

## [Unreleased]

### Planned
- Gold Tier implementation (1-hour anchoring)
- Enhanced webhook authentication
- Real-time monitoring dashboard
- Performance optimizations for high-frequency events

---

For more information about VCP versions, see:
- [VCP v1.1 Specification](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
