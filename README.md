# VCP TradingView Reference Trading Agent (VCP-TV-RTA)

[**English**](README.md) | [日本語](README.ja.md)

[![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)](https://github.com/veritaschain/vcp-spec)
[![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)](https://veritaschain.org)
[![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)](https://creativecommons.org/licenses/by/4.0/)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![TradingView](https://img.shields.io/badge/TradingView-Pine%20Script%20v5-131722)](https://www.tradingview.com/)

> **"Verify, Don't Trust."** — AI needs a Flight Recorder

VCP-TV-RTA is a reference implementation demonstrating **VCP v1.1 Silver Tier** compliance for TradingView-based algorithmic trading systems. This repository provides a complete, verifiable evidence pack that third parties can independently validate.

---

## Overview

This Evidence Pack demonstrates a production-grade implementation of VCP integrated with TradingView's Pine Script environment. The implementation captures algorithmic trading decisions and execution events using a **sidecar architecture** that operates independently of the TradingView platform via webhooks.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  TradingView                                                    │
│  ┌──────────────────────────────────────────────────────┐       │
│  │  Pine Script Strategy (vcp_silver_strategy.pine)     │       │
│  │  - Event capture (Entry/Exit/Position Change)        │       │
│  │  - VCP Silver Tier compliant JSON payloads           │       │
│  │  - Webhook-based transmission                        │       │
│  └──────────────────────┬───────────────────────────────┘       │
└─────────────────────────┼───────────────────────────────────────┘
                          │ Webhook (HTTPS POST)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  VCP Sidecar (Python FastAPI)                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │ FastAPI     │→ │ Canonical   │→ │ Merkle Tree │→ │ Anchor  │ │
│  │ Receiver    │  │ Transform   │  │ Builder     │  │ Service │ │
│  │             │  │ (RFC 8785)  │  │ (RFC 6962)  │  │         │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│        │                                                 ↓      │
│        ▼                                    ┌───────────────────┐│
│  ┌─────────────┐                            │ OpenTimestamps /  ││
│  │ Ed25519     │                            │ Bitcoin / TSA     ││
│  │ Signature   │                            └───────────────────┘│
│  └─────────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## What's New in v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| **Three-Layer Architecture** | - | ✅ NEW |
| **External Anchor (Silver)** | OPTIONAL | **REQUIRED** |
| **Policy Identification** | - | **REQUIRED** |
| **PrevHash** | REQUIRED | OPTIONAL |
| **Completeness Guarantees** | - | ✅ NEW |

---

## Repository Structure

```
vcp-tradingview-rta-reference/
├── evidence/
│   ├── evidence_index.json
│   ├── 01_trade_logs/
│   │   └── vcp_tv_events.jsonl
│   ├── 02_verification/
│   │   └── verification_report.txt
│   ├── 03_tamper_detection/
│   │   ├── tamper_detection_test.py
│   │   └── tampered_chain.jsonl
│   └── 04_anchor/
│       ├── security_object.json
│       ├── anchor_reference.json
│       └── public_key.json
├── sidecar/
│   ├── main.py
│   ├── vcp_core.py
│   ├── merkle.py
│   ├── anchor.py
│   ├── keygen.py
│   ├── config/settings.yaml
│   └── tests/test_vcp_core.py
├── tradingview/
│   ├── vcp_silver_strategy.pine
│   └── vcp_webhook_format.md
├── tools/verifier/
│   └── vcp_verifier.py
├── docs/
│   ├── VERIFICATION_GUIDE.md
│   ├── INTEGRATION.md
│   └── architecture.md
├── examples/
├── CHANGELOG.md
├── DISCLAIMER.md
├── LICENSE
└── README.md
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/veritaschain/vcp-tradingview-rta-reference.git
cd vcp-tradingview-rta-reference

# Install
pip install -r requirements.txt

# Generate keys
python -m sidecar.keygen

# Run server
python -m sidecar.main
```

---

## Quick Verification

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_tv_events.jsonl \
    -s evidence/04_anchor/security_object.json
```

---

## License

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (Evidence Pack)  
MIT License (Implementation Code)

---

**VeritasChain Standards Organization (VSO)**  
*"Verify, Don't Trust."*
