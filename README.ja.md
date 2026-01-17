# VCP TradingView リファレンス・トレーディング・エージェント (VCP-TV-RTA)

[English](README.md) | [**日本語**](README.ja.md)

[![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)](https://github.com/veritaschain/vcp-spec)
[![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)](https://veritaschain.org)
[![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)](https://creativecommons.org/licenses/by/4.0/)

> **"Verify, Don't Trust."** — AIにはフライトレコーダーが必要

VCP-TV-RTA は、TradingView ベースのアルゴリズム取引システム向けに **VCP v1.1 Silver Tier** 準拠を実証するリファレンス実装です。

---

## 概要

本エビデンスパックは、TradingView の Pine Script 環境と統合した VCP の本番グレード実装を実証します。Webhook とサイドカーアーキテクチャを使用して、取引イベントをキャプチャし、暗号学的監査証跡を生成します。

---

## クイックスタート

```bash
# クローン
git clone https://github.com/veritaschain/vcp-tradingview-rta-reference.git
cd vcp-tradingview-rta-reference

# インストール
pip install -r requirements.txt

# 鍵生成
python -m sidecar.keygen

# サーバー起動
python -m sidecar.main
```

---

## クイック検証

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_tv_events.jsonl \
    -s evidence/04_anchor/security_object.json
```

---

## ライセンス

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)（エビデンスパック）  
MIT License（実装コード）

---

**VeritasChain Standards Organization (VSO)**  
*"Verify, Don't Trust."*
