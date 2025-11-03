# cpace-ts — CPace in TypeScript

[![CI](https://github.com/slava-nikulin/cpace-ts/actions/workflows/ci.yml/badge.svg)](…)
[![npm version](https://img.shields.io/npm/v/cpace-ts.svg)](…)
[![types](https://img.shields.io/badge/types-.d.ts-blue.svg)](#)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](#)

**What is it?** Minimal, audit-friendly implementation in strict accordance with version 15 of the [IETF draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) CPace for TS
**Why?** Clean API, strict validation, audit hooks, test-driven.

## Features
- ✅ X25519 + SHA-512 suite
- ✅ IR/OC modes, AD handling (ada/adb)
- ✅ Deterministic audit events (`AUDIT_CODES`)
- ✅ Strict input validation, zeroization of secrets
- ✅ Unit + integration tests 

## Install
```bash
pnpm add cpace-ts
