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
```

## Usage

```ts
import {
  type CPaceMessage,
  type CPaceMode,
  type CPaceRole,
  CPaceSession,
  G_X25519,
  sha512,
} from 'cpace-ts';

const EMPTY_AD = new Uint8Array(0);

export function newSession(role: CPaceRole, prs: Uint8Array): CPaceSession {
  const suite = {
    name: 'CPACE-X25519-SHA512',
    group: G_X25519,
    hash: sha512,
  } as const;

  const mode: CPaceMode = 'initiator-responder';

  const s = new CPaceSession({
    prs,
    suite,
    mode,
    role,
  });

  return s;
}

export async function start(s: CPaceSession): Promise<Uint8Array> {
  const msg = await s.start();
  if (!msg) throw new Error('CPaceSession.start() returned null/undefined');
  return msg.payload;
}

export async function receive(
  s: CPaceSession,
  payload: Uint8Array,
): Promise<Uint8Array> {
  const inbound: CPaceMessage = {
    type: 'msg',
    payload,
    ad: EMPTY_AD,
  };

  const out = await s.receive(inbound);
  return out.payload;
}

export function exportISK(s: CPaceSession): Uint8Array {
  return s.exportISK();
}

async function runFullHandshake() {
  const prs = new Uint8Array([...]); // Pre-shared secret

  // Setup both parties
  const initiator = newSession('initiator', prs);
  const responder = newSession('responder', prs);

  // 1. Initiator starts and sends message to Responder
  const msg1 = await start(initiator);

  // 2. Responder receives message and sends a reply
  const msg2 = await receive(responder, msg1);

  // 3. Initiator receives the reply
  await receive(initiator, msg2);

  // Handshake complete, keys can be exported
  const initiatorKey = exportISK(initiator);
  const responderKey = exportISK(responder);
}
```