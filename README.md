# Solana Foundation audit details

- Total Prize Pool: $203,500 in USDC
  - HM awards: up to $192,000 in USDC
    - If no valid Highs or Mediums are found, the HM pool is $0
  - QA awards: $8,000 in USDC
  - Judge awards: $3,000 in USDC
  - Scout awards: $500 in USDC
- [Read our guidelines for more details](https://docs.code4rena.com/competitions)
- Starts August 19th, 2025 20:00 UTC
- Ends September 15, 2025 20:00 UTC

**❗ Important notes for wardens**

1. Judging phase risk adjustments (upgrades/downgrades):

- High- or Medium-risk submissions downgraded by the judge to Low-risk (QA) will be ineligible for awards.
- Upgrading a Low-risk finding from a QA report to a Medium- or High-risk finding is not supported.
- As such, wardens are encouraged to select the appropriate risk level carefully during the submission phase.

## Publicly Known Issues

_Note for C4 wardens: Anything included in this `Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

The only known issue is that we use a non-standard key-derivation method as described in <https://github.com/solana-program/zk-elgamal-proof/issues/35>.

# Overview of Token22 Confidential Transfer Audit

The main objective of the audit is to find potential vulnerabilities in the confidential transfer component of the Solana Token22 program. The Token22 program (also known as Token Extensions) is an extension of the standard SPL Token program, which introduces new features including confidential transfers.

There are two primary components that enable confidential transfers. The first is the on-chain Token22 program, which manages the state and logic for token interactions. The second is the native ZK ElGamal Proof program, a specialized program integrated directly into the Solana validator runtime. The Token22 program embeds zero-knowledge proofs within its instructions, and the native ZK program is responsible for the task of verifying these proofs.

## Links

- **Previous audits:**
  - The audit reports can be found in <https://github.com/anza-xyz/security-audits> under "Token-2022".
- **Previous security advisories for the ElGamal program:**
  - <https://solana.com/tr/news/post-mortem-may-2-2025>
  - <https://solana.com/tr/news/post-mortem-june-25-2025>
- **Documentation:**
  - <https://edge.docs.anza.xyz/runtime/zk-elgamal-proof>
  - <https://www.solana-program.com/docs/confidential-balances>
- **Website:** <https://solana.org/>
- **X/Twitter:** <https://x.com/SolanaFndn>

---

# Scope

The scope of the audit covers the following components:

- **The zk-sdk**
  - Contains the core cryptographic logic for generating and verifying proofs. The crate is divided into three main components:
    - Cryptographic Primitives: ElGamal encryption and Pedersen commitments
    - Proof Systems: sigma proofs and range proofs
    - Program Components: Client-side logic for interacting with the ZK ElGamal Proof program instructions

- **The ZK ElGamal Proof Program**
  - While the zk-sdk contains proof generation and client-side verification logic, this repository contains the actual native program logic that is deployed on-chain and executed by Solana validators to verify proofs.

- **The Token-2022 Confidential Transfer ZK Logic**
  - This component contains the specific logic for generating and verifying proofs within the context of the Token-2022 program's state and instructions.

- **The Token22 program**
  - This repository contains the full Token-2022 on-chain program. While a full audit of the entire program is out of scope, its role as the primary consumer of the confidential transfer functionality makes it highly relevant. The three extensions that utilize the ZK components are confidential transfer, confidential fee, and confidential mint-burn extensions

### Files in scope

### Files out of scope

# Additional context

## Areas of concern (where to focus for bugs)

- Does the rust proof generation/verification implementation faithfully follow the protocol specification of <https://edge.docs.anza.xyz/runtime/zk-elgamal-proof> and <https://eprint.iacr.org/2017/1066>?
- Managing the merlin transcript in the proof implementation has been tricky. Are all necessary components like the zk public statements and all proof components hashed into the transcript
- We use a concept called the proof context to divide up long proofs into multiple chunks. Are there any security issues during the creation or deletion of these context states?
- Multiple proofs are used to instructions like the transfer and transfer with fee. The consistency between these proofs have be meticulously checked. Are our consistency checks sound?
- Likewise, proof components have to be checked for consistency with the actual token22 instruction data. Are our consistency checks sound?
- The confidential transfer extension was originally developed independently of other token22 extensions. Are there any security issues involved in how the confidential transfer extensions interact with other extensions?

## Main invariants

N/A

## All trusted roles in the protocol

N/A

## Running tests

```bash
git clone --recurse https://github.com/code-423n4/2025-08-solana-foundation.git
cd 2025-08-solana-foundation

# ZK-SDK:
cd zk-elgamal-proof
pnpm install
pnpm zk-sdk:test
cd ..

# Token22
cd token-2022
pnpm install
pnpm programs:test
pnpm clients:rust:test
pnpm confidential-transfer:proof-tests:test
```

## Miscellaneous

Employees of Solana Foundation and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.
