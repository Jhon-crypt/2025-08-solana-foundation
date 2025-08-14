# ✨ So you want to run an audit

This `README.md` contains a set of checklists for our audit collaboration. This is your audit repo, which is used for scoping your audit and for providing information to wardens

Some of the checklists in this doc are for our scouts and some of them are for **you as the audit sponsor (⭐️)**.

---

# Repo setup

## ⭐️ Sponsor: Add code to this repo

- [ ] Create a PR to this repo with the below changes:
- [ ] Confirm that this repo is a self-contained repository with working commands that will build (at least) all in-scope contracts, and commands that will run tests producing gas reports for the relevant contracts.
- [ ] Please have final versions of contracts and documentation added/updated in this repo **no less than 48 business hours prior to audit start time.**
- [ ] Be prepared for a 🚨code freeze🚨 for the duration of the audit — important because it establishes a level playing field. We want to ensure everyone's looking at the same code, no matter when they look during the audit. (Note: this includes your own repo, since a PR can leak alpha to our wardens!)

## ⭐️ Sponsor: Repo checklist

- [ ] Modify the [Overview](#overview) section of this `README.md` file. Describe how your code is supposed to work with links to any relevant documentation and any other criteria/details that the auditors should keep in mind when reviewing. (Here are two well-constructed examples: [Ajna Protocol](https://github.com/code-423n4/2023-05-ajna) and [Maia DAO Ecosystem](https://github.com/code-423n4/2023-05-maia))
- [ ] Optional: pre-record a high-level overview of your protocol (not just specific smart contract functions). This saves wardens a lot of time wading through documentation.
- [ ] Review and confirm the details created by the Scout (technical reviewer) who was assigned to your contest. *Note: any files not listed as "in scope" will be considered out of scope for the purposes of judging, even if the file will be part of the deployed contracts.*  

---

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

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/2025-07-solana-foundation/blob/main/4naly3er-report.md).

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._
## 🐺 C4 team: paste this into the bottom of the sponsor's audit repo `README`, then delete this line

The only known issue is that we use a non-standard key-derivation method as described in https://github.com/solana-program/zk-elgamal-proof/issues/35.

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

# Overview

[ ⭐️ SPONSORS: add info here ]

## Links

- **Previous audits:**  The audit reports can be found in https://github.com/anza-xyz/security-audits under "Token-2022".
  - ✅ SCOUTS: If there are multiple report links, please format them in a list.
- **Documentation:** https://edge.docs.anza.xyz/runtime/zk-elgamal-proof
- **Website:** https://solana.org/
- **X/Twitter:** https://x.com/SolanaFndn

---

# Scope

[ ✅ SCOUTS: add scoping and technical details here ]

### Files in scope
- ✅ This should be completed using the `metrics.md` file
- ✅ Last row of the table should be Total: SLOC
- ✅ SCOUTS: Have the sponsor review and and confirm in text the details in the section titled "Scoping Q amp; A"

*For sponsors that don't use the scoping tool: list all files in scope in the table below (along with hyperlinks) -- and feel free to add notes to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [contracts/folder/sample.sol](https://github.com/code-423n4/repo-name/blob/contracts/folder/sample.sol) | 123 | This contract does XYZ | [`@openzeppelin/*`](https://openzeppelin.com/contracts/) |

### Files out of scope
✅ SCOUTS: List files/directories out of scope

# Additional context

## Areas of concern (where to focus for bugs)
- Does the rust proof generation/verification implementation faithfully follow the protocol specification of https://edge.docs.anza.xyz/runtime/zk-elgamal-proof and https://eprint.iacr.org/2017/1066?
- Managing the merlin transcript in the proof implementation has been tricky. Are all necessary components like the zk public statements and all proof components hashed into the transcript
- We use a concept called the proof context to divide up long proofs into multiple chunks. Are there any security issues during the creation or deletion of these context states?
- Multiple proofs are used to instructions like the transfer and transfer with fee. The consistency between these proofs have be meticulously checked. Are our consistency checks sound?
- Likewise, proof components have to be checked for consistency with the actual token22 instruction data. Are our consistency checks sound?
- The confidential transfer extension was originally developed independently of other token22 extensions. Are there any security issues involved in how the confidential transfer extensions interact with other extensions?

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

## Main invariants

N/A

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

## All trusted roles in the protocol

N/A

✅ SCOUTS: Please format the response above 👆 using the template below👇

| Role                                | Description                       |
| --------------------------------------- | ---------------------------- |
| Owner                          | Has superpowers                |
| Administrator                             | Can change fees                       |

✅ SCOUTS: Please format the response above 👆 so its not a wall of text and its readable.

## Running tests

ZK-SDK:
git clone https://github.com/solana-program/zk-elgamal-proof
pnpm install
pnpm zk-sdk:test

Token22
git clone https://github.com/solana-program/token-2022
pnpm install
pnpm programs:test
pnpm clients:rust:test
pnpm confidential-transfer:proof-tests:test

✅ SCOUTS: Please format the response above 👆 using the template below👇

```bash
git clone https://github.com/code-423n4/2023-08-arbitrum
git submodule update --init --recursive
cd governance
foundryup
make install
make build
make sc-election-test
```
To run code coverage
```bash
make coverage
```

✅ SCOUTS: Add a screenshot of your terminal showing the test coverage

## Miscellaneous
Employees of Solana Foundation and employees' family members are ineligible to participate in this audit.

Code4rena's rules cannot be overridden by the contents of this README. In case of doubt, please check with C4 staff.


