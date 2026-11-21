# Portal submission text — Bug Bounty Report Verifier (Intelligent Contract)

Copy the sections below into the GenLayer Builder portal
(Intelligent Contracts contribution). Replace `<REPO-URL>` with the public
GitHub URL of this repo once pushed.

## Title

Bug Bounty Report Verifier — consensus judging of vulnerability claims against proof-of-concept evidence

## Description

An Intelligent Contract that judges whether a security report's claimed
vulnerability is supported by the proof-of-concept evidence submitted with
it (reproduction steps, request/response excerpts, command output).
Example: a researcher claims "stored XSS in the profile bio field"; the
PoC is a step-by-step reproduction plus the observed alert. The contract
decides whether the PoC backs the claim — triage by consensus before a
human analyst spends time on the report.

`compute(report_id, claim, poc_evidence, candidate_quote)` assesses the
PoC with an LLM and derives the decision from a deterministic table:
supported + relevant + PoC found → accept; contradicted or irrelevant →
reject; otherwise review. `get_evaluation(report_id)` reads the stored
result back. A claim is SUPPORTED only when the PoC shows concrete
reproduction steps AND observed output demonstrating the flaw — a
description of a hypothetical attack without observed output does not
count. A deterministic substring check (`key_step_present`) records
whether the reporter's key PoC step actually appears in the evidence, so
fabricated quotes are flagged outside the LLM prompt.

The validator model is independent re-evaluation, not a structure check:
every validator issues its OWN exec_prompt call with the SAME prompt the
leader used, derives its own decision from its own assessment, and accepts
the leader only when the bound (assessment, decision) pair agrees with its
own. Opposite assessments cannot both pass. Review-class labels (partial /
insufficient / ambiguous) count as agreeing with each other, so wording
variance between honest validators does not stall consensus. Malformed
validator output votes False.

## What it judges

Whether a claimed vulnerability (e.g. "Stored XSS in the profile bio
field") is supported, contradicted, or unestablished by the submitted
proof-of-concept (reproduction steps + observed output).

## Evidence links

- Repository: <REPO-URL>
- Contract source: <REPO-URL>/blob/main/contracts/bugbounty_contract.py
- Live contract (Studio Next, chain 61997): 0x4E2467437E6A771a6c67F78Bc94375f6053440a7
- Explorer (contract): https://explorer-studio-dev.genlayer.com/address/0x4E2467437E6A771a6c67F78Bc94375f6053440a7
- Deploy TX: https://explorer-studio-dev.genlayer.com/tx/0xe2033c12a5fc07ee5a5979e52ef8a8b91c17a4b22f7a93ef06365dc498816408
- Write TX 1 (BB-001, supported → accept): https://explorer-studio-dev.genlayer.com/tx/0xb1aa3daeef752a2b8c50385a3b4caebb090031a3332f7d97c24cc384e14beb57
- Write TX 2 (BB-002, contradicted → reject): https://explorer-studio-dev.genlayer.com/tx/0x07a03e5e6f8a43dacbba99553a2231e59db84e85ed70daac712ece2a67ff7978
- On-chain proof doc: <REPO-URL>/blob/main/ONCHAIN_PROOF.md
- Tests: 30/30 passing locally (stdlib unittest, stubbed genlayer module) — `python -m unittest -v tests.test_bugbounty_validator`
