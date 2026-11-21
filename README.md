# Bug Bounty Report Verifier — GenLayer Intelligent Contract

An Intelligent Contract that judges whether a security report's **claimed
vulnerability is supported by the proof-of-concept evidence** submitted
with it — reproduction steps, request/response excerpts, command output.
Example: a researcher claims "stored XSS in the profile bio field"; the
PoC is a step-by-step reproduction plus the observed alert. This contract
decides whether the PoC backs the claim, so bug bounty triage can be
checked by consensus before a human analyst spends time on it.

## Live deployment (GenLayer Studio Next, chain 61997)

- **Contract:** `0x4E2467437E6A771a6c67F78Bc94375f6053440a7`
- **Deploy TX:** `0xe2033c12a5fc07ee5a5979e52ef8a8b91c17a4b22f7a93ef06365dc498816408`
- **Explorer (contract):** https://explorer-studio-dev.genlayer.com/address/0x4E2467437E6A771a6c67F78Bc94375f6053440a7
- **Explorer (deploy tx):** https://explorer-studio-dev.genlayer.com/tx/0xe2033c12a5fc07ee5a5979e52ef8a8b91c17a4b22f7a93ef06365dc498816408
- **RPC:** https://studio-next.genlayer.com/api
- **Deployer:** `0x898bc9eE1DD84Ab7E2319faAeC6cEDa864Ed2F00` (fresh testnet keypair, Studio faucet)
- **py-genlayer version (Depends):** `1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6` (supports TreeMap + `from genlayer import *`)

Full on-chain proof (both decision paths, read back from the chain) is in
[ONCHAIN_PROOF.md](ONCHAIN_PROOF.md). Ready-to-paste portal text is in
[SUBMISSION.md](SUBMISSION.md).

## What it judges

`compute(report_id, claim, poc_evidence, candidate_quote)`:

| Input | Meaning |
|---|---|
| `report_id` | Caller-chosen id the evaluation is stored under |
| `claim` | The claimed vulnerability, e.g. "Stored XSS in the profile bio field" |
| `poc_evidence` | PoC text: reproduction steps + observed output |
| `candidate_quote` | A key PoC step/output the reporter says is in the evidence |

The LLM assesses the PoC and returns three fields; the contract derives
the decision deterministically:

| Assessment | Decision |
|---|---|
| `supported` + `relevant` + PoC found | `accept` |
| `contradicted`, or `irrelevant` | `reject` |
| anything else (`partial`, `insufficient`, `ambiguous`, …) | `review` |

`get_evaluation(report_id)` reads the stored result back.

A claim is SUPPORTED only when the PoC shows concrete reproduction steps
AND observed output demonstrating the flaw. A description of a
hypothetical attack, without any observed output, does not count as
support. A deterministic literal-substring check (`key_step_present`)
records whether the candidate quote actually appears in the PoC —
computed outside the LLM prompt, so a fabricated quote is flagged even if
the LLM is fooled.

## Why validators can't be fooled by a dishonest leader

The validator does **independent re-evaluation**, not a structure check.
Every validator issues its OWN `exec_prompt` call with the SAME assessment
prompt the leader used, derives its own decision from its own assessment
via the shared deterministic table, and accepts the leader's result only
when the bound (assessment, decision) pair agrees with its own:

- A leader claiming `supported -> accept` and a leader claiming
  `contradicted -> reject` for the same report cannot both pass.
- Labels inside the review class (`partial` / `insufficient` / `ambiguous`)
  all mean "the PoC does not establish the vulnerability, a human must
  review", so two honest validators may use different review-class labels
  and still agree — wording variance must not stall consensus.
- Any malformed output from the validator's own LLM call votes `False`
  (disagree rather than agree on broken output).

All nondeterministic calls live inside
`gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`; contract storage is
never accessed inside those blocks.

## Tests (30 passing, stdlib-only, no network)

The `genlayer` module is stubbed (`tests/genlayer_stub.py`) with scripted
LLM responses, so every scenario is deterministic:

```bash
python -m unittest -v tests.test_bugbounty_validator
# Ran 30 tests — OK
```

Coverage: opposite assessments must not both pass (both directions);
agreement passes (accept and reject); review-class equivalence; broken
validator output disagrees (malformed JSON, missing fields, invalid enum);
structural checks retained (decision-table inconsistency,
`key_step_present` mismatch, non-Return leader result, cross-field
inconsistency); decision-table rows; end-to-end `compute()` runs
(agreement stores, disagreement stores nothing, leader/validator prompts
byte-identical, fabricated quote flagged, oversized PoC rejected).

## Reproduce the deployment

```bash
cd scripts
npm install            # genlayer-js + viem (builds the addTransaction calldata)
# Deploy (needs DEPLOYER_KEYFILE pointing at a JSON {"address","key"} file,
# or place .deployer-key.json at the repo parent):
node build_deploy.mjs ../contracts/bugbounty_contract.py <SENDER> | awk '/---TX---/{f=1;next} f' > /tmp/tx.json
python3 sign_broadcast.py /tmp/tx.json
# Call compute:
node build_call.mjs <SENDER> <CONTRACT> compute '["BB-001","<claim>","<poc>","<quote>"]' | awk '/---TX---/{f=1;next} f' > /tmp/tx.json
python3 sign_broadcast.py /tmp/tx.json
# Read back:
node verify.mjs <CONTRACT> BB-001
```

Documented gotchas (all handled by these scripts): the GenLayer node
rejects 2-param `eth_estimateGas` (use 1-param); gas price 0, legacy tx
with no `type` field; transactions go to the consensus contract
(`0xb7278A61aa25c888815aFC32Ad3cC52fF24fE575`) via `addTransaction`, not
directly to the contract. The `genlayer` PyPI package is an empty
placeholder — there is no `genlayer` CLI to rely on.

## Layout

```
contracts/bugbounty_contract.py   the intelligent contract
tests/                            stub-based local tests (30 passing)
scripts/                          deploy / call / sign+broadcast / verify
ONCHAIN_PROOF.md                  live tx hashes + read-back results
SUBMISSION.md                     ready-to-paste portal submission text
```
