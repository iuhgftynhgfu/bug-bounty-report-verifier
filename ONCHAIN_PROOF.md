# Bug Bounty Report Verifier — on-chain proof (Studio Next, chain 61997)

## Contract

- **BugBountyReportVerifier:** `0x4E2467437E6A771a6c67F78Bc94375f6053440a7`
- **Deploy TX:** `0xe2033c12a5fc07ee5a5979e52ef8a8b91c17a4b22f7a93ef06365dc498816408` (FINALIZED, FINISHED_WITH_RETURN)
- **Explorer (contract):** https://explorer-studio-dev.genlayer.com/address/0x4E2467437E6A771a6c67F78Bc94375f6053440a7
- **Explorer (deploy tx):** https://explorer-studio-dev.genlayer.com/tx/0xe2033c12a5fc07ee5a5979e52ef8a8b91c17a4b22f7a93ef06365dc498816408
- **Consensus contract:** `0xb7278A61aa25c888815aFC32Ad3cC52fF24fE575`
- **RPC:** https://studio-next.genlayer.com/api
- **Deployer:** `0x898bc9eE1DD84Ab7E2319faAeC6cEDa864Ed2F00` (fresh testnet keypair, funded from the Studio faucet)
- **py-genlayer version (Depends):** `1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
- **Contract code verified on-chain** via `gen_getContractCode` (returns the deployed source starting with the pinned Depends header).

## Verified evaluations (both decision paths, read back via genlayer-js readContract)

### BB-001 — PoC demonstrates the flaw → ACCEPT

- Claim: "Stored XSS in the profile bio field"
- PoC: "Steps: 1) Set bio to <img src=x onerror=alert(1)>. 2) Save profile. 3) View profile as another user. Observed: alert(1) executes."
- Candidate quote: "alert(1) executes"
- **compute TX:** `0xb1aa3daeef752a2b8c50385a3b4caebb090031a3332f7d97c24cc384e14beb57` (FINALIZED, FINISHED_WITH_RETURN)
- Explorer: https://explorer-studio-dev.genlayer.com/tx/0xb1aa3daeef752a2b8c50385a3b4caebb090031a3332f7d97c24cc384e14beb57
- Stored result (`get_evaluation("BB-001")`):
  - `poc_support: supported`, `vuln_relevance: relevant`, `poc_found: true`
  - `decision: accept`, `key_step_present: true`
  - `evaluation_complete: true`, `review_required: false`
  - Explanation: "The proof-of-concept provides clear reproduction steps (setting the bio and viewing it as another user) and explicitly observes the expected malicious behavior (alert(1) executes), which directly demonstrates the stored XSS vulnerability."

### BB-002 — PoC shows the attack failed → REJECT

- Claim: "SQL injection in the login form"
- PoC: "Steps: 1) Enter username admin' OR 1=1 -- . 2) Submit login. Observed: login failed with error invalid credentials, no data returned, no session created."
- Candidate quote: "SQL injection succeeded"
- **compute TX:** `0x07a03e5e6f8a43dacbba99553a2231e59db84e85ed70daac712ece2a67ff7978` (FINALIZED, FINISHED_WITH_RETURN)
- Explorer: https://explorer-studio-dev.genlayer.com/tx/0x07a03e5e6f8a43dacbba99553a2231e59db84e85ed70daac712ece2a67ff7978
- Stored result (`get_evaluation("BB-002")`):
  - `poc_support: contradicted`, `vuln_relevance: relevant`, `poc_found: true`
  - `decision: reject`, `key_step_present: false` (the claimed success quote is not in the PoC)
  - `evaluation_complete: true`, `review_required: false`
  - Explanation: "The PoC gives concrete steps ... and an observed result. The result shows the attack failed: the login returned 'invalid credentials', no data came back, and no session was created. That is the expected safe behavior, so the payload did not bypass authentication."

## How the judging works

`compute()` runs the assessment inside `gl.vm.run_nondet_unsafe`: the
leader proposes an assessment (`poc_support`, `vuln_relevance`,
`poc_found`) and the contract derives the decision from a deterministic
table. Every validator independently re-runs the SAME prompt, derives its
own decision, and accepts the leader only when the bound
(assessment, decision) pair agrees with its own — review-class labels
(partial / insufficient / ambiguous) count as agreeing with each other.
The agreed result is stored on-chain under the report id.

## Deploy method (proven)

- Build addTransaction calldata with the genlayer-js SDK in Node
  (`scripts/build_deploy.mjs` for deploys, `scripts/build_call.mjs` for
  method calls).
- Sign + broadcast with web3.py / eth_account
  (`scripts/sign_broadcast.py`): 1-param `eth_estimateGas`, gas = estimate
  × 1.2, gasPrice 0, legacy tx WITHOUT a `type` field, chainId 61997.
- The deployed address is read from the deploy transaction's
  `to_address` via `sim_getTransactionsForAddress`, and confirmed with
  `gen_getContractCode`.
