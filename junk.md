These are all **dynamic analysis** tools — they actually *execute* EVM bytecode rather than reading it statically. Here's each one in depth.

---

## 1. Fuzzer (Echidna, Foundry's `forge fuzz`)

### What it is
A fuzzer generates thousands of random or semi-random inputs and calls your contract with them, looking for property violations (invariants you define).

### How it works
```
Define invariant:                 e.g. assert(totalSupply == sumOfBalances)
                                       assert(price_after_swap >= minOut)
Fuzzer generates random calldata  →  executes tx on local EVM
Checks invariant after each call  →  if violated, reports minimal reproducer
Shrinks the failing input         →  gives you the smallest tx that breaks it
```

Two main strategies:
- **Blackbox**: purely random inputs
- **Coverage-guided** (Echidna, AFL-style): instruments the EVM to track which branches were hit; mutates inputs that reach new branches — vastly more efficient than pure random

### Benefits
- Finds bugs that are *logically correct in isolation* but break under weird combinations of state: flash loan + reentrant call + specific token amounts
- Automatically discovers edge cases a human analyst would never think of
- Gives you a concrete failing transaction sequence you can replay

### Complexity / cost
- You must write the invariants yourself in Solidity (Echidna) or as Foundry test functions — this is non-trivial and requires domain knowledge of what "correct" means
- Runs for minutes to hours; the longer it runs, the more confidence you get
- Stateful fuzzing (sequences of 5–20 calls) is much harder than stateless — finding reentrancy or flash loan paths requires the fuzzer to generate the right sequence, which can take hours of compute
- Needs a compiled contract + ABI, not just bytecode — so it typically requires source code

---

## 2. Symbolic Execution Engine (Manticore, Mythril, Halmos, hevm)

### What it is
Instead of running one concrete input at a time, symbolic execution represents inputs as *symbolic variables* (unknowns) and explores all possible execution paths simultaneously using an SMT solver (Z3, Bitwuzla).

### How it works
```
Concrete execution:    x = 5  →  branch: (5 > 3) = TRUE  →  takes left path only
Symbolic execution:    x = ★  →  branch: (★ > 3) = ?
                               →  solver asks: can ★ > 3? YES → explore left path
                                              can ★ ≤ 3? YES → explore right path
                               →  both paths explored simultaneously
```

The engine builds a *path condition* — a logical formula of all constraints on symbolic inputs needed to reach a given point. If a REVERT or assertion failure is reachable, the solver finds concrete values that trigger it.

### Halmos specifically
Halmos is the most modern one for EVM. It takes Foundry-style tests, replaces all concrete inputs with symbolic variables, and exhaustively proves whether any input can make an assertion fail:
```solidity
function testSymbolic_noOverflow(uint256 a, uint256 b) public {
    vm.assume(a < 2**128 && b < 2**128);
    assertEq(a + b, safeAdd(a, b)); // halmos proves this for ALL valid a,b
}
```

### Benefits
- **Exhaustive within a bounded depth**: for functions with ≤ N calls deep, it provably finds all bugs — not just "didn't find one after 10 minutes"
- Excellent at integer overflow, access control bypasses, and exact condition checks
- No invariants needed — it can automatically check for things like "can SELFDESTRUCT be reached by an arbitrary caller"

### Complexity / cost
- **Path explosion**: a function with 20 branches has 2²⁰ paths; many are infeasible but the solver doesn't know that cheaply — analysis can take hours or simply time out
- **Loops are hard**: symbolic engines usually bound loop iterations (e.g. "explore up to 3 iterations") — bugs requiring more iterations are missed
- **External call stubs**: calls to unknown contracts become non-deterministic; engines either assume the worst (overapproximation → false positives) or skip them (underapproximation → false negatives)
- Requires source code or very clean bytecode + ABI; pure bytecode symbolic execution (Mythril's mode) is slower and less precise

---

## 3. Mainnet Fork

### What it is
Running a local Ethereum node that starts its state as a snapshot of mainnet (or any network) at a specific block. Your test transactions execute against real deployed state — real USDC balances, real Uniswap pool reserves, real Chainlink prices.

### How it works
```
Foundry: anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/KEY --fork-block-number 19000000

Your test contract:  → calls real Uniswap router (address 0x7a250d...)
                     → reads real WETH/USDC pool state
                     → executes swap against real liquidity
                     → asserts profit/loss
```
State is loaded lazily from an archive node via RPC — only the slots you touch are fetched and cached locally.

### Benefits
- **Realistic exploit reproduction**: if you think a contract is vulnerable to a specific MEV attack, you can reproduce it exactly with real token amounts, real pool depths, real oracle prices
- No need to mock anything — `vm.prank(whale_address)` gives you a real whale's token balance
- Flash loan attacks can be tested against real Aave/Balancer/Uniswap liquidity
- Essential for DeFi audits where the vulnerability only manifests under specific market conditions

### Complexity / cost
- Requires an **archive node** — a full Ethereum node that stores historical state. These are expensive: Alchemy, Infura, QuickNode charge ~$50–500/month for archive access
- Slow: first run fetches lots of RPC calls; subsequent runs use local cache but cold starts are 30–120 seconds
- **Not reproducible offline** — your CI breaks if the RPC is down, rate-limited, or the block changes
- Fork tests are integration tests, not unit tests — they don't tell you *why* something fails, just *that* it does

---

## 4. REVM (Rust EVM)

### What it is
REVM is a standalone, dependency-minimal, extremely fast EVM implementation written in Rust. It's the execution engine underneath Foundry/Anvil, Reth (Ethereum client), and many analysis tools.

### How it works
REVM is a **library**, not a tool — it gives you a programmable EVM you embed in your own code:
```rust
let mut evm = Evm::builder()
    .with_db(in_memory_db)
    .with_tx(TransactionEnv { caller, data: calldata, value, .. })
    .build();
let result = evm.transact();
// result has: gas_used, output, logs, state_changes, revert_reason
```

You can:
- Plug in any state backend (in-memory, RocksDB, mainnet fork via RPC)
- Hook every opcode execution
- Inspect the full call stack after execution
- Run thousands of transactions per second (REVM executes a simple transfer in ~1 microsecond)

### Benefits
- **Speed**: 10–100× faster than Go's `go-ethereum` EVM for scripted testing
- **Programmability**: you can write custom inspectors that record every SLOAD/SSTORE, every external call, every jump taken — this is how coverage-guided fuzzers work
- **Correctness**: used in production by Reth; very close to spec-compliant

### Complexity / cost
- Pure Rust — if your toolchain is Python/TypeScript you need FFI or a subprocess boundary
- You're building an EVM harness from scratch; you handle state, gas, block context, precompiles yourself
- Integrating mainnet state requires writing a DB backend that proxies REVM storage reads to an archive node or local snapshot — non-trivial (~500–1000 lines of infrastructure)
- Not a tool you "run" — it's an engine you build on

---

## 5. Anvil (and Hardhat node)

### What it is
A local Ethereum node for development and testing — think of it as a local simulated blockchain you fully control.

### How it works
```
anvil  →  starts on localhost:8545
           20 pre-funded accounts (10000 ETH each)
           instant block mining (or interval-based)
           accepts standard JSON-RPC (eth_sendTransaction, eth_call, ...)
           special cheat codes: anvil_setBalance, anvil_impersonateAccount, anvil_mine
```

Foundry tests run against Anvil via `vm` cheatcodes:
```solidity
vm.deal(attacker, 100 ether);           // set ETH balance
vm.prank(0xWhale);                      // next call comes from whale
vm.warp(block.timestamp + 1 days);     // advance time
vm.roll(block.number + 100);           // advance block
vm.expectRevert("Slippage");           // assert next call reverts
```

Anvil can also run in fork mode (see #3 above).

### Benefits
- Instant: no real network, no gas costs, no waiting for blocks
- Deterministic: same test → same result every time
- Cheatcodes are very powerful: you can teleport tokens, impersonate any address, manipulate time — things impossible on real mainnet
- The standard test environment for Foundry/Hardhat projects

### Complexity / cost
- Only useful if you have test scripts (Foundry/Hardhat/ethers.js) — not useful for pure bytecode analysis
- Not a standalone analyzer — it executes what you tell it to; you still need to write the attack scenario yourself
- Requires the Foundry toolchain; cross-language use requires JSON-RPC calls or subprocesses

---

## Why the Plan Excluded All of Them

The core tension is this:

| Property | Static (your system) | Dynamic (these tools) |
|---|---|---|
| Input needed | Runtime bytecode only | Source code + ABI + test harness |
| Setup per contract | Zero | 1–10 hours of invariant / harness writing |
| Output | "This pattern looks like X" | "Here is a concrete transaction that proves X" |
| False positive rate | Medium (mitigated by counter-evidence) | Very low (proof by execution) |
| False negative rate | Medium (can't reason about all state) | Low (bounded, but can miss complex state paths) |
| Scales to "scan all deployed contracts" | Yes | No — too slow, too much manual setup |
| Useful for SaaS "scan any address" | Yes | Only for targeted manual audits |

For a **SaaS that scans arbitrary deployed contracts** (no source, no ABI, no custom harness), dynamic tools don't compose — you'd need to auto-generate invariants and call sequences from bytecode alone, which is an unsolved research problem. The static approach with strong counter-evidence and coverage gates is the right architecture for that use case.