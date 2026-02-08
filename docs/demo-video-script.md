# Waiola Demo Video Script (3 Minutes)

**Target**: ETHGlobal HackMoney 2026 - Uniswap v4 Privacy DeFi Track
**Duration**: 3:00
**Format**: Screen recording (OBS/Loom) + voiceover
**Resolution**: 1080p, terminal font 18pt+

---

## 0:00-0:30 - The Problem (Show, Don't Tell)

**Screen**: Terminal showing a simulated public RFQ flow

**Voiceover**:
> "When a trader requests a quote through public RFQ systems, the entire process leaks information.
> The quote request reveals the taker's intent — what token, how much, which direction.
> Market makers see this and can fade their prices. Copy-traders front-run based on large orders.
> The result? Worse execution for everyone."

**Visual cues**:
- Show a mock public RFQ request being broadcast
- Highlight the visible fields: token pair, amount, direction
- Show "adversary" icons watching the mempool

---

## 0:30-1:00 - The Solution (Architecture Overview)

**Screen**: Architecture diagram (from docs/diagrams/)

**Voiceover**:
> "Waiola solves this with three components working together:
>
> First, **ENS-based discovery** — makers publish their RFQ endpoints and trading policies as ENS text records. Takers resolve them just like resolving a domain name.
>
> Second, **private offchain negotiation** — quote requests happen over direct HTTP, not public channels. Only the maker and taker see the quote terms.
>
> Third, **ZK-enforced settlement** — a Noir zero-knowledge proof is **mandatory** for every swap. The Uniswap v4 hook verifies the proof, the maker's signature, and prevents replay attacks — all before the swap executes."

**Visual cues**:
- Animated flow: Taker -> ENS -> Maker -> Quote -> Proof -> Hook -> Swap
- Highlight "private" for the offchain portion
- Highlight "enforced" for the onchain portion

---

## 1:00-1:30 - Live Demo Part 1: ENS Discovery + Quote Request

**Screen**: Terminal (large font, dark background)

**Voiceover**:
> "Let me show you. First, we discover a maker through ENS."

```bash
# Step 1: Resolve maker via ENS
npm run taker:request -- --maker alice.eth --amount 1000000000000000000

# Output shows:
# Resolving ENS: alice.eth
# Endpoint: https://rfq.alice.example/quote
# Policy Hash: 0xabc...def (verified against ENS record)
# Requesting quote...
# Quote received:
#   quotedOut: 995000000000000000 (0.995 ETH)
#   expiry: 1707352800
#   commitment: 0x1234...5678
#   signature: 0xabcd...ef01 (EIP-712)
```

> "The ENS text record told us where to find this maker.
> We fetched their policy, verified its hash matches what's on ENS, then requested a quote.
> The maker signed the quote with EIP-712 — this is cryptographic proof they agreed to these terms."

---

## 1:30-2:00 - Live Demo Part 2: ZK Proof + Settlement

**Screen**: Terminal continuing

**Voiceover**:
> "Now we generate a zero-knowledge proof. This proves we have a valid quote commitment without revealing the exact quoted price onchain."

```bash
# Step 2: Generate Noir ZK proof
npm run taker:prove

# Output shows:
# Reading quote from quote.json...
# Computing Poseidon2 commitment...
# Writing Prover.toml...
# Generating proof (nargo prove)...
# Proof generated in 2.3s
# Proof saved to quote.json
```

> "The proof binds the commitment to our public inputs — pool, taker, amount, and expiry.
> The quoted output amount stays hidden inside the proof."

```bash
# Step 3: Commit + Execute swap
npm run taker:swap

# Output shows:
# Committing quote onchain...
# Commitment TX: 0x1111...2222
# Executing swap via Uniswap v4...
# Hook validated: signature, commitment, expiry, ZK proof
# Swap TX: 0x3333...4444
# Swap successful!
```

---

## 2:00-2:30 - Live Demo Part 3: Replay Protection

**Screen**: Terminal + Etherscan split view

**Voiceover**:
> "Now the critical test — what happens if someone tries to replay this quote?"

```bash
# Step 4: Attempt replay attack
npm run taker:swap  # Same quote, same proof

# Output shows:
# ERROR: RFQRegistry__CommitmentAlreadyUsed(0x1234...5678)
# Replay attack PREVENTED
```

> "The commitment was consumed atomically during the first swap.
> Any replay attempt — same quote, different taker, different pool — all fail.
> This is airtight, onchain-enforced protection."

**Visual cues**:
- Show the revert on Etherscan
- Show the consumed commitment in the registry

---

## 2:30-3:00 - Technical Highlights + TXIDs

**Screen**: GitHub README with deployment table

**Voiceover**:
> "Let me highlight what makes this different:
>
> The ZK proof is **mandatory** — the hook reverts without it. This isn't optional privacy, it's enforced.
>
> ENS is a **functional discovery layer** — not a vanity name. Makers publish endpoints and policy hashes that takers cryptographically verify.
>
> Every component is tested — 124 tests passing, 100% coverage on core contracts.
>
> Deployed to three testnets with verified contracts."

**Show on screen**:
- TXIDs table from README
- Gas benchmark table
- Test results (124 passing)
- ENS text records screenshot

> "All code is open source and the demo is reproducible with a single command: `./script/demo.sh`
>
> Waiola — private RFQ settlement on Uniswap v4 with ENS discovery and Noir ZK enforcement."

---

## Recording Checklist

- [ ] Terminal: iTerm2 or Windows Terminal, font size 18pt+, dark background
- [ ] Browser: Etherscan tabs pre-loaded for each TXID
- [ ] Architecture diagram open in separate tab
- [ ] All demo scripts tested end-to-end before recording
- [ ] Audio: clear voiceover, no background noise
- [ ] Resolution: 1080p minimum
- [ ] Total duration: under 3:00

## Tools

- **Recording**: OBS Studio or Loom
- **Diagrams**: Excalidraw (exported as SVG)
- **Terminal**: Large font (18pt+), clear contrast
- **Editing**: Trim dead time, add transitions between sections
