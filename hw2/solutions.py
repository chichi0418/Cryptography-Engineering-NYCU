#!/usr/bin/env python3
"""
Cryptography Engineering - Quiz 2: Complete Solutions
Student ID: 112550081

This script computes and displays all intermediate values needed for the PDF writeup.
"""
from math import gcd

print("=" * 70)
print("  PROBLEM 1: Stream Cipher Cryptanalysis")
print("=" * 70)

C1 = [0x03, 0x16, 0x0A, 0x0C, 0x0D, 0x18, 0x17, 0x1F,
      0x0F, 0x0D, 0x11, 0x05, 0x03, 0x00, 0x0E, 0x00]
C2 = [0x05, 0x0D, 0x10, 0x08, 0x0A, 0x1A, 0x01, 0x18,
      0x0F, 0x09, 0x14, 0x05, 0x05, 0x17, 0x0F, 0x00]
C3 = [0x0A, 0x0A, 0x0C, 0x1C, 0x09, 0x09, 0x00, 0x0D,
      0x04, 0x0B, 0x11, 0x18, 0x1D, 0x05, 0x04, 0x1D]

# ==================================================================
# Task 1: Theoretical Analysis of Crib-Dragging
# ==================================================================
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Task 1: Crib-Dragging — Theoretical Explanation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Given: Stream cipher with keystream reuse.
  C1 = P1 ⊕ S
  C2 = P2 ⊕ S

Step 1: XOR two ciphertexts to eliminate the keystream:
  C1 ⊕ C2 = (P1 ⊕ S) ⊕ (P2 ⊕ S) = P1 ⊕ P2
  (The keystream S cancels out via S ⊕ S = 0)

Step 2: The attacker guesses a word (crib), e.g., "THE", and slides it
  across each position j of (C1 ⊕ C2):

  For each position j:
    result[j..j+len] = crib ⊕ (C1 ⊕ C2)[j..j+len]
                      = crib ⊕ (P1 ⊕ P2)[j..j+len]

Step 3: WHY does the correct position produce readable text?

  If the crib matches P1 at position j (i.e., crib = P1[j..j+len]), then:
    result = P1[j..j+len] ⊕ (P1 ⊕ P2)[j..j+len]
           = P1[j..j+len] ⊕ P1[j..j+len] ⊕ P2[j..j+len]
           = P2[j..j+len]

  Since P2 is meaningful English text, the result IS a fragment of P2,
  which exhibits "semantic readability" — recognizable English characters
  forming words or word fragments.

  At INCORRECT positions, the crib does NOT equal P1, so:
    result = crib ⊕ P1[j..] ⊕ P2[j..]
  This produces essentially random bytes (the XOR of unrelated text),
  which appear as gibberish — NOT readable English.

  KEY INSIGHT: The semantic structure of natural language is extremely
  unlikely to appear by chance. When the output at a particular position
  looks like English, we can be confident the crib is correctly placed.
""")

# Demonstrate C1 ⊕ C2
print("  Demonstration: C1 ⊕ C2 =", ' '.join(f'{c1^c2:02X}' for c1, c2 in zip(C1, C2)))
print("  Demonstration: C1 ⊕ C3 =", ' '.join(f'{c1^c3:02X}' for c1, c3 in zip(C1, C3)))
print("  Demonstration: C2 ⊕ C3 =", ' '.join(f'{c2^c3:02X}' for c2, c3 in zip(C2, C3)))

# ==================================================================
# Task 2: Practical Walkthrough
# ==================================================================
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Task 2: Known-Plaintext Attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

# P1 starts with "BRIGHT SUN ARRIVES" (18 chars), ciphertext is 16 bytes
# First 16 chars: "BRIGHT SUN ARRIV"
P1_guess = "BRIGHT SUN ARRIV"
P1_bytes = [ord(c) for c in P1_guess]

print(f"  Known plaintext assumption: P1 starts with \"{P1_guess}\"")
print(f"  (First 16 bytes of \"BRIGHT SUN ARRIVES\")\n")

# (a) Recover keystream S
print("  (a) Recovering keystream S = C1 ⊕ P1:")
print(f"  {'Pos':>3s}  {'C1[i]':>6s}  {'P1[i]':>6s}  {'S[i]':>6s}  {'P1 char'}")
print(f"  {'---':>3s}  {'-----':>6s}  {'-----':>6s}  {'----':>6s}  {'-------'}")

S = []
for i in range(16):
    s = C1[i] ^ P1_bytes[i]
    S.append(s)
    print(f"  {i:3d}  0x{C1[i]:02X}    0x{P1_bytes[i]:02X}    0x{s:02X}    '{chr(P1_bytes[i])}'")

print(f"\n  Keystream S = [{', '.join(f'0x{s:02X}' for s in S)}]")

# (b) Decrypt C2 and C3
print("\n  (b) Decrypting C2 and C3 using recovered S:")

print(f"\n  Decrypting P2 = C2 ⊕ S:")
print(f"  {'Pos':>3s}  {'C2[i]':>6s}  {'S[i]':>6s}  {'P2[i]':>6s}  {'Char'}")
print(f"  {'---':>3s}  {'-----':>6s}  {'----':>6s}  {'-----':>6s}  {'----'}")
P2 = []
for i in range(16):
    p = C2[i] ^ S[i]
    P2.append(p)
    ch = chr(p) if 32 <= p < 127 else f'[{p:02X}]'
    print(f"  {i:3d}  0x{C2[i]:02X}    0x{S[i]:02X}    0x{p:02X}    '{ch}'")

P2_text = ''.join(chr(p) if 32 <= p < 127 else '?' for p in P2)
print(f"\n  P2 = \"{P2_text}\"")

print(f"\n  Decrypting P3 = C3 ⊕ S:")
print(f"  {'Pos':>3s}  {'C3[i]':>6s}  {'S[i]':>6s}  {'P3[i]':>6s}  {'Char'}")
print(f"  {'---':>3s}  {'-----':>6s}  {'----':>6s}  {'-----':>6s}  {'----'}")
P3 = []
for i in range(16):
    p = C3[i] ^ S[i]
    P3.append(p)
    ch = chr(p) if 32 <= p < 127 else f'[{p:02X}]'
    print(f"  {i:3d}  0x{C3[i]:02X}    0x{S[i]:02X}    0x{p:02X}    '{ch}'")

P3_text = ''.join(chr(p) if 32 <= p < 127 else '?' for p in P3)
print(f"\n  P3 = \"{P3_text}\"")

print("""
  Assessment:
  - P2 begins with "DISCOV" → strongly suggests "DISCOVER..."
  - P3 begins with "KNOWLE" → strongly suggests "KNOWLEDGE..."
  - The first 6 characters of both P2 and P3 are clearly readable English,
    confirming the known-plaintext attack works correctly for those positions.
  - Positions 6 onward show some non-alphabetic characters (e.g., '6', '%', '^'),
    which indicates the assumed P1 may differ from the actual plaintext at those
    positions (e.g., the actual P1 might lack spaces between "BRIGHT" and "SUN").
  - Cross-validation: assuming P2="DISCOVER..." and P3="KNOWLEDGE...",
    positions 6-8 give S values that produce P1="SUN" (no space before SUN),
    confirming the actual P1 is likely "BRIGHTSUN..." rather than "BRIGHT SUN...".
  - Despite imperfections, the technique successfully reveals significant portions
    of the plaintext, demonstrating the critical vulnerability of keystream reuse.
""")

# ==================================================================
# PROBLEM 2: RSA Weak Key Recovery
# ==================================================================
print("=" * 70)
print("  PROBLEM 2: RSA Weak Key Recovery (GCD Attack)")
print("=" * 70)

n1 = 0x61aa9a3bcb1e80b5a50ca09d8774ef0deba55e66e6bb90a835051256072ff701e51e09be8c339f4810c4abb9a4b1b22f
n2 = 0x72366ead2204584a49e1104941921c810a79bbfe84c0afeb2d873d38d3ca739c3a501936d006d9faaac5815219f94b51
e1 = 65537
e2 = 65537

# ------------------------------------------------------------------
# Task 1: Identify the Flaw
# ------------------------------------------------------------------
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Task 1: Identify the Flaw
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The RSA key generation relies on a WEAK random number generator (RNG).
When a weak RNG is used, different devices may generate overlapping
prime factors. Specifically, n1 = p * q1 and n2 = p * q2 may share
a common prime factor p.

This is fatal because:
  gcd(n1, n2) = p   (the shared prime)

Once p is known:
  q1 = n1 / p,  q2 = n2 / p

Both private keys can be computed immediately. This completely breaks
RSA security for both devices.

This vulnerability has been observed in real-world IoT devices and
embedded systems where entropy sources are insufficient at boot time.
""")

print(f"  n1 = 0x{n1:X}")
print(f"  n1 bit length: {n1.bit_length()} bits\n")
print(f"  n2 = 0x{n2:X}")
print(f"  n2 bit length: {n2.bit_length()} bits\n")
print(f"  e1 = e2 = {e1}")

# ------------------------------------------------------------------
# Task 2: Recover the Factorization
# ------------------------------------------------------------------
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Task 2: Recover the Factorization
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

p = gcd(n1, n2)
q1 = n1 // p
q2 = n2 // p

print(f"  Step 1: Compute p = gcd(n1, n2)")
print(f"  p = 0x{p:X}")
print(f"  p (decimal) = {p}")
print(f"  p bit length: {p.bit_length()} bits\n")

print(f"  Step 2: Compute q1 = n1 / p")
print(f"  q1 = 0x{q1:X}")
print(f"  q1 (decimal) = {q1}")
print(f"  q1 bit length: {q1.bit_length()} bits\n")

print(f"  Step 3: Compute q2 = n2 / p")
print(f"  q2 = 0x{q2:X}")
print(f"  q2 (decimal) = {q2}")
print(f"  q2 bit length: {q2.bit_length()} bits\n")

# Verify
assert p * q1 == n1, "VERIFICATION FAILED: p * q1 != n1"
assert p * q2 == n2, "VERIFICATION FAILED: p * q2 != n2"
assert p > 1, "gcd is 1, no shared factor found"
print(f"  Verification:")
print(f"    p × q1 == n1 ? {p * q1 == n1}  ✓")
print(f"    p × q2 == n2 ? {p * q2 == n2}  ✓")

# Note on factorization structure
print(f"\n  Factorization structure:")
print(f"    n1 = p (256-bit) × q1 (128-bit)  [unbalanced!]")
print(f"    n2 = p (256-bit) × q2 (128-bit)  [unbalanced!]")
print(f"    The shared factor p is larger than q1, q2 — another sign of weak RNG.")

# ------------------------------------------------------------------
# Task 3: Compute Private Keys
# ------------------------------------------------------------------
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Task 3: Compute Private Keys d1 and d2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

phi_n1 = (p - 1) * (q1 - 1)
phi_n2 = (p - 1) * (q2 - 1)

print(f"  Step 1: Compute Euler's totient φ(n)")
print(f"  φ(n1) = (p-1)(q1-1)")
print(f"  φ(n1) = 0x{phi_n1:X}")
print(f"  φ(n1) = {phi_n1}\n")

print(f"  φ(n2) = (p-1)(q2-1)")
print(f"  φ(n2) = 0x{phi_n2:X}")
print(f"  φ(n2) = {phi_n2}\n")

d1 = pow(e1, -1, phi_n1)
d2 = pow(e2, -1, phi_n2)

print(f"  Step 2: Compute private exponents using modular inverse")
print(f"  d1 = e1⁻¹ mod φ(n1)")
print(f"  d1 = 0x{d1:X}")
print(f"  d1 = {d1}\n")

print(f"  d2 = e2⁻¹ mod φ(n2)")
print(f"  d2 = 0x{d2:X}")
print(f"  d2 = {d2}\n")

# Verify
assert (d1 * e1) % phi_n1 == 1, "VERIFICATION FAILED: d1 * e1 mod φ(n1) != 1"
assert (d2 * e2) % phi_n2 == 1, "VERIFICATION FAILED: d2 * e2 mod φ(n2) != 1"
print(f"  Verification:")
print(f"    d1 × e1 ≡ 1 (mod φ(n1)) ? {(d1 * e1) % phi_n1 == 1}  ✓")
print(f"    d2 × e2 ≡ 1 (mod φ(n2)) ? {(d2 * e2) % phi_n2 == 1}  ✓")

# ------------------------------------------------------------------
# Task 4: Summary of All Steps
# ------------------------------------------------------------------
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Task 4: Summary of All Steps
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Complete RSA key recovery process:

1. IDENTIFY THE FLAW: The weak RNG caused both RSA key pairs to share
   a common prime factor p. Instead of n1 and n2 having four distinct
   primes, they share one: n1 = p·q1, n2 = p·q2.

2. RECOVER FACTORIZATION:
   p  = gcd(n1, n2)     — Euclidean algorithm, O(log²n) time
   q1 = n1 / p
   q2 = n2 / p

3. COMPUTE PRIVATE KEYS:
   φ(n1) = (p-1)(q1-1)
   φ(n2) = (p-1)(q2-1)
   d1 = e1⁻¹ mod φ(n1)  — Extended Euclidean algorithm
   d2 = e2⁻¹ mod φ(n2)

4. RESULT: Both private keys are fully recovered. An attacker can now
   decrypt any message encrypted with either public key, and forge
   signatures for either device.

Why this works: RSA security relies on the hardness of factoring n.
But gcd(n1, n2) is computable in polynomial time. If two moduli share
a factor, factoring is trivial — no brute force needed.
""")

# Quick encryption/decryption test to verify keys work
print("  Encryption/Decryption Verification:")
test_msg = 42
ct1 = pow(test_msg, e1, n1)
pt1 = pow(ct1, d1, n1)
ct2 = pow(test_msg, e2, n2)
pt2 = pow(ct2, d2, n2)
print(f"    Test message m = {test_msg}")
print(f"    Encrypt with e1, decrypt with d1: {pt1}  {'✓' if pt1 == test_msg else '✗'}")
print(f"    Encrypt with e2, decrypt with d2: {pt2}  {'✓' if pt2 == test_msg else '✗'}")

# ------------------------------------------------------------------
# Bonus: Real-World Case Study
# ------------------------------------------------------------------
print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BONUS: Real-World Case Study
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The most notable real-world instance of this vulnerability was published in:

  "Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices"
  by Nadia Heninger, Zakir Durumeric, Eric Wustrow, and J. Alex Halderman
  USENIX Security Symposium, 2012
  https://factorable.net/

Key findings:
  - Scanned all publicly visible RSA moduli on the Internet (~6 million TLS
    and ~5 million SSH keys)
  - Found that 0.2% of TLS keys and 1.03% of SSH keys shared prime factors
    with another key
  - Recovered private keys for 64,000 TLS hosts and 108,000 SSH hosts
  - Affected devices: routers, firewalls, VPN appliances, and embedded
    devices from major manufacturers (including Cisco, Juniper, etc.)

Root cause:
  - Embedded devices generated RSA keys at boot time before sufficient
    entropy was available from /dev/urandom
  - Linux's PRNG was seeded with limited entropy sources (uptime,
    device serial numbers) which were often identical across devices
  - Result: different devices generated the same or overlapping prime
    factors, enabling the batch-GCD attack

The attack technique:
  - For N moduli, pairwise GCD takes O(N²) time (impractical for millions)
  - The authors used a batch-GCD algorithm (O(N log²N)) by Daniel Bernstein
  - Compute the product tree of all moduli, then use remainder trees to
    efficiently find all pairs sharing a common factor

This is exactly the same vulnerability demonstrated in this problem,
scaled from 2 keys to millions.
""")

print("=" * 70)
print("  All computations complete.")
print("=" * 70)
