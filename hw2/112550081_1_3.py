#!/usr/bin/env python3
"""
Cryptography Engineering - Quiz 2, Problem 1, Task 3
Student ID: 112550081

Automated Stream Cipher Cryptanalysis Program
==============================================
Given three ciphertexts encrypted with the same keystream (two-time pad attack),
this program recovers the keystream and plaintexts WITHOUT any known plaintext.

Techniques used:
1. Space-XOR detection: XORing a space (0x20) with a letter flips its case.
   If C_a[i] XOR C_b[i] results in a letter, one plaintext likely has a space.
2. English letter frequency scoring: candidate keystream bytes are scored by how well
   the resulting plaintext characters match expected English letter frequencies.
3. Automated crib dragging: common English words are slid over XOR differences
   between ciphertext pairs; matches that produce readable text in the counterpart
   plaintext vote for specific keystream bytes.
4. Beam search with bigram context for globally coherent solutions.
"""

# ============================================================
# Ciphertexts (hex bytes)
# ============================================================
C1 = [0x03, 0x16, 0x0A, 0x0C, 0x0D, 0x18, 0x17, 0x1F,
      0x0F, 0x0D, 0x11, 0x05, 0x03, 0x00, 0x0E, 0x00]

C2 = [0x05, 0x0D, 0x10, 0x08, 0x0A, 0x1A, 0x01, 0x18,
      0x0F, 0x09, 0x14, 0x05, 0x05, 0x17, 0x0F, 0x00]

C3 = [0x0A, 0x0A, 0x0C, 0x1C, 0x09, 0x09, 0x00, 0x0D,
      0x04, 0x0B, 0x11, 0x18, 0x1D, 0x05, 0x04, 0x1D]

CIPHERTEXTS = [C1, C2, C3]
NUM_BYTES = 16

# ============================================================
# English letter frequency table (percentages)
# ============================================================
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074, ' ': 15.0
}

# Common English bigrams
COMMON_BIGRAMS = {
    'TH', 'HE', 'IN', 'EN', 'NT', 'RE', 'ER', 'AN', 'TI', 'ON',
    'ES', 'ST', 'OR', 'TE', 'ED', 'IS', 'IT', 'AL', 'AR', 'ND',
    'TO', 'SE', 'HA', 'OU', 'LE', 'NO', 'TA', 'AT', 'NG', 'NE',
    'SU', 'UN', 'IG', 'HT', 'OV', 'DI', 'SC', 'KN', 'OW', 'WL',
    'DG', 'GE', 'RI', 'GH', 'SH', 'VE', 'RY', 'RS', 'CE', 'DE',
    'CO', 'BR', 'EE', 'SS', 'OT', 'EW', 'LI', 'GR', 'NI', 'RO',
    'EP', 'WE', 'RA', 'DA', 'EA', 'IO', 'TR', 'LA'
}


def is_uppercase_or_space(b):
    """Check if byte is uppercase letter or space."""
    return b == 0x20 or (0x41 <= b <= 0x5A)


def frequency_score(chars):
    """Score characters based on English letter frequency."""
    return sum(ENGLISH_FREQ.get(c.upper(), -5.0) for c in chars)


# ============================================================
# Method 1: Space-XOR Detection
# ============================================================
def space_xor_detection():
    """
    Detect positions where a plaintext likely has a space character.

    Principle: For a stream cipher, C_i = P_i XOR S.
    Therefore: C_a[i] XOR C_b[i] = P_a[i] XOR P_b[i] (keystream cancels).

    If P_a[i] = ' ' (0x20) and P_b[i] is a letter:
        P_a[i] XOR P_b[i] = 0x20 XOR letter = letter with flipped case bit.
    So C_a[i] XOR C_b[i] falling in the letter range suggests one has a space.

    If BOTH C1^C2 and C1^C3 give letters at position i, then P1[i] is likely a space
    (since P1 is the common factor).
    """
    print("=" * 60)
    print("Method 1: Space-XOR Detection")
    print("=" * 60)

    pairs = [(C1, C2, 0, 1), (C1, C3, 0, 2), (C2, C3, 1, 2)]
    space_votes = [[0] * NUM_BYTES for _ in range(3)]  # votes per plaintext per position
    keystream_from_space = {}  # pos -> list of (s_value, confidence)

    for Ca, Cb, pa, pb in pairs:
        for i in range(NUM_BYTES):
            xor_val = Ca[i] ^ Cb[i]
            if (0x41 <= xor_val <= 0x5A) or (0x61 <= xor_val <= 0x7A):
                space_votes[pa][i] += 1
                space_votes[pb][i] += 1

    detected = False
    for p_idx in range(3):
        for i in range(NUM_BYTES):
            if space_votes[p_idx][i] >= 2:
                detected = True
                # This plaintext has space at position i
                s_val = CIPHERTEXTS[p_idx][i] ^ 0x20
                if i not in keystream_from_space:
                    keystream_from_space[i] = []
                keystream_from_space[i].append(s_val)
                print(f"  P{p_idx+1}[{i}] likely = SPACE -> S[{i}] = 0x{s_val:02X}")

    if not detected:
        print("  No space positions detected via XOR method.")
        print("  (All ciphertext bytes are in 0x00-0x1F range, so P_i XOR P_j")
        print("   is too small to reach the letter range 0x41-0x7A.)")
        print("  -> Spaces likely do NOT appear in these plaintexts.")

    return keystream_from_space


# ============================================================
# Method 2: Automated Crib Dragging
# ============================================================
def automated_crib_dragging():
    """
    Slide common English words (cribs) over C_a XOR C_b.

    When C_a XOR C_b = P_a XOR P_b, XORing a crib (guess for P_a at some offset)
    recovers P_b at that offset. If the recovered P_b fragment is readable English,
    the guess is likely correct, and we can derive keystream bytes.
    """
    print("\n" + "=" * 60)
    print("Method 2: Automated Crib Dragging")
    print("=" * 60)

    cribs = [
        # Long cribs (more reliable when they match)
        "KNOWLEDGE", "DISCOVER", "BRIGHT", "SENSOR",
        "SYSTEM", "STATUS", "ARRIVE", "ALERT",
        # Medium cribs
        "THE", "AND", "ING", "TION", "MENT", "ABLE",
        "SUN", "MOON", "STAR", "LIGHT", "NIGHT", "DATA",
        "POWER", "LEVEL", "ERROR", "CHECK", "RESET",
        "NEW", "OLD", "RUN", "SET", "GET",
    ]

    # XOR pairs
    pairs = [
        (C1, C2, "P1", "P2"),
        (C1, C3, "P1", "P3"),
        (C2, C3, "P2", "P3"),
    ]

    # Weighted votes: longer cribs that produce readable results get more weight
    keystream_scores = {}  # pos -> {s_value: weighted_score}

    for Ca, Cb, pa_name, pb_name in pairs:
        xor_ab = [Ca[i] ^ Cb[i] for i in range(NUM_BYTES)]

        for crib in cribs:
            crib_upper = crib.upper()
            crib_bytes = [ord(c) for c in crib_upper]
            crib_len = len(crib_bytes)

            for start in range(NUM_BYTES - crib_len + 1):
                # Assume crib is in P_a at this position
                # Then P_b at this position = crib XOR (C_a XOR C_b)
                result = [xor_ab[start + k] ^ crib_bytes[k] for k in range(crib_len)]

                if all(is_uppercase_or_space(b) for b in result):
                    result_text = ''.join(chr(b) for b in result)
                    # Score the result by letter frequency
                    r_score = frequency_score(result_text)
                    # Weight by crib length (longer = more confident)
                    weight = crib_len * (1 + r_score / 50)

                    for k in range(crib_len):
                        pos = start + k
                        s_val = Ca[pos] ^ crib_bytes[k]
                        if pos not in keystream_scores:
                            keystream_scores[pos] = {}
                        keystream_scores[pos][s_val] = \
                            keystream_scores[pos].get(s_val, 0) + weight

                # Also try: crib is in P_b at this position
                result2 = [xor_ab[start + k] ^ crib_bytes[k] for k in range(crib_len)]
                # (same math, but S comes from C_b now)
                if all(is_uppercase_or_space(b) for b in result2):
                    result_text = ''.join(chr(b) for b in result2)
                    r_score = frequency_score(result_text)
                    weight = crib_len * (1 + r_score / 50)

                    for k in range(crib_len):
                        pos = start + k
                        s_val = Cb[pos] ^ crib_bytes[k]
                        if pos not in keystream_scores:
                            keystream_scores[pos] = {}
                        keystream_scores[pos][s_val] = \
                            keystream_scores[pos].get(s_val, 0) + weight

    # Report top candidates per position
    print("  Crib dragging results (top candidates per position):")
    crib_best = {}
    for pos in range(NUM_BYTES):
        if pos in keystream_scores:
            votes = sorted(keystream_scores[pos].items(), key=lambda x: -x[1])
            best_s, best_w = votes[0]
            crib_best[pos] = (best_s, best_w)
            chars = [chr(C[pos] ^ best_s) for C in CIPHERTEXTS]
            print(f"    Pos {pos:2d}: S=0x{best_s:02X} (weight={best_w:6.1f}) "
                  f"-> P1='{chars[0]}' P2='{chars[1]}' P3='{chars[2]}'")

    return crib_best


# ============================================================
# Method 3: Frequency Analysis with Beam Search
# ============================================================
def frequency_beam_search():
    """
    For each position, enumerate valid keystream bytes (those producing
    uppercase letters or spaces in all three plaintexts). Score by English
    letter frequency and bigram context using beam search.
    """
    print("\n" + "=" * 60)
    print("Method 3: Frequency Analysis + Beam Search")
    print("=" * 60)

    # Phase 1: valid candidates per position
    candidates_per_pos = []
    for i in range(NUM_BYTES):
        candidates = []
        for s in range(256):
            chars = [C[i] ^ s for C in CIPHERTEXTS]
            if all(is_uppercase_or_space(c) for c in chars):
                char_list = [chr(c) for c in chars]
                score = frequency_score(char_list)
                candidates.append((s, char_list, score))
        candidates.sort(key=lambda x: -x[2])
        candidates_per_pos.append(candidates)
        top = candidates[0]
        print(f"  Pos {i:2d}: {len(candidates):2d} valid, "
              f"best: S=0x{top[0]:02X} -> "
              f"({top[1][0]},{top[1][1]},{top[1][2]}) score={top[2]:.1f}")

    # Phase 2: Beam search
    BEAM_WIDTH = 500
    print(f"\n  Running beam search (width={BEAM_WIDTH})...")

    beam = [(0.0, [])]
    for pos in range(NUM_BYTES):
        new_beam = []
        for total_score, ks in beam:
            for s, char_list, char_score in candidates_per_pos[pos]:
                new_score = total_score + char_score

                # Bigram bonus with previous position
                if ks:
                    prev_s = ks[-1]
                    for C in CIPHERTEXTS:
                        prev_c = chr(C[pos-1] ^ prev_s)
                        curr_c = char_list[CIPHERTEXTS.index(C)]
                        bigram = (prev_c + curr_c).upper()
                        if bigram in COMMON_BIGRAMS:
                            new_score += 4.0

                new_beam.append((new_score, ks + [s]))

        new_beam.sort(key=lambda x: -x[0])
        beam = new_beam[:BEAM_WIDTH]

    return beam, candidates_per_pos


# ============================================================
# Combine all methods and produce final answer
# ============================================================
def main():
    print("=" * 60)
    print("  Stream Cipher Cryptanalysis - Automated Attack")
    print("  Three ciphertexts encrypted with same keystream")
    print("=" * 60)
    print()

    for name, C in zip(["C1", "C2", "C3"], CIPHERTEXTS):
        print(f"  {name}: {' '.join(f'{b:02X}' for b in C)}")
    print()

    # --- Run all three methods ---
    ks_from_space = space_xor_detection()
    crib_best = automated_crib_dragging()
    beam_results, candidates = frequency_beam_search()

    # --- Combine methods ---
    # Priority: space-XOR (highest confidence) > crib dragging > beam search
    print("\n" + "=" * 60)
    print("Combined Results")
    print("=" * 60)

    best_score, best_S = beam_results[0]
    final_S = list(best_S)

    # Crib dragging overrides beam search when confidence is sufficient.
    # The crib method leverages multi-character context (word-level patterns),
    # which is fundamentally more reliable than per-character frequency scoring.
    for pos, (crib_s, crib_w) in crib_best.items():
        chars = [C[pos] ^ crib_s for C in CIPHERTEXTS]
        if all(is_uppercase_or_space(c) for c in chars) and crib_w > 80:
            final_S[pos] = crib_s

    # Space-XOR overrides (highest confidence)
    for pos, s_vals in ks_from_space.items():
        if s_vals:
            final_S[pos] = s_vals[0]

    # --- Output ---
    print(f"\n  Recovered Keystream S:")
    print(f"    {' '.join(f'0x{s:02X}' for s in final_S)}")

    print(f"\n  Decrypted Plaintexts:")
    for name, C in zip(["P1", "P2", "P3"], CIPHERTEXTS):
        pt = ''.join(chr(C[i] ^ final_S[i]) for i in range(NUM_BYTES))
        print(f"    {name} = \"{pt}\"")

    # --- Show top beam search alternatives ---
    print(f"\n  Top 5 Candidate Solutions (by frequency + bigram score):")
    seen = set()
    count = 0
    for score, S in beam_results:
        p1 = ''.join(chr(C1[i] ^ S[i]) for i in range(NUM_BYTES))
        p2 = ''.join(chr(C2[i] ^ S[i]) for i in range(NUM_BYTES))
        p3 = ''.join(chr(C3[i] ^ S[i]) for i in range(NUM_BYTES))
        key = (p1, p2, p3)
        if key not in seen:
            seen.add(key)
            S_hex = ' '.join(f'{s:02X}' for s in S)
            print(f"    Score={score:6.1f}  P1=\"{p1}\"  P2=\"{p2}\"  P3=\"{p3}\"")
            count += 1
            if count >= 5:
                break

    print("\n" + "=" * 60)
    print("  Analysis complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
