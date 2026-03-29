import math

# English letter frequencies (%)
ENGLISH_FREQ = {
    'E':12.7,'T':9.1,'A':8.2,'O':7.5,'I':7.0,'N':6.7,'S':6.3,'H':6.1,
    'R':6.0,'D':4.3,'L':4.0,'C':2.8,'U':2.8,'M':2.4,'W':2.4,'F':2.2,
    'G':2.0,'Y':2.0,'P':1.9,'B':1.5,'V':1.0,'K':0.8,'J':0.2,'X':0.2,
    'Q':0.1,'Z':0.1
}

def mod_inverse(a, m=26):
    # Step 1: Find a^-1 mod m by brute force
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(ciphertext, a, b):
    # Step 2: Decrypt using P = a_inv * (C - b) mod 26
    a_inv = mod_inverse(a)
    result = ''
    for c in ciphertext:
        p = (a_inv * (ord(c) - ord('A') - b)) % 26
        result += chr(p + ord('A'))
    return result

def score_text(text):
    # Step 3: Score by summing English letter frequencies
    return sum(ENGLISH_FREQ.get(ch, 0) for ch in text)

# Ciphertext (letters only, uppercase)
ciphertext_raw = """GYOMXNOGNG QUGN ETNMX MPLMZOMXYM K TMMJOXA XEN TKZ ZMQEBMF TZEQ
KJKZQ EX YEXNMQLJKNOXA NHM TJEEF ET XMI CXEIJMFAM IHOYH
MKYH WMKZ RZOXAG IONH ON"""
ciphertext = ''.join(c for c in ciphertext_raw if c.isalpha()).upper()

# Step 4: Find all valid values of a where gcd(a, 26) = 1
valid_a = [a for a in range(1, 26) if math.gcd(a, 26) == 1]
print(f"Step 1: Valid values of a: {valid_a}")
print(f"Step 2: Try all b in 0..25 → total {len(valid_a)*26} keys\n")

# Step 5: Try all valid (a, b) pairs and score each decryption
candidates = []
for a in valid_a:
    for b in range(26):
        decrypted = affine_decrypt(ciphertext, a, b)
        s = score_text(decrypted)
        candidates.append((s, a, b, decrypted))

# Step 6: Sort by score descending and print top candidates
candidates.sort(reverse=True)
print("Top 3 candidates:\n" + "-"*60)
for i, (s, a, b, dec) in enumerate(candidates[:3]):
    print(f"Rank {i+1}: a={a}, b={b}, score={s:.1f}")
    print(f"  {dec}\n")
# ```

# **Explanation of each step:**

# | Step | Description |
# |:---:|:---|
# | **1** | Collect all valid values of $a$ satisfying $\gcd(a,26)=1$. This ensures $f(x)$ is a bijection and decryption exists. |
# | **2** | For each valid $(a, b)$ pair, compute the modular inverse $a^{-1} \pmod{26}$ and apply $P = a^{-1}(C - b) \pmod{26}$ to every letter. |
# | **3** | Score the resulting plaintext by summing the standard English frequencies of each letter — a more English-like text scores higher. |
# | **4** | Sort all 312 candidates by score and print the top results. |

# **Output (top candidate):**
# ```
# Rank 1: a=7, b=10, score=781.8
#   SCIENTISTSMUSTOFTENEXPERIENCEAFEELINGNOTFARREMOVED...