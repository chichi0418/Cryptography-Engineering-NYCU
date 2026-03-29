import numpy as np
import math

# ═══════════════════════════════════════════
#  KEYS
# ═══════════════════════════════════════════
AFFINE_A, AFFINE_B = 7, 10
TRANS_KEY = [2, 0, 1]
HILL_K = np.array([[6,24,1],[13,16,10],[20,17,15]])

# ═══════════════════════════════════════════
#  HELPER
# ═══════════════════════════════════════════
def mod_inverse(a, m=26):
    """Find a^-1 mod m."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(K, m=26):
    """Compute K^-1 mod m via adjugate."""
    det = int(round(np.linalg.det(K))) % m
    assert math.gcd(det, m) == 1, "Matrix not invertible mod 26!"
    det_inv = mod_inverse(det, m)
    n = K.shape[0]
    cofactors = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(K, i, 0), j, 1)
            cofactors[i][j] = ((-1)**(i+j)) * int(round(np.linalg.det(minor)))
    return (det_inv * cofactors.T) % m

# ═══════════════════════════════════════════
#  STAGE 1 : AFFINE CIPHER
#  Encrypt : C = (a*P + b) mod 26
#  Decrypt : P = a_inv*(C - b) mod 26
# ═══════════════════════════════════════════
def affine_encrypt(text, a=AFFINE_A, b=AFFINE_B):
    return ''.join(chr((a*(ord(c)-65)+b) % 26 + 65) for c in text)

def affine_decrypt(text, a=AFFINE_A, b=AFFINE_B):
    a_inv = mod_inverse(a)
    return ''.join(chr((a_inv*(ord(c)-65-b)) % 26 + 65) for c in text)

# ═══════════════════════════════════════════
#  STAGE 2 : COLUMNAR TRANSPOSITION CIPHER
#  Encrypt : write rows, read columns by key
#  Decrypt : inverse column reordering
# ═══════════════════════════════════════════
def transposition_encrypt(text, key=TRANS_KEY):
    ncols = len(key)
    while len(text) % ncols:
        text += 'X'                          # pad with X if needed
    nrows = len(text) // ncols
    grid = [text[i*ncols:(i+1)*ncols] for i in range(nrows)]
    # read columns in sorted-key order
    return ''.join(grid[r][c]
                   for c in sorted(range(ncols), key=lambda x: key[x])
                   for r in range(nrows))

def transposition_decrypt(text, key=TRANS_KEY):
    ncols = len(key)
    nrows = len(text) // ncols
    sorted_cols = sorted(range(ncols), key=lambda x: key[x])
    cols = {c: text[i*nrows:(i+1)*nrows] for i, c in enumerate(sorted_cols)}
    return ''.join(cols[c][r] for r in range(nrows) for c in range(ncols))

# ═══════════════════════════════════════════
#  STAGE 3 : HILL CIPHER
#  Encrypt : c = K * p  (mod 26), block size = n
#  Decrypt : p = K^-1 * c  (mod 26)
# ═══════════════════════════════════════════
def hill_encrypt(text, K=HILL_K):
    n = K.shape[0]
    while len(text) % n:
        text += 'X'
    result = ''
    for i in range(0, len(text), n):
        vec = np.array([ord(c)-65 for c in text[i:i+n]])
        enc = np.dot(K, vec) % 26
        result += ''.join(chr(int(x)+65) for x in enc)
    return result

def hill_decrypt(text, K=HILL_K):
    K_inv = matrix_mod_inverse(K)
    n = K.shape[0]
    result = ''
    for i in range(0, len(text), n):
        vec = np.array([ord(c)-65 for c in text[i:i+n]])
        dec = np.dot(K_inv, vec) % 26
        result += ''.join(chr(int(x)+65) for x in dec)
    return result

# ═══════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════
if __name__ == "__main__":
    plaintext = "CRYPTOGRAPHY"

    print("=" * 52)
    print("           ENCRYPTION PROCESS")
    print("=" * 52)
    print(f"Original Plaintext     : {plaintext}")
    print()

    s1 = affine_encrypt(plaintext)
    print(f"[Stage 1] Affine Cipher  (a={AFFINE_A}, b={AFFINE_B})")
    print(f"  Formula  : C = (7P + 10) mod 26")
    print(f"  Output   : {s1}")
    print()

    s2 = transposition_encrypt(s1)
    print(f"[Stage 2] Columnar Transposition  (key={TRANS_KEY})")
    print(f"  Formula  : write into rows, read columns by key order")
    print(f"  Output   : {s2}")
    print()

    s3 = hill_encrypt(s2)
    print(f"[Stage 3] Hill Cipher  (3x3 key matrix K)")
    print(f"  Formula  : c = K * p  (mod 26)")
    print(f"  Output   : {s3}")
    print()
    print(f"Final Ciphertext       : {s3}")

    print()
    print("=" * 52)
    print("           DECRYPTION PROCESS")
    print("=" * 52)

    d1 = hill_decrypt(s3)
    print(f"[Stage 3 inv] Hill Decrypt")
    print(f"  Formula  : p = K^-1 * c  (mod 26)")
    print(f"  Output   : {d1}")
    print()

    d2 = transposition_decrypt(d1)
    print(f"[Stage 2 inv] Transposition Decrypt")
    print(f"  Formula  : reverse column reordering")
    print(f"  Output   : {d2}")
    print()

    d3 = affine_decrypt(d2)
    print(f"[Stage 1 inv] Affine Decrypt")
    print(f"  Formula  : P = 15*(C - 10)  mod 26")
    print(f"  Output   : {d3}")
    print()

    print(f"Recovered Plaintext    : {d3}")
    print(f"Original  Plaintext    : {plaintext}")
    print(f"Verification           : {'PASS ✓' if d3.startswith(plaintext) else 'FAIL ✗'}")
# ```

# ---

# ### Output
# ```
# ====================================================
#            ENCRYPTION PROCESS
# ====================================================
# Original Plaintext     : CRYPTOGRAPHY

# [Stage 1] Affine Cipher  (a=7, b=10)
#   Formula  : C = (7P + 10) mod 26
#   Output   : YZWLNEAZKLHW

# [Stage 2] Columnar Transposition  (key=[2, 0, 1])
#   Formula  : write into rows, read columns by key order
#   Output   : ZNZHWEKWYLAL

# [Stage 3] Hill Cipher  (3x3 key matrix K)
#   Formula  : c = K * p  (mod 26)
#   Output   : TDECPCOUYZTV

# Final Ciphertext       : TDECPCOUYZTV

# ====================================================
#            DECRYPTION PROCESS
# ====================================================
# [Stage 3 inv] Hill Decrypt
#   Formula  : p = K^-1 * c  (mod 26)
#   Output   : ZNZHWEKWYLAL

# [Stage 2 inv] Transposition Decrypt
#   Formula  : reverse column reordering
#   Output   : YZWLNEAZKLHW

# [Stage 1 inv] Affine Decrypt
#   Formula  : P = 15*(C - 10)  mod 26
#   Output   : CRYPTOGRAPHY

# Recovered Plaintext    : CRYPTOGRAPHY
# Original  Plaintext    : CRYPTOGRAPHY
# Verification           : PASS ✓