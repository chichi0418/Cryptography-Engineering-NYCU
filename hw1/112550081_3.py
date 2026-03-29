import numpy as np
import math

K = np.array([[6,24,1],[13,16,10],[20,17,15]])

def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(K, m=26):
    # Step 1: Compute determinant
    det = int(round(np.linalg.det(K))) % m
    print(f"det(K) mod 26 = {det}")

    # Step 2: Verify gcd(det, 26) = 1
    assert math.gcd(det, m) == 1, "Matrix not invertible mod 26!"
    print(f"gcd({det}, 26) = 1 → Valid ✓")

    # Step 3: Modular inverse of determinant
    det_inv = mod_inverse(det, m)
    print(f"det_inv = {det_inv}")

    # Step 4: Compute adjugate matrix
    n = K.shape[0]
    cofactors = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            minor = np.delete(np.delete(K, i, axis=0), j, axis=1)
            cofactors[i][j] = ((-1)**(i+j)) * int(round(np.linalg.det(minor)))
    adj = cofactors.T
    print(f"Adjugate:\n{adj}")

    # Step 5: K_inv = det_inv * adj mod 26
    K_inv = (det_inv * adj) % m
    print(f"K_inv mod 26:\n{K_inv}")
    return K_inv

K_inv = matrix_mod_inverse(K)

# Step 6: Verify
assert np.array_equal(np.dot(K, K_inv) % 26,
                      np.eye(3, dtype=int)), "Verification failed!"
print("K × K_inv = I mod 26 ✓")

# Step 7: Decrypt AJN
c = np.array([0, 9, 13])  # A=0, J=9, N=13
p = np.dot(K_inv, c) % 26
print("Decrypted:", ''.join(chr(int(x)+65) for x in p))


# **Output:**
# ```
# det(K) mod 26 = 25
# gcd(25, 26) = 1 → Valid ✓
# det_inv = 25
# K_inv mod 26:
# [[ 8  5 10]
#  [21  8 21]
#  [21 12  8]]
# K × K_inv = I mod 26 ✓
# Decrypted: THE
# ```