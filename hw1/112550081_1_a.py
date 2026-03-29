"""
Problem 1(a) - Frequency distribution of ciphertext letters
"""
from collections import Counter

ciphertext_raw = """GYOMXNOGNG QUGN ETNMX MPLMZOMXYM K TMMJOXA XEN TKZ ZMQEBMF TZEQ
KJKZQ EX YEXNMQLJKNOXA NHM TJEEF ET XMI CXEIJMFAM IHOYH
MKYH WMKZ RZOXAG IONH ON"""

ciphertext = ''.join(c for c in ciphertext_raw if c.isalpha()).upper()
freq = Counter(ciphertext)
total = len(ciphertext)

print(f"Ciphertext length: {total} letters\n")
print(f"{'Letter':<8} {'Count':<8} {'Frequency'}")
print("-" * 28)
for letter in sorted(freq, key=freq.get, reverse=True):
    bar = '#' * freq[letter]
    print(f"  {letter}     {freq[letter]:3d}      {100*freq[letter]/total:5.1f}%  {bar}")