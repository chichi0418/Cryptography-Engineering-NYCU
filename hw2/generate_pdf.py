#!/usr/bin/env python3
"""Generate 112550081.pdf from the solution content using reportlab."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.colors import HexColor, black, white, grey
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib import colors

# ── PDF Setup ──
pdf_path = "/Users/jacky/nycu/senior/crypto/hw2/112550081.pdf"
doc = SimpleDocTemplate(
    pdf_path,
    pagesize=A4,
    topMargin=1.8*cm,
    bottomMargin=1.8*cm,
    leftMargin=2*cm,
    rightMargin=2*cm,
)

styles = getSampleStyleSheet()

# ── Custom Styles ──
styles.add(ParagraphStyle(
    name='DocTitle', parent=styles['Title'],
    fontSize=20, spaceAfter=4, leading=24,
))
styles.add(ParagraphStyle(
    name='Subtitle', parent=styles['Normal'],
    fontSize=12, alignment=TA_CENTER, spaceAfter=16, textColor=HexColor('#444444'),
))
styles.add(ParagraphStyle(
    name='H1', parent=styles['Heading1'],
    fontSize=16, spaceBefore=20, spaceAfter=8, textColor=HexColor('#1a1a2e'),
))
styles.add(ParagraphStyle(
    name='H2', parent=styles['Heading2'],
    fontSize=13, spaceBefore=14, spaceAfter=6, textColor=HexColor('#16213e'),
))
styles.add(ParagraphStyle(
    name='H3', parent=styles['Heading3'],
    fontSize=11, spaceBefore=10, spaceAfter=4, textColor=HexColor('#0f3460'),
))
styles.add(ParagraphStyle(
    name='Body', parent=styles['Normal'],
    fontSize=10, leading=14, spaceAfter=6,
))
styles.add(ParagraphStyle(
    name='Formula', parent=styles['Normal'],
    fontSize=10, leading=14, alignment=TA_CENTER, spaceAfter=8, spaceBefore=4,
    fontName='Courier', textColor=HexColor('#333333'),
))
styles.add(ParagraphStyle(
    name='CodeBlock', parent=styles['Normal'],
    fontSize=9, leading=12, fontName='Courier',
    leftIndent=20, spaceAfter=4, textColor=HexColor('#2d2d2d'),
))
styles.add(ParagraphStyle(
    name='BulletItem', parent=styles['Normal'],
    fontSize=10, leading=14, leftIndent=20, spaceAfter=4,
    bulletIndent=8, bulletFontSize=10,
))
styles.add(ParagraphStyle(
    name='SmallNote', parent=styles['Normal'],
    fontSize=9, leading=12, leftIndent=20, textColor=HexColor('#555555'),
    spaceAfter=6, spaceBefore=2,
))
styles.add(ParagraphStyle(
    name='CellStyle', parent=styles['Normal'],
    fontSize=8, leading=10,
))
styles.add(ParagraphStyle(
    name='CellCode', parent=styles['Normal'],
    fontSize=7.5, leading=10, fontName='Courier',
))
styles.add(ParagraphStyle(
    name='CellBold', parent=styles['Normal'],
    fontSize=8, leading=10, fontName='Helvetica-Bold',
))

# ── Helpers ──
def hr():
    return HRFlowable(width="100%", thickness=0.5, color=HexColor('#cccccc'), spaceAfter=8, spaceBefore=8)

def sp(pts=6):
    return Spacer(1, pts)

def make_table(data, col_widths=None, header=True):
    """Create a styled table."""
    style_cmds = [
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('LEADING', (0, 0), (-1, -1), 11),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.4, HexColor('#cccccc')),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]
    if header and len(data) > 1:
        style_cmds += [
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e8eaf6')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
        ]
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle(style_cmds))
    return t

story = []

# ══════════════════════════════════════════════
# TITLE
# ══════════════════════════════════════════════
story.append(Paragraph("Cryptography Engineering — Quiz 2", styles['DocTitle']))
story.append(Paragraph("<b>Student ID:</b> 112550081", styles['Subtitle']))
story.append(hr())

# ══════════════════════════════════════════════
# PROBLEM 1
# ══════════════════════════════════════════════
story.append(Paragraph("Problem 1 — Stream Cipher Cryptanalysis", styles['H1']))

story.append(Paragraph("<b>Background:</b> Three ciphertexts encrypted with the same keystream S (16 bytes each):", styles['Body']))

story.append(make_table([
    ['', 'Hex Bytes'],
    ['C1', '03 16 0A 0C 0D 18 17 1F 0F 0D 11 05 03 00 0E 00'],
    ['C2', '05 0D 10 08 0A 1A 01 18 0F 09 14 05 05 17 0F 00'],
    ['C3', '0A 0A 0C 1C 09 09 00 0D 04 0B 11 18 1D 05 04 1D'],
], col_widths=[1.2*cm, None]))
story.append(sp())

# ── Task 1 ──
story.append(hr())
story.append(Paragraph("Task 1 — Theoretical Analysis (2 pts)", styles['H2']))
story.append(Paragraph("Crib-Dragging Attack Explanation", styles['H3']))

story.append(Paragraph(
    "<b>Setup:</b> In a stream cipher, encryption is: C<sub>i</sub> = P<sub>i</sub> XOR S, "
    "where P<sub>i</sub> is the plaintext and S is the keystream. When the <b>same keystream</b> S "
    "is reused, the attacker XORs two ciphertexts:", styles['Body']))

story.append(Paragraph("C1 XOR C2 = (P1 XOR S) XOR (P2 XOR S) = P1 XOR P2", styles['Formula']))

story.append(Paragraph(
    "The keystream S <b>cancels out</b> (since S XOR S = 0), leaving only the XOR of the two plaintexts.", styles['Body']))

story.append(Paragraph("<b>Crib-Dragging Procedure:</b>", styles['Body']))
story.append(Paragraph("1. The attacker computes D = C1 XOR C2 = P1 XOR P2.", styles['BulletItem']))
story.append(Paragraph('2. A guessed word (crib), e.g. "THE", is slid position-by-position over D.', styles['BulletItem']))
story.append(Paragraph("3. At each position j, the attacker computes: result = crib XOR D[j ... j+len]", styles['BulletItem']))

story.append(sp(4))
story.append(Paragraph("<b>Why does the correct position produce readable text?</b>", styles['Body']))

story.append(Paragraph(
    "If the crib correctly matches P1 at position j (i.e., crib = P1[j..j+len]), then:", styles['BulletItem']))
story.append(Paragraph(
    "result = P1[j..] XOR (P1 XOR P2)[j..] = P1[j..] XOR P1[j..] XOR P2[j..] = P2[j..]", styles['Formula']))
story.append(Paragraph(
    "The result is exactly the <b>corresponding fragment of P2</b>, which is meaningful English text "
    "exhibiting <b>semantic readability</b> (recognizable words, letter patterns).", styles['BulletItem']))

story.append(Paragraph(
    "At <b>incorrect positions</b>, the crib does NOT equal P1, so: "
    "result = crib XOR P1[j..] XOR P2[j..]. "
    "This produces the XOR of unrelated text fragments, resulting in <b>random-looking gibberish</b>. "
    "The probability of random bytes forming readable English is extremely low.", styles['BulletItem']))

story.append(Paragraph(
    "<b>Key Insight:</b> Natural language has strong statistical structure (letter frequencies, word patterns). "
    "Readable output at a specific position is a reliable signal that the crib is correctly placed, "
    "allowing the attacker to recover both plaintext fragments and the corresponding keystream bytes.", styles['Body']))

story.append(Paragraph("<b>Demonstration:</b>", styles['Body']))
story.append(make_table([
    ['Pair', 'XOR Result'],
    ['C1 XOR C2', '06 1B 1A 04 07 02 16 07 00 04 05 00 06 17 01 00'],
    ['C1 XOR C3', '09 1C 06 10 04 11 17 12 0B 06 00 1D 1E 05 0A 1D'],
    ['C2 XOR C3', '0F 07 1C 14 03 13 01 15 0B 02 05 1D 18 12 0B 1D'],
], col_widths=[2.5*cm, None]))

# ── Task 2 ──
story.append(hr())
story.append(Paragraph("Task 2 — Practical Walkthrough (1 pt)", styles['H2']))
story.append(Paragraph(
    '<b>Given:</b> P1 starts with "BRIGHT SUN ARRIVES" (18 characters). Since the ciphertext is only '
    '16 bytes, we use the first 16 characters: <b>"BRIGHT SUN ARRIV"</b>.', styles['Body']))

story.append(Paragraph("(a) Recover the first 16 bytes of keystream S", styles['H3']))
story.append(Paragraph("Formula: S[i] = C1[i] XOR P1[i]", styles['Formula']))

task2a_data = [
    ['Pos', 'C1[i]', 'P1[i]', 'Char', 'S[i]'],
    ['0','0x03','0x42','B','0x41'], ['1','0x16','0x52','R','0x44'],
    ['2','0x0A','0x49','I','0x43'], ['3','0x0C','0x47','G','0x4B'],
    ['4','0x0D','0x48','H','0x45'], ['5','0x18','0x54','T','0x4C'],
    ['6','0x17','0x20','(space)','0x37'], ['7','0x1F','0x53','S','0x4C'],
    ['8','0x0F','0x55','U','0x5A'], ['9','0x0D','0x4E','N','0x43'],
    ['10','0x11','0x20','(space)','0x31'], ['11','0x05','0x41','A','0x44'],
    ['12','0x03','0x52','R','0x51'], ['13','0x00','0x52','R','0x52'],
    ['14','0x0E','0x49','I','0x47'], ['15','0x00','0x56','V','0x56'],
]
story.append(make_table(task2a_data, col_widths=[1*cm, 1.5*cm, 1.5*cm, 1.5*cm, 1.5*cm]))
story.append(sp(4))
story.append(Paragraph(
    "<b>Recovered keystream:</b> S = [41, 44, 43, 4B, 45, 4C, 37, 4C, 5A, 43, 31, 44, 51, 52, 47, 56]<sub>hex</sub>",
    styles['Body']))

story.append(Paragraph("(b) Decrypt C2 and C3", styles['H3']))
story.append(Paragraph("Formula: P2[i] = C2[i] XOR S[i],  P3[i] = C3[i] XOR S[i]", styles['Formula']))

task2b_data = [
    ['Pos','C2[i]','S[i]','P2[i]','Chr','C3[i]','P3[i]','Chr'],
    ['0','0x05','0x41','0x44','D','0x0A','0x4B','K'],
    ['1','0x0D','0x44','0x49','I','0x0A','0x4E','N'],
    ['2','0x10','0x43','0x53','S','0x0C','0x4F','O'],
    ['3','0x08','0x4B','0x43','C','0x1C','0x57','W'],
    ['4','0x0A','0x45','0x4F','O','0x09','0x4C','L'],
    ['5','0x1A','0x4C','0x56','V','0x09','0x45','E'],
    ['6','0x01','0x37','0x36','6','0x00','0x37','7'],
    ['7','0x18','0x4C','0x54','T','0x0D','0x41','A'],
    ['8','0x0F','0x5A','0x55','U','0x04','0x5E','^'],
    ['9','0x09','0x43','0x4A','J','0x0B','0x48','H'],
    ['10','0x14','0x31','0x25','%','0x11','0x20','(sp)'],
    ['11','0x05','0x44','0x41','A','0x18','0x5C','\\'],
    ['12','0x05','0x51','0x54','T','0x1D','0x4C','L'],
    ['13','0x17','0x52','0x45','E','0x05','0x57','W'],
    ['14','0x0F','0x47','0x48','H','0x04','0x43','C'],
    ['15','0x00','0x56','0x56','V','0x1D','0x4B','K'],
]
w = 1.8*cm
story.append(make_table(task2b_data, col_widths=[0.8*cm,w,w,w,0.8*cm,w,w,0.8*cm]))
story.append(sp(4))
story.append(Paragraph('<b>Decrypted: P2 = "DISCOV6TUJ%ATEHV"  ,  P3 = "KNOWLE7A^H \\LWCK"</b>', styles['CodeBlock']))

story.append(sp(4))
story.append(Paragraph("<b>Assessment:</b>", styles['H3']))
story.append(Paragraph(
    '<b>Positions 0-5</b> decode perfectly: P2 begins with <b>"DISCOV"</b> (suggesting "DISCOVER...") '
    'and P3 begins with <b>"KNOWLE"</b> (suggesting "KNOWLEDGE..."). '
    'This confirms the first 6 characters of P1 = "BRIGHT" are correct.', styles['BulletItem']))
story.append(Paragraph(
    '<b>Positions 6 onward</b> produce non-alphabetic characters (\'6\', \'%\', \'^\'), indicating '
    'the assumed P1 may differ from the actual plaintext at those positions — the spaces in '
    '"BRIGHT SUN ARRIV" appear incorrect.', styles['BulletItem']))
story.append(Paragraph(
    '<b>Cross-validation:</b> Assuming P2="DISCOVER..." and P3="KNOWLEDGE...", position 6 requires '
    'S[6]=0x44, implying P1[6] = C1[6] XOR 0x44 = 0x17 XOR 0x44 = 0x53 = \'S\'. '
    'The actual P1 is likely <b>"BRIGHTSUN..."</b> (no space).', styles['BulletItem']))
story.append(Paragraph(
    '<b>Conclusion:</b> The known-plaintext attack is validated — even a partially correct guess reveals '
    'significant portions of the other plaintexts, demonstrating the critical vulnerability of keystream reuse.', styles['BulletItem']))

# ── Task 3 ──
story.append(hr())
story.append(Paragraph("Task 3 — Automated Cryptanalysis Program (3 pts)", styles['H2']))
story.append(Paragraph("<b>File:</b> 112550081_1_3.py", styles['Body']))
story.append(Paragraph("The program implements three complementary techniques:", styles['Body']))

story.append(Paragraph(
    "<b>1. Space-XOR Detection:</b> Checks if C<sub>a</sub>[i] XOR C<sub>b</sub>[i] falls in the letter range. "
    "If so, one plaintext likely has a space (space XOR letter = letter with flipped case). "
    "For these ciphertexts (all bytes in 0x00-0x1F), this correctly determines <b>no spaces exist</b>.", styles['BulletItem']))
story.append(Paragraph(
    '<b>2. Automated Crib Dragging:</b> Common English words ("BRIGHT", "DISCOVER", "KNOWLEDGE", etc.) '
    "are slid over each pair's XOR difference. Readable results vote for keystream bytes, "
    "weighted by crib length and output readability.", styles['BulletItem']))
story.append(Paragraph(
    "<b>3. Frequency Analysis + Beam Search:</b> Enumerates all valid keystream byte candidates per position, "
    "scored by English letter frequency and bigram patterns. Beam search (width 500) maintains globally coherent solutions.", styles['BulletItem']))
story.append(Paragraph(
    "Methods are combined with crib dragging taking priority (word-level context is more reliable than "
    "per-character frequency), producing ranked candidate solutions.", styles['Body']))

# ══════════════════════════════════════════════
# PROBLEM 2
# ══════════════════════════════════════════════
story.append(PageBreak())
story.append(Paragraph("Problem 2 — RSA Weak Key Recovery", styles['H1']))

story.append(Paragraph("<b>Background:</b> Two IoT sensors with 384-bit RSA keys from a weak RNG:", styles['Body']))
story.append(make_table([
    ['', 'Value'],
    ['n1', Paragraph('<font face="Courier" size="7">0x61AA9A3BCB1E80B5A50CA09D8774EF0DEBA55E66E6BB90A8'
                     '35051256072FF701E51E09BE8C339F4810C4ABB9A4B1B22F</font>', styles['CellCode'])],
    ['e1', '65537'],
    ['n2', Paragraph('<font face="Courier" size="7">0x72366EAD2204584A49E1104941921C810A79BBFE84C0AFEB'
                     '2D873D38D3CA739C3A501936D006D9FAAAC5815219F94B51</font>', styles['CellCode'])],
    ['e2', '65537'],
], col_widths=[1.2*cm, None]))

# ── Task 1 ──
story.append(hr())
story.append(Paragraph("Task 1 — Identify the Flaw (1 pt)", styles['H2']))
story.append(Paragraph(
    "The RSA key generation relies on a <b>weak random number generator (RNG)</b>. "
    "When entropy is insufficient (common in IoT/embedded devices at boot time), different devices may "
    "generate <b>overlapping prime factors</b>. Both moduli share a common prime factor:", styles['Body']))
story.append(Paragraph("n1 = p * q1,    n2 = p * q2", styles['Formula']))
story.append(Paragraph(
    "This is fatal because p = gcd(n1, n2) is computable in <b>polynomial time</b> "
    "(Euclidean algorithm), instantly factoring both moduli.", styles['Body']))

# ── Task 2 ──
story.append(hr())
story.append(Paragraph("Task 2 — Recover the Factorization (1 pt)", styles['H2']))

story.append(Paragraph("<b>Step 1:</b> Compute p = gcd(n1, n2)", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="8">p = 0xBBA4A24AD3FACD617724FBC2574F09550842A482683E1FA43F7C8CC63C4AE277</font>',
    styles['CodeBlock']))
story.append(Paragraph("p is a <b>256-bit</b> prime.", styles['SmallNote']))

story.append(Paragraph("<b>Step 2:</b> Compute q1 = n1 / p and q2 = n2 / p", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="8">q1 = 0x853EDA593F5798985C6DBF09F2412409</font>  (128-bit prime)',
    styles['CodeBlock']))
story.append(Paragraph(
    '<font face="Courier" size="8">q2 = 0x9BD1C319D1F05AD06280D1DB0031AA77</font>  (128-bit prime)',
    styles['CodeBlock']))

story.append(Paragraph("<b>Verification:</b>  p * q1 == n1  ✓  ,  p * q2 == n2  ✓", styles['Body']))
story.append(Paragraph(
    "<i>Note: The factorization is highly unbalanced (256-bit x 128-bit) — another sign of weak RNG. "
    "A proper 384-bit RSA key should have two ~192-bit primes.</i>", styles['SmallNote']))

# ── Task 3 ──
story.append(hr())
story.append(Paragraph("Task 3 — Compute Private Keys (1 pt)", styles['H2']))

story.append(Paragraph("<b>Step 1:</b> Euler's totient: phi(n) = (p-1)(q-1)", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="7">phi(n1) = 0x61AA9A3BCB1E80B5A50CA09D8774EF0D3000BC1C12C0C346'
    'BDE01693AFE0EDAC579C8AE2E49DE70B74DA5FE97625ABB0</font>', styles['CodeBlock']))
story.append(Paragraph(
    '<font face="Courier" size="7">phi(n2) = 0x72366EAD2204584A49E1104941921C804ED519B3B0C5E289'
    'B66241767C7B6A46963BB19A95D85F8608C822B0DD7CBE64</font>', styles['CodeBlock']))

story.append(sp(4))
story.append(Paragraph("<b>Step 2:</b> Private exponents: d = e<super>-1</super> mod phi(n)", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="7">d1 = 0x4F9D72FD2B274264D096EA977FC4A2DA6D372C20F6688CC7'
    '2E216E4616299595D8159462415B36ECEFE4D42ACC55091</font>', styles['CodeBlock']))
story.append(Paragraph(
    '<font face="Courier" size="7">d2 = 0x6C6E992CEE3AC9C7DDD43B2E117EB2686E6F8AF33A44E50A'
    '71895F352A81D1282AC189A085DAE2F5D1A890A6F1E0D8B1</font>', styles['CodeBlock']))

story.append(sp(4))
story.append(Paragraph("<b>Verification:</b>", styles['Body']))
story.append(Paragraph("d1 * e1 mod phi(n1) == 1  ✓", styles['BulletItem']))
story.append(Paragraph("d2 * e2 mod phi(n2) == 1  ✓", styles['BulletItem']))
story.append(Paragraph("Encrypt m=42 with e, decrypt with d: recovers m=42 for both keys  ✓", styles['BulletItem']))

# ── Task 4 ──
story.append(hr())
story.append(Paragraph("Task 4 — Justification of All Steps (1 pt)", styles['H2']))

task4_data = [
    ['Step', 'Operation', 'Justification'],
    ['1', 'p = gcd(n1, n2)', 'Weak RNG caused shared prime. Euclidean algo: O(log^2 n).'],
    ['2', 'q1=n1/p, q2=n2/p', 'Since n=p*q and p is known, integer division yields q.'],
    ['3', 'phi(n)=(p-1)(q-1)', "Euler's totient for n=pq with distinct primes."],
    ['4', 'd=e^-1 mod phi(n)', 'RSA requires ed=1 mod phi(n). Extended Euclidean Algo.'],
    ['5', 'Verify decrypt', 'Confirms recovered private key correctly decrypts.'],
]
story.append(make_table(task4_data, col_widths=[1*cm, 3.5*cm, None]))
story.append(sp(4))
story.append(Paragraph(
    "<b>Why RSA breaks:</b> RSA security assumes factoring n is infeasible. "
    "But gcd(n1,n2) is efficient and instantly reveals the shared factor. "
    "A single shared prime compromises <b>both</b> key pairs.", styles['Body']))

# ── Bonus ──
story.append(PageBreak())
story.append(Paragraph("Bonus — Real-World Case Study (2 pts)", styles['H1']))
story.append(Paragraph('"Mining Your Ps and Qs" (USENIX Security 2012)', styles['H2']))

story.append(Paragraph(
    '<b>Paper:</b> Nadia Heninger, Zakir Durumeric, Eric Wustrow, and J. Alex Halderman. '
    '"Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices." '
    'USENIX Security Symposium, 2012.', styles['Body']))
story.append(Paragraph('<b>URL:</b> https://factorable.net/', styles['Body']))

story.append(Paragraph("Background", styles['H3']))
story.append(Paragraph(
    "The researchers scanned all publicly visible RSA public keys on the Internet "
    "(~6M TLS certificates, ~5M SSH host keys) and computed pairwise GCDs to detect shared prime factors.", styles['Body']))

story.append(Paragraph("Findings", styles['H3']))
findings_data = [
    ['Metric', 'Result'],
    ['TLS keys sharing a prime factor', '0.2%'],
    ['SSH keys sharing a prime factor', '1.03%'],
    ['TLS private keys recovered', '~64,000 hosts'],
    ['SSH private keys recovered', '~108,000 hosts'],
    ['Affected manufacturers', 'Cisco, Juniper, various IoT vendors'],
]
story.append(make_table(findings_data, col_widths=[6*cm, None]))

story.append(Paragraph("Root Cause", styles['H3']))
story.append(Paragraph(
    "Embedded devices (routers, firewalls, VPN appliances) generated RSA keys <b>at boot time</b> before "
    "sufficient entropy was available from /dev/urandom.", styles['BulletItem']))
story.append(Paragraph(
    "Linux's PRNG was seeded with limited sources (uptime, serial number) that were "
    "<b>identical across devices</b> of the same model.", styles['BulletItem']))
story.append(Paragraph(
    "Result: different physical devices generated the same or overlapping prime factors.", styles['BulletItem']))

story.append(Paragraph("Attack Technique", styles['H3']))
story.append(Paragraph(
    "Naive pairwise GCD for N moduli takes O(N<super>2</super>) — infeasible for millions. "
    "The authors used Daniel Bernstein's <b>batch-GCD algorithm</b> with O(N log<super>2</super> N) complexity:", styles['Body']))
story.append(Paragraph("1. Build a product tree of all moduli.", styles['BulletItem']))
story.append(Paragraph("2. Use remainder trees to efficiently compute gcd(n_i, Product/n_i) for all i.", styles['BulletItem']))

story.append(Paragraph("Demonstration: Key Recovery on Simulated Scenario", styles['H3']))
story.append(Paragraph(
    "Below we reproduce the attack on a pair of 512-bit RSA keys sharing a common prime — "
    "simulating two routers with identical low-entropy PRNG state.", styles['Body']))

story.append(Paragraph("<b>Intercepted public keys</b> (both 512-bit, e=65537):", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="7">n1 = 0x80000000000000000000000000000000000000000000000000000000000000F3'
    '8000000000000000000000000000000000000000000000000000000000006E37</font>', styles['CodeBlock']))
story.append(Paragraph(
    '<font face="Courier" size="7">n2 = 0x80000000000000800000000000000000000000000000000000000000000000'
    '788000000000005F00000000000000000000000000000000000000000012ED</font>', styles['CodeBlock']))

story.append(sp(4))
story.append(Paragraph("<b>Step 1 — GCD reveals the shared prime:</b>", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="8">p = gcd(n1,n2) = 0x80000000000000000000000000000000'
    '0000000000000000000000000000005F</font>', styles['CodeBlock']))
story.append(Paragraph("(256-bit prime — identical on both devices due to weak entropy.)", styles['SmallNote']))

story.append(Paragraph("<b>Step 2 — Factor both moduli:</b>", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="8">q1 = 0x10000000000000000000000000000000000000000000000000000000000000129</font>', styles['CodeBlock']))
story.append(Paragraph(
    '<font face="Courier" size="8">q2 = 0x10000000000000100000000000000000000000000000000000000000000000033</font>', styles['CodeBlock']))

story.append(Paragraph("<b>Step 3 — Recover private keys:</b>", styles['Body']))
story.append(Paragraph(
    '<font face="Courier" size="8">d1 = 0x77A4885B77A4885B...AAB6BAE1</font>', styles['CodeBlock']))
story.append(Paragraph(
    '<font face="Courier" size="8">d2 = 0x1804E7FB1804E813...0BD8F799</font>', styles['CodeBlock']))

story.append(Paragraph("<b>Step 4 — Verify:</b> Encrypt m=42 with e, decrypt with d: recovers m=42 for both keys.  ✓", styles['Body']))
story.append(Paragraph(
    "This demonstrates <b>exactly</b> the same batch-GCD technique the researchers used at "
    "Internet scale to recover 64,000+ TLS and 108,000+ SSH private keys.", styles['Body']))

story.append(sp(8))
story.append(Paragraph("Lessons", styles['H3']))
story.append(Paragraph("Cryptographic key generation <b>must</b> use high-quality entropy sources.", styles['BulletItem']))
story.append(Paragraph("Embedded devices should delay key generation until sufficient entropy is available, or use hardware RNGs.", styles['BulletItem']))
story.append(Paragraph("The vulnerability is not in RSA itself but in the <b>implementation</b> of key generation.", styles['BulletItem']))

# ── Build ──
doc.build(story)
print(f"PDF generated: {pdf_path}")
