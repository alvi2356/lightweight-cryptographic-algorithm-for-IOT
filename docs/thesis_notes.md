# IoT-SC1 Thesis Notes
**Title: Lightweight Cryptographic Algorithm for Robust IoT and Reliable 5G Wireless Network**

---

## Suggested Chapter Structure

### Chapter 1 — Introduction
- IoT explosion: billions of devices, constrained resources
- 5G NB-IoT / eMTC: low power, low throughput, battery-operated sensors
- Problem: AES-128 too heavy for Class 0–1 IoT (< 10 KB RAM, 8-bit MCU)
- Contribution: IoT-SC1 — custom lightweight stream cipher
- Thesis organization

### Chapter 2 — Background & Literature Review
- Stream ciphers vs block ciphers for IoT
- eSTREAM project finalists: Grain-128, Trivium, MICKEY
- PRESENT / SIMON / SPECK lightweight block ciphers
- 5G security standards: 3GPP TS 33.401, NAS security
- NIST lightweight cryptography project (ASCON winner, 2023)
- Comparison table of existing work

### Chapter 3 — IoT-SC1 Algorithm Design
- Design rationale and goals
- Architecture: LFSR + NLFSR + S-box pipeline
- LFSR design: primitive polynomial selection
- NLFSR: non-linear feedback terms, algebraic degree
- Combiner: correlation immunity via H(a,b)
- S-box: PRESENT derivation, DU/NL analysis
- IV scheme for 5G NB-IoT nonce uniqueness
- MAC construction
- Full algorithm specification (refer to docs/algorithm_spec.md)

### Chapter 4 — Security Analysis
- Differential cryptanalysis resistance (S-box DU)
- Linear cryptanalysis resistance (S-box NL, CI combiner)
- BM attack resistance (NLFSR algebraic degree)
- Correlation attack analysis (Siegenthaler bound)
- Strict Avalanche Criterion results
- Linear complexity via BM algorithm
- Security level: birthday bound 2⁶⁴
- Comparison with Grain-128, Trivium security

### Chapter 5 — Implementation & Simulation
- Python reference implementation
- Statistical test suite (NIST SP 800-22): results table
- Benchmark: throughput and cycles/byte on MCU classes
- 5G NB-IoT PDU integration simulation
- Known-Answer Test vectors

### Chapter 6 — Performance Evaluation
- Throughput comparison: IoT-SC1 vs AES-128-CTR vs ChaCha20
- Cycles/byte across device classes (Table + Chart)
- ROM/RAM footprint comparison
- Power consumption estimate
- Latency per IoT packet

### Chapter 7 — Conclusion & Future Work
- Summary of contributions
- Limitations (64-bit security, no PQC)
- Future: hardware (FPGA/ASIC) implementation
- Future: extend MAC to 64-bit (GHASH-style)
- Future: formal security proof (UC framework)

---

## Key Claims to Support with Data

1. **ROM ≤ 256 bytes** — measure cipher.py code path with `dis` module
2. **RAM = 32 bytes** — two 64-bit registers (16 bytes) + 4-byte MAC = 20 bytes state
3. **Cycles/byte = 3–8** — profiled in benchmarks/
4. **Shannon entropy ≥ 7.9** — from statistical_tests.py output
5. **Avalanche ≈ 50%** — from security_analysis.py SAC test
6. **DU = 4, NL = 4** — from security_analysis.py sbox_report()
7. **LC ≈ n/2** — from lc_analysis()

---

## Figures to Generate

| Figure | Source | Description |
|--------|--------|-------------|
| Fig 3.1 | `docs/` | IoT-SC1 architecture pipeline |
| Fig 3.2 | S-box table | 4×4 S-box heatmap |
| Fig 5.1 | `utils/keystream_viz.png` | Keystream bit bitmap |
| Fig 5.2 | `utils/keystream_viz.png` | Byte frequency histogram |
| Fig 6.1 | `benchmarks/benchmark_chart.png` | Throughput comparison bar chart |
| Fig 6.2 | `benchmarks/benchmark_chart.png` | Latency comparison line chart |
| Table 4.1 | security_analysis output | Full security property table |
| Table 6.1 | benchmark CSV | Numeric performance data |

---

## LaTeX Snippet — Algorithm Pseudocode

```latex
\begin{algorithm}
\caption{IoT-SC1 Keystream Generation}
\begin{algorithmic}[1]
\REQUIRE Key $K = K_1 \| K_2$ (128 bits), IV $N$ (64 bits)
\STATE $\text{LFSR} \leftarrow K_1 \oplus N$
\STATE $\text{NLFSR} \leftarrow K_2 \oplus N \oplus C_{\text{div}}$
\FOR{$i = 1$ to $64$} \COMMENT{Warm-up}
  \STATE Clock LFSR; Clock NLFSR
\ENDFOR
\WHILE{plaintext bytes remain}
  \STATE Clock LFSR; Clock NLFSR
  \STATE $a \leftarrow \text{extract}(\text{LFSR}, \text{taps})$
  \STATE $b \leftarrow \text{extract}(\text{NLFSR}, \text{taps})$
  \STATE $z \leftarrow a \oplus b \oplus (a \cdot b)$
  \STATE $k \leftarrow \text{SBOX}[z[7:4]] \| \text{SBOX}[z[3:0]]$
  \STATE Output $k \oplus p_i$
\ENDWHILE
\end{algorithmic}
\end{algorithm}
```
