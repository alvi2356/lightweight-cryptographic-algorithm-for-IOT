"""
IoT-SC1 Keystream Visualizer
==============================
Generates visual outputs of the keystream:
  - ASCII bit-map to terminal
  - Byte frequency histogram (text)
  - XOR diff heatmap between two keystreams
  - Saves PNG if matplotlib is available

Run:
    python utils/visualizer.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.cipher import IoTSC1


def _bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def ascii_bitmap(ks: bytes, width: int = 64):
    """Print a binary bitmap of the keystream to terminal."""
    bits = list(_bits(ks))
    print(f"\n  Keystream bitmap ({len(ks)} bytes = {len(bits)} bits):")
    print(f"  " + "─" * width)
    for row_start in range(0, min(len(bits), width * 8), width):
        row = bits[row_start:row_start + width]
        line = "".join("█" if b else "░" for b in row)
        print(f"  {line}")
    print(f"  " + "─" * width)


def freq_histogram(ks: bytes, bins: int = 16):
    """Print byte-frequency histogram to terminal."""
    from collections import Counter
    freq = Counter(ks)
    # Group into bins
    bin_size = 256 // bins
    print(f"\n  Byte frequency histogram ({len(ks)} bytes, {bins} bins):")
    print(f"  {'Range':<12} {'Count':>6}  Bar")
    print(f"  " + "─" * 50)
    max_count = max(sum(freq.get(b, 0) for b in range(i * bin_size, (i + 1) * bin_size))
                    for i in range(bins))
    for i in range(bins):
        lo = i * bin_size; hi = (i + 1) * bin_size - 1
        count = sum(freq.get(b, 0) for b in range(lo, hi + 1))
        bar_len = int(count / max_count * 30) if max_count > 0 else 0
        expected = len(ks) / bins
        marker = "✓" if abs(count - expected) < expected * 0.3 else "!"
        print(f"  {lo:3d}–{hi:3d}       {count:6d}  {'█' * bar_len} {marker}")


def xor_diff_heatmap(key1: bytes, iv1: bytes, key2: bytes, iv2: bytes, n: int = 64):
    """Show XOR difference between two keystreams."""
    ks1 = IoTSC1(key1, iv1).keystream(n)
    ks2 = IoTSC1(key2, iv2).keystream(n)
    diff = bytes(a ^ b for a, b in zip(ks1, ks2))

    print(f"\n  XOR diff heatmap (key1 vs key2, {n} bytes):")
    print(f"  Darker = more bits differ")
    print(f"  " + "─" * 65)
    for row_start in range(0, n, 16):
        row = diff[row_start:row_start + 16]
        hex_part  = " ".join(f"{b:02x}" for b in row)
        heat_part = "".join("█" if b > 200 else "▓" if b > 128 else "░" if b > 50 else "·"
                            for b in row)
        print(f"  {hex_part:<48}  {heat_part}")
    changed = sum(1 for b in diff if b != 0)
    avg_bits = sum(bin(b).count('1') for b in diff) / n
    print(f"\n  Changed bytes: {changed}/{n} ({changed/n*100:.1f}%)")
    print(f"  Avg bits/byte differing: {avg_bits:.2f}/8 ({avg_bits/8*100:.1f}%)")


def plot_keystream_png(ks: bytes, path: str = "utils/keystream_viz.png"):
    """Save PNG visualization using matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        from collections import Counter

        fig, axes = plt.subplots(1, 3, figsize=(15, 4))
        fig.suptitle("IoT-SC1 Keystream Analysis", fontsize=14, fontweight='bold')
        fig.patch.set_facecolor("#f8f8f6")

        # 1. Bit bitmap
        bits = list(_bits(ks))
        bmp = np.array(bits[:512]).reshape(8, 64)
        axes[0].imshow(bmp, cmap="Blues", aspect="auto", interpolation="nearest")
        axes[0].set_title("Bit Bitmap (512 bits)")
        axes[0].set_xlabel("Bit position"); axes[0].set_ylabel("Row")

        # 2. Byte frequency
        freq = Counter(ks)
        x = list(range(256))
        y = [freq.get(i, 0) for i in x]
        axes[1].bar(x, y, color="#185FA5", alpha=0.7, width=1)
        axes[1].axhline(len(ks) / 256, color="red", linestyle="--", label="Expected")
        axes[1].set_title("Byte Frequency Distribution")
        axes[1].set_xlabel("Byte value (0–255)"); axes[1].set_ylabel("Count")
        axes[1].legend()

        # 3. Running entropy
        window = 64
        entropies = []
        for i in range(0, len(ks) - window, 8):
            chunk = ks[i:i + window]
            fc = Counter(chunk)
            e = -sum((c / window) * np.log2(c / window) for c in fc.values())
            entropies.append(e)
        axes[2].plot(entropies, color="#639922", linewidth=1.5)
        axes[2].axhline(8.0, color="red", linestyle="--", label="Ideal (8.0)")
        axes[2].set_ylim(0, 8.5)
        axes[2].set_title(f"Running Entropy (window={window}B)")
        axes[2].set_xlabel("Window position"); axes[2].set_ylabel("Entropy (bits/byte)")
        axes[2].legend()

        for ax in axes:
            ax.set_facecolor("#f8f8f6")

        plt.tight_layout()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"\n  PNG saved → {path}")
    except ImportError:
        print("  matplotlib not installed — skipping PNG export")


def run_visualizer():
    key1 = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    iv1  = bytes.fromhex("a1b2c3d4e5f6a7b8")
    key2 = bytes.fromhex("1f1e2d3c4b5a69788796a5b4c3d2e1f0")  # 1-bit diff
    iv2  = bytes.fromhex("a1b2c3d4e5f6a7b8")

    print(f"\n{'='*65}")
    print(f"  IoT-SC1 Keystream Visualizer")
    print(f"{'='*65}")

    ks = IoTSC1(key1, iv1).keystream(256)

    ascii_bitmap(ks, width=64)
    freq_histogram(ks, bins=16)
    xor_diff_heatmap(key1, iv1, key2, iv2, n=64)
    plot_keystream_png(ks)

    print(f"\n{'='*65}\n")


if __name__ == "__main__":
    run_visualizer()
