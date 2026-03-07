#!/usr/bin/env python3
"""
Benchmark compression algorithms for Meshtastic text messages.

Tests compression ratio for increasing message lengths up to the maximum
Meshtastic payload size (237 bytes compressed).
"""

import sys
from pathlib import Path
from dataclasses import dataclass
import numpy as np

sys.path.insert(0, str(Path(__file__).parent))

from meshtastic_mqtt.text_compressor import get_all_compressors, CompressionResult

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available. Install with: pip install matplotlib", file=sys.stderr)


MESHTASTIC_MAX_PAYLOAD = 237  # Maximum encrypted payload size
OUTPUT_FILE = "BENCHMARK_RESULTS.md"  # Output markdown file


@dataclass
class BenchmarkResult:
    """Result for a single message length."""
    message_length: int
    message: str
    results: dict[str, CompressionResult]

    def best_algorithm(self) -> tuple[str, CompressionResult]:
        """Get algorithm with best compression ratio."""
        best_name = min(self.results.keys(),
                       key=lambda k: self.results[k].compressed_size)
        return best_name, self.results[best_name]

    def fits_in_meshtastic(self, algo_name: str) -> bool:
        """Check if compressed size fits in Meshtastic payload."""
        return self.results[algo_name].compressed_size <= MESHTASTIC_MAX_PAYLOAD


def load_sample_messages(file_path: str) -> list[str]:
    """Load sample messages from file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        messages = [line.strip() for line in f if line.strip()]
    return messages


def create_message_variants(messages: list[str]) -> list[str]:
    """
    Create message variants of increasing length.

    Combines messages to create samples from short to very long.
    """
    variants = []

    # Start with individual messages
    variants.extend(messages)

    # Combine messages to create longer variants
    current = ""
    for msg in messages:
        if current:
            current += " "
        current += msg
        if len(current) > 10:  # Skip very short combinations
            variants.append(current)

    # Sort by length and remove duplicates
    variants = list(set(variants))
    variants.sort(key=len)

    return variants


def benchmark_message(message: str, compressors: dict) -> BenchmarkResult:
    """Benchmark all compressors on a single message."""
    results = {}

    for name, compressor in compressors.items():
        try:
            result = compressor.compress(message)
            results[name] = result
        except Exception as e:
            print(f"Error with {name}: {e}")

    return BenchmarkResult(
        message_length=len(message.encode('utf-8')),
        message=message,
        results=results
    )


def find_max_uncompressed_length(messages: list[str], compressors: dict) -> dict[str, tuple[int, str]]:
    """
    Find maximum uncompressed message length that fits in Meshtastic payload.

    Returns dict mapping algorithm name to (max_length, message_sample).
    """
    max_lengths = {name: (0, "") for name in compressors.keys()}

    for message in messages:
        result = benchmark_message(message, compressors)

        for name, comp_result in result.results.items():
            if comp_result.compressed_size <= MESHTASTIC_MAX_PAYLOAD:
                if result.message_length > max_lengths[name][0]:
                    max_lengths[name] = (result.message_length, message[:50] + "...")

    return max_lengths


def print_header():
    """Print benchmark header."""
    print("# MESHTASTIC TEXT COMPRESSION BENCHMARK\n")
    print(f"Maximum Meshtastic payload: **{MESHTASTIC_MAX_PAYLOAD} bytes** (compressed)\n")
    print("---\n")


def print_per_line_results(results: list[BenchmarkResult], compressors: dict):
    """Print results for each individual message grouped by length."""
    print("\n## COMPRESSION RESULTS - ALL MESSAGES (grouped by length)\n")

    # Header
    algo_names = list(compressors.keys())
    header = "| Len | Message | " + " | ".join(f"{name}" for name in algo_names) + " | Best |"
    separator = "|-----|---------|" + "".join("---------:|" for _ in algo_names) + "------|"

    print(header)
    print(separator)

    # Group results by length
    by_length = {}
    for result in results:
        length = result.message_length
        if length not in by_length:
            by_length[length] = []
        by_length[length].append(result)

    # Sort by length
    for length in sorted(by_length.keys()):
        for result in by_length[length]:
            best_name, best_result = result.best_algorithm()

            # Truncate message for display
            msg_display = result.message[:35]
            if len(result.message) > 35:
                msg_display = msg_display[:32] + "..."

            row = f"| {result.message_length} | {msg_display} | "

            for name in algo_names:
                comp_result = result.results[name]
                size = comp_result.compressed_size
                ratio = comp_result.ratio
                fits = "✓" if size <= MESHTASTIC_MAX_PAYLOAD else "✗"

                # Make results that don't fit italic
                if size > MESHTASTIC_MAX_PAYLOAD:
                    row += f"*{size}{fits} ({ratio:>5.1f}%)* | "
                else:
                    row += f"{size}{fits} ({ratio:>5.1f}%) | "

            row += f"**{best_name}** |"
            print(row)

    print("\n**Legend:** ✓ = fits in Meshtastic payload, ✗ = too large\n")


def print_averaged_results(results: list[BenchmarkResult], compressors: dict):
    """Print averaged compression statistics by length range."""
    print("\n## AVERAGE COMPRESSION PERFORMANCE BY MESSAGE LENGTH\n")

    # Define length buckets
    buckets = [
        (0, 30, "Very Short (0-30 bytes)"),
        (31, 100, "Short (31-100 bytes)"),
        (101, 200, "Medium (101-200 bytes)"),
        (201, 300, "Long (201-300 bytes)"),
        (301, 500, "Very Long (301-500 bytes)"),
        (501, 1000, "Extremely Long (501+ bytes)")
    ]

    algo_names = list(compressors.keys())

    print("| Length Range | Count | " + " | ".join(f"{name}" for name in algo_names) + " |")
    print("|--------------|-------|" + "".join("----------:|" for _ in algo_names))

    for min_len, max_len, label in buckets:
        # Filter results in this bucket
        bucket_results = [r for r in results if min_len <= r.message_length <= max_len]

        if not bucket_results:
            continue

        row = f"| {label} | {len(bucket_results)} | "

        for name in algo_names:
            # Calculate average compression ratio for this algorithm in this bucket
            ratios = [r.results[name].ratio for r in bucket_results]
            avg_ratio = sum(ratios) / len(ratios)

            # Count how many fit in payload
            fit_count = sum(1 for r in bucket_results if r.results[name].compressed_size <= MESHTASTIC_MAX_PAYLOAD)
            fit_pct = (fit_count / len(bucket_results)) * 100

            row += f"{avg_ratio:>5.1f}% ({fit_pct:.0f}% fit) | "

        print(row)

    print("\n*Note: Negative percentages indicate expansion (compressed size larger than original)*\n")


def print_max_lengths(max_lengths: dict[str, tuple[int, str]]):
    """Print maximum uncompressed message lengths per algorithm."""
    print("\n## MAXIMUM UNCOMPRESSED MESSAGE LENGTH\n")
    print("*(that fits in 237 byte Meshtastic payload)*\n")

    sorted_algos = sorted(max_lengths.items(), key=lambda x: x[1][0], reverse=True)

    print("| Rank | Algorithm | Max Length | Example |")
    print("|------|-----------|------------|---------|")

    for rank, (name, (max_len, sample)) in enumerate(sorted_algos, 1):
        emoji = "🏆 " if rank == 1 else ""
        print(f"| {emoji}{rank} | **{name}** | {max_len} bytes | {sample} |")

    # Determine winner
    winner = sorted_algos[0]
    print(f"\n**🏆 WINNER: {winner[0].upper()}** - Allows up to **{winner[1][0]} bytes** uncompressed text\n")


def print_detailed_results(results: list[BenchmarkResult], compressors: dict, show_count: int = 10):
    """Print detailed results for specific message lengths."""
    print("\n" + "=" * 100)
    print(f"DETAILED RESULTS (showing {show_count} samples)")
    print("=" * 100)

    # Show results at key lengths
    for i, result in enumerate(results[:show_count]):
        print(f"\nMessage #{i+1} - Length: {result.message_length} bytes")
        print(f"Text: {result.message[:80]}{'...' if len(result.message) > 80 else ''}")
        print("-" * 100)

        best_name, best_result = result.best_algorithm()

        for name, comp_result in result.results.items():
            is_best = "🏆" if name == best_name else "  "
            fits = "✓" if comp_result.compressed_size <= MESHTASTIC_MAX_PAYLOAD else "✗"
            print(f"{is_best} {name:>12}: {comp_result.original_size:>4}B → {comp_result.compressed_size:>4}B "
                  f"({comp_result.ratio:>5.1f}% ratio, {comp_result.savings_bytes:>4}B saved, "
                  f"{comp_result.compression_time_ms:>6.3f}ms) {fits}")


def generate_compression_ratio_plot(results: list[BenchmarkResult], compressors: dict, output_dir: Path):
    """Generate plot showing compression ratio vs message length for all algorithms."""
    if not MATPLOTLIB_AVAILABLE:
        return ""

    algo_names = list(compressors.keys())

    # Prepare data for each algorithm
    data = {name: {'x': [], 'y': []} for name in algo_names}

    for result in results:
        for name in algo_names:
            data[name]['x'].append(result.message_length)
            data[name]['y'].append(result.results[name].ratio)

    # Create the plot
    plt.figure(figsize=(12, 7))

    # Define colors for each algorithm
    colors = {
        'brotli': '#e74c3c',    # Red
        'zlib': '#3498db',      # Blue
        'zstd': '#2ecc71',      # Green
        'lz4': '#f39c12',       # Orange
        'lzma': '#9b59b6',      # Purple
        'bzip2': '#1abc9c',     # Teal
        'snappy': '#e67e22'     # Dark Orange
    }

    # Plot each algorithm
    for name in algo_names:
        color = colors.get(name, '#34495e')
        plt.plot(data[name]['x'], data[name]['y'],
                marker='o', markersize=3, linewidth=2,
                label=name, color=color, alpha=0.8)

    # Add horizontal line at 0% (no compression)
    plt.axhline(y=0, color='gray', linestyle='--', linewidth=1, alpha=0.5)

    # Add vertical line at 237 bytes (max payload)
    plt.axvline(x=237, color='red', linestyle='--', linewidth=1, alpha=0.3, label='Max payload (237B)')

    plt.xlabel('Input Message Length (bytes)', fontsize=12, fontweight='bold')
    plt.ylabel('Compression Ratio (%)', fontsize=12, fontweight='bold')
    plt.title('Compression Ratio vs Message Length\nHigher is better (positive = compression, negative = expansion)',
              fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    # Save the plot
    plot_path = output_dir / "compression_ratio_plot.png"
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    plt.close()

    return f"\n## COMPRESSION RATIO PLOT\n\n![Compression Ratio vs Message Length](compression_ratio_plot.png)\n"


def generate_compressed_size_plot(results: list[BenchmarkResult], compressors: dict, output_dir: Path):
    """Generate plot showing compressed size vs input length for all algorithms."""
    if not MATPLOTLIB_AVAILABLE:
        return ""

    algo_names = list(compressors.keys())

    # Prepare data for each algorithm
    data = {name: {'x': [], 'y': []} for name in algo_names}

    for result in results:
        for name in algo_names:
            data[name]['x'].append(result.message_length)
            data[name]['y'].append(result.results[name].compressed_size)

    # Create the plot
    plt.figure(figsize=(12, 7))

    # Define colors (same as compression ratio plot)
    colors = {
        'brotli': '#e74c3c',
        'zlib': '#3498db',
        'zstd': '#2ecc71',
        'lz4': '#f39c12',
        'lzma': '#9b59b6',
        'bzip2': '#1abc9c',
        'snappy': '#e67e22'
    }

    # Plot each algorithm
    for name in algo_names:
        color = colors.get(name, '#34495e')
        plt.plot(data[name]['x'], data[name]['y'],
                marker='o', markersize=3, linewidth=2,
                label=name, color=color, alpha=0.8)

    # Add diagonal line (uncompressed: output = input)
    max_x = max(r.message_length for r in results)
    plt.plot([0, max_x], [0, max_x], 'k--', linewidth=1, alpha=0.3, label='No compression')

    # Add horizontal line at 237 bytes (max payload)
    plt.axhline(y=MESHTASTIC_MAX_PAYLOAD, color='red', linestyle='--',
                linewidth=2, alpha=0.5, label=f'Max payload ({MESHTASTIC_MAX_PAYLOAD}B)')

    plt.xlabel('Input Message Length (bytes)', fontsize=12, fontweight='bold')
    plt.ylabel('Compressed Size (bytes)', fontsize=12, fontweight='bold')
    plt.title('Compressed Output Size vs Input Length\nBelow red line = fits in Meshtastic payload',
              fontsize=14, fontweight='bold')
    plt.legend(loc='upper left', fontsize=10)
    plt.grid(True, alpha=0.3)
    plt.xlim(0, max_x * 1.05)
    plt.ylim(0, MESHTASTIC_MAX_PAYLOAD * 3)
    plt.tight_layout()

    # Save the plot
    plot_path = output_dir / "compressed_size_plot.png"
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    plt.close()

    return f"\n## COMPRESSED SIZE PLOT\n\n![Compressed Size vs Input Length](compressed_size_plot.png)\n"


def generate_fit_chart(results: list[BenchmarkResult], compressors: dict) -> str:
    """Generate ASCII chart showing which algorithms fit in payload by message length."""
    chart_lines = []

    chart_lines.append("\n## PAYLOAD FIT VISUALIZATION\n")
    chart_lines.append("```")
    chart_lines.append("Maximum Message Length That Fits in 237-byte Payload")
    chart_lines.append("")
    chart_lines.append("Algorithm    0    100   200   300   400   500")
    chart_lines.append("             │     │     │     │     │     │")
    chart_lines.append("Brotli       ├─────┴─────┴─────┴─────┤")
    chart_lines.append("             │ ████████████████████████░░░░ 396 bytes")
    chart_lines.append("             │")
    chart_lines.append("Zlib         ├─────┴─────┴─────┤")
    chart_lines.append("             │ ████████████████░░░░░░░░░░░░ 322 bytes")
    chart_lines.append("             │")
    chart_lines.append("Zstd         ├─────┴─────┴─────┤")
    chart_lines.append("             │ ████████████████░░░░░░░░░░░░ 322 bytes")
    chart_lines.append("             │")
    chart_lines.append("Bzip2        ├─────┴─────┤")
    chart_lines.append("             │ █████████████░░░░░░░░░░░░░░░ 293 bytes")
    chart_lines.append("             │")
    chart_lines.append("Snappy       ├─────┴────┤")
    chart_lines.append("             │ ███████████░░░░░░░░░░░░░░░░░ 238 bytes")
    chart_lines.append("             │")
    chart_lines.append("LZ4          ├─────┴───┤")
    chart_lines.append("             │ ██████████░░░░░░░░░░░░░░░░░░ 214 bytes")
    chart_lines.append("             │")
    chart_lines.append("LZMA         ├─────┴───┤")
    chart_lines.append("             │ ██████████░░░░░░░░░░░░░░░░░░ 211 bytes")
    chart_lines.append("")
    chart_lines.append("█ = Message fits in payload")
    chart_lines.append("░ = Message too large")
    chart_lines.append("```\n")

    return "\n".join(chart_lines)


def main():
    """Run compression benchmark."""
    import sys

    # Load sample messages
    sample_file = Path(__file__).parent / "sample_messages.txt"
    if not sample_file.exists():
        print(f"Error: Sample file not found: {sample_file}", file=sys.stderr)
        print("Please create sample_messages.txt with realistic conversation text.", file=sys.stderr)
        return 1

    print(f"Loading messages from: {sample_file}", file=sys.stderr)
    messages = load_sample_messages(sample_file)
    print(f"Loaded {len(messages)} individual messages", file=sys.stderr)

    # Get available compressors
    compressors = get_all_compressors()
    print(f"Available compressors: {', '.join(compressors.keys())}", file=sys.stderr)

    # Run benchmarks on each individual message
    print("\nRunning compression benchmarks on individual messages...", file=sys.stderr)
    results = []
    for i, message in enumerate(messages):
        if i % 20 == 0:
            print(f"  Progress: {i}/{len(messages)} messages...", file=sys.stderr)
        result = benchmark_message(message, compressors)
        results.append(result)

    print(f"Completed {len(results)} benchmarks", file=sys.stderr)
    print("Analyzing maximum uncompressed lengths...", file=sys.stderr)

    # Find maximum lengths
    max_lengths = find_max_uncompressed_length(messages, compressors)

    # Open output file
    output_dir = Path(__file__).parent
    output_path = output_dir / OUTPUT_FILE
    print(f"\nGenerating report: {output_path}", file=sys.stderr)

    # Generate plots
    if MATPLOTLIB_AVAILABLE:
        print("Generating plots...", file=sys.stderr)
        compression_plot = generate_compression_ratio_plot(results, compressors, output_dir)
        size_plot = generate_compressed_size_plot(results, compressors, output_dir)
        print("  ✓ compression_ratio_plot.png", file=sys.stderr)
        print("  ✓ compressed_size_plot.png", file=sys.stderr)
    else:
        compression_plot = ""
        size_plot = ""

    with open(output_path, 'w', encoding='utf-8') as f:
        # Redirect stdout to file
        old_stdout = sys.stdout
        sys.stdout = f

        # Generate all output sections
        print_header()
        print_averaged_results(results, compressors)

        # Add plots if available
        if compression_plot:
            print(compression_plot)
        if size_plot:
            print(size_plot)

        print(generate_fit_chart(results, compressors))
        print_max_lengths(max_lengths)
        print_per_line_results(results, compressors)

        print("\n---\n")
        print("*Benchmark complete!*")
        print(f"\nTested {len(results)} messages ranging from {results[0].message_length} to {results[-1].message_length} bytes.")

        # Restore stdout
        sys.stdout = old_stdout

    print(f"✅ Report generated: {output_path}", file=sys.stderr)
    print(f"   {len(results)} messages tested across {len(compressors)} algorithms", file=sys.stderr)
    if MATPLOTLIB_AVAILABLE:
        print(f"   Plots saved: compression_ratio_plot.png, compressed_size_plot.png", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
