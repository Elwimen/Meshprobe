# Meshtastic Compression Benchmark

## Overview

This benchmark tests 7 compression algorithms on realistic Meshtastic radio messages to determine which provides the best compression for the 237-byte payload limit.

## Running the Benchmark

```bash
python3 benchmark_compression.py
```

## Output Files

- **BENCHMARK_RESULTS.md** - Full markdown report with tables and charts
- **compression_ratio_plot.png** - Graph showing compression ratio vs input length
- **compressed_size_plot.png** - Graph showing output size vs input length

## Requirements

- Python 3.12+
- `pip install matplotlib numpy brotli zstandard lz4 python-snappy`

## Results Summary

**Winner: Brotli** - Allows up to 396 bytes of uncompressed text (67% more than the 237-byte limit)

### Compression Rankings

1. **Brotli** - 396 bytes max (51% compression on long messages)
2. **Zlib** - 322 bytes max (36% compression, built-in)
3. **Zstd** - 322 bytes max (32% compression)
4. **Bzip2** - 293 bytes max (23% compression, built-in)
5. **Snappy** - 238 bytes max (best for tiny messages)
6. **LZ4** - 214 bytes max (fast but weak)
7. **LZMA** - 211 bytes max (too much overhead)

### Key Findings

- **Short messages (<30 bytes)**: All algorithms expand data due to overhead
  - Snappy has minimal expansion (-20%)
  - Best strategy: send uncompressed or use dictionary encoding

- **Medium messages (100-200 bytes)**: Compression becomes effective
  - Brotli: 33% compression
  - Zlib: 25% compression

- **Long messages (200-400 bytes)**: Maximum compression benefit
  - Brotli: 40-51% compression
  - Allows significantly longer messages

- **Very long messages (>400 bytes)**: Cannot fit even with compression
  - Must split into multiple packets

## Plots

The benchmark generates two matplotlib plots showing:

1. **Compression Ratio** - How compression improves with message length
2. **Compressed Size** - Which algorithms stay under the 237-byte limit

Both plots show all 7 algorithms with color-coded lines for easy comparison.

## Test Data

The benchmark uses 120 realistic messages ranging from 6 to 623 bytes, including:
- Short radio exchanges ("Coming", "Signal strong")
- Technical discussions about equipment
- Long detailed status reports
- Field test observations

This provides comprehensive coverage of real-world Meshtastic usage patterns.
