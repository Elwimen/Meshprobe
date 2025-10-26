"""
Text message compression for Meshtastic.

Provides multiple compression algorithms optimized for short text messages
before encryption. Uses TEXT_MESSAGE_COMPRESSED_APP portnum (7) infrastructure.
"""

import time
import zlib
import lzma
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class CompressionAlgorithm(IntEnum):
    """Algorithm identifiers for compression header."""
    ZLIB = 0x00
    ZSTD = 0x01
    LZ4 = 0x02
    BROTLI = 0x03
    LZMA = 0x04


@dataclass
class CompressionResult:
    """Result of compression operation."""
    original_size: int
    compressed_size: int
    algorithm: CompressionAlgorithm
    compressed_data: bytes
    compression_time_ms: float
    use_compressed: bool

    @property
    def ratio(self) -> float:
        """Compression ratio as percentage."""
        if self.original_size == 0:
            return 0.0
        return (1 - self.compressed_size / self.original_size) * 100

    @property
    def savings_bytes(self) -> int:
        """Bytes saved by compression."""
        return self.original_size - self.compressed_size


class TextCompressor(ABC):
    """Base class for text compression algorithms."""

    def __init__(self, algorithm: CompressionAlgorithm):
        self.algorithm = algorithm

    @abstractmethod
    def _compress_impl(self, data: bytes) -> bytes:
        """Implement compression algorithm."""
        pass

    @abstractmethod
    def _decompress_impl(self, data: bytes) -> bytes:
        """Implement decompression algorithm."""
        pass

    def compress(self, text: str) -> CompressionResult:
        """
        Compress text with algorithm identifier header.

        Args:
            text: UTF-8 text to compress

        Returns:
            CompressionResult with compression stats
        """
        original_data = text.encode('utf-8')
        original_size = len(original_data)

        start = time.perf_counter()
        compressed_payload = self._compress_impl(original_data)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Add 1-byte algorithm identifier header
        compressed_with_header = bytes([self.algorithm]) + compressed_payload
        compressed_size = len(compressed_with_header)

        # Always use compression
        use_compressed = True

        return CompressionResult(
            original_size=original_size,
            compressed_size=compressed_size,
            algorithm=self.algorithm,
            compressed_data=compressed_with_header,
            compression_time_ms=elapsed_ms,
            use_compressed=use_compressed
        )

    def decompress(self, data: bytes) -> str:
        """
        Decompress data with algorithm identifier header.

        Args:
            data: Compressed data with 1-byte algorithm header

        Returns:
            Decompressed UTF-8 text

        Raises:
            ValueError: If algorithm ID doesn't match or data is invalid
        """
        if len(data) < 2:
            raise ValueError(f"Data too short: {len(data)} bytes")

        algorithm_id = data[0]
        if algorithm_id != self.algorithm:
            raise ValueError(
                f"Algorithm mismatch: expected {self.algorithm.name} ({self.algorithm}), "
                f"got {algorithm_id}"
            )

        compressed_payload = data[1:]
        decompressed = self._decompress_impl(compressed_payload)
        return decompressed.decode('utf-8')


class ZlibCompressor(TextCompressor):
    """DEFLATE compression (built-in, no dependencies)."""

    def __init__(self, level: int = 6):
        super().__init__(CompressionAlgorithm.ZLIB)
        self.level = level

    def _compress_impl(self, data: bytes) -> bytes:
        return zlib.compress(data, level=self.level)

    def _decompress_impl(self, data: bytes) -> bytes:
        return zlib.decompress(data)


class ZstdCompressor(TextCompressor):
    """Zstandard compression (requires zstandard package)."""

    def __init__(self, level: int = 3):
        super().__init__(CompressionAlgorithm.ZSTD)
        self.level = level
        try:
            import zstandard
            self.zstd = zstandard
        except ImportError:
            raise ImportError("zstandard package required. Install with: pip install zstandard")

    def _compress_impl(self, data: bytes) -> bytes:
        compressor = self.zstd.ZstdCompressor(level=self.level)
        return compressor.compress(data)

    def _decompress_impl(self, data: bytes) -> bytes:
        decompressor = self.zstd.ZstdDecompressor()
        return decompressor.decompress(data)


class Lz4Compressor(TextCompressor):
    """LZ4 compression (requires lz4 package)."""

    def __init__(self, compression_level: int = 0):
        super().__init__(CompressionAlgorithm.LZ4)
        self.compression_level = compression_level
        try:
            import lz4.frame
            self.lz4 = lz4.frame
        except ImportError:
            raise ImportError("lz4 package required. Install with: pip install lz4")

    def _compress_impl(self, data: bytes) -> bytes:
        return self.lz4.compress(data, compression_level=self.compression_level)

    def _decompress_impl(self, data: bytes) -> bytes:
        return self.lz4.decompress(data)


class BrotliCompressor(TextCompressor):
    """Brotli compression (requires brotli package)."""

    def __init__(self, quality: int = 6):
        super().__init__(CompressionAlgorithm.BROTLI)
        self.quality = quality
        try:
            import brotli
            self.brotli = brotli
        except ImportError:
            raise ImportError("brotli package required. Install with: pip install brotli")

    def _compress_impl(self, data: bytes) -> bytes:
        return self.brotli.compress(data, quality=self.quality)

    def _decompress_impl(self, data: bytes) -> bytes:
        return self.brotli.decompress(data)


class LzmaCompressor(TextCompressor):
    """LZMA compression (built-in, no dependencies)."""

    def __init__(self, preset: int = 6):
        super().__init__(CompressionAlgorithm.LZMA)
        self.preset = preset

    def _compress_impl(self, data: bytes) -> bytes:
        return lzma.compress(data, preset=self.preset)

    def _decompress_impl(self, data: bytes) -> bytes:
        return lzma.decompress(data)


def get_all_compressors() -> dict[str, TextCompressor]:
    """
    Get all available compressors.

    Returns:
        Dictionary mapping algorithm names to compressor instances.
        Only includes compressors whose dependencies are available.
    """
    compressors = {}

    # Built-in compressors (always available)
    compressors['zlib'] = ZlibCompressor()
    compressors['lzma'] = LzmaCompressor()

    # Optional compressors
    try:
        compressors['zstd'] = ZstdCompressor()
    except ImportError:
        pass

    try:
        compressors['lz4'] = Lz4Compressor()
    except ImportError:
        pass

    try:
        compressors['brotli'] = BrotliCompressor()
    except ImportError:
        pass

    return compressors


def decompress_auto(data: bytes) -> str:
    """
    Automatically detect algorithm and decompress.

    Args:
        data: Compressed data with 1-byte algorithm header

    Returns:
        Decompressed UTF-8 text

    Raises:
        ValueError: If algorithm is unknown or not available
    """
    if len(data) < 2:
        raise ValueError(f"Data too short: {len(data)} bytes")

    algorithm_id = data[0]

    try:
        algorithm = CompressionAlgorithm(algorithm_id)
    except ValueError:
        raise ValueError(f"Unknown algorithm ID: 0x{algorithm_id:02x}")

    # Map algorithm to compressor class
    compressor_map = {
        CompressionAlgorithm.ZLIB: ZlibCompressor,
        CompressionAlgorithm.ZSTD: ZstdCompressor,
        CompressionAlgorithm.LZ4: Lz4Compressor,
        CompressionAlgorithm.BROTLI: BrotliCompressor,
        CompressionAlgorithm.LZMA: LzmaCompressor,
    }

    compressor_class = compressor_map[algorithm]
    try:
        compressor = compressor_class()
        return compressor.decompress(data)
    except ImportError as e:
        raise ValueError(f"Algorithm {algorithm.name} not available: {e}")
