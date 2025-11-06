#!/usr/bin/env python3
"""Utility helpers for exercising the Twofish reference implementation.

The script verifies encryption/decryption for multiple key sizes and message
lengths and optionally records encryption/decryption throughput for each
scenario.  Use ``python3 twofish_test.py --help`` to see available CLI flags.
"""

from __future__ import annotations

import argparse
import os
import random
import struct
import time
from statistics import mean
from typing import Iterable, List, Sequence

try:
    import myref
    from myref import decrypt, encrypt, keySched
except ImportError as exc:  # pragma: no cover - defensive import guard
    raise SystemExit(f"Unable to import Twofish reference implementation: {exc}")


DEFAULT_BLOCK_SIZE = 16
BLOCK_LEN = getattr(myref, "BLOCK_SIZE", DEFAULT_BLOCK_SIZE)


def _random_bytes(length: int, seed: int | None = None) -> bytes:
    if seed is None:
        return os.urandom(length)

    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(length))


def iter_blocks(data: bytes, block_size: int = BLOCK_LEN) -> Iterable[bytes]:
    for start in range(0, len(data), block_size):
        yield data[start : start + block_size]


def pkcs7_pad(data: bytes, block_size: int = BLOCK_LEN) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_LEN) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid padding byte")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding contents")
    return data[:-pad_len]


def bytes_to_words(block: bytes) -> List[int]:
    if len(block) != BLOCK_LEN:
        raise ValueError(f"Blocks must be exactly {BLOCK_LEN} bytes")
    return list(struct.unpack(">IIII", block))


def words_to_bytes(words: Sequence[int]) -> bytes:
    if len(words) != 4:
        raise ValueError("Twofish operates on 4-word blocks")
    return struct.pack(">IIII", *[w & 0xFFFFFFFF for w in words])


def words_from_key(key_bytes: bytes) -> List[int]:
    if len(key_bytes) % 4:
        raise ValueError("Key material must be a multiple of 32 bits")
    fmt = ">" + "I" * (len(key_bytes) // 4)
    return list(struct.unpack(fmt, key_bytes))


def benchmark_encrypt(
    K: Sequence[int],
    k: int,
    S: Sequence[int],
    blocks: Sequence[Sequence[int]],
    iterations: int,
) -> float:
    if iterations <= 0:
        return float("nan")

    start = time.perf_counter()
    for _ in range(iterations):
        for block in blocks:
            encrypt(K, k, S, block)
    elapsed = time.perf_counter() - start
    return (elapsed * 1000.0) / iterations


def benchmark_decrypt(
    K: Sequence[int],
    k: int,
    S: Sequence[int],
    blocks: Sequence[Sequence[int]],
    iterations: int,
) -> float:
    if iterations <= 0:
        return float("nan")

    start = time.perf_counter()
    for _ in range(iterations):
        for block in blocks:
            decrypt(K, k, S, block, verbose=False)
    elapsed = time.perf_counter() - start
    return (elapsed * 1000.0) / iterations


def run_validation(
    key_bits: int,
    message_len: int,
    *,
    seed: int | None,
    benchmark_iterations: int,
    sample_seed: int,
) -> tuple[bool, float, float]:
    sample_key_seed = None if seed is None else seed + sample_seed * 97
    key_bytes = _random_bytes(key_bits // 8, sample_key_seed)
    K, k, S = keySched(words_from_key(key_bytes), key_bits)

    sample_msg_seed = None if seed is None else seed + sample_seed * 193
    message = _random_bytes(message_len, sample_msg_seed)
    padded = pkcs7_pad(message)
    blocks = [bytes_to_words(block) for block in iter_blocks(padded)]

    cipher_blocks = [encrypt(K, k, S, block) for block in blocks]
    decrypted_blocks = [decrypt(K, k, S, block, verbose=False) for block in cipher_blocks]
    recovered = pkcs7_unpad(b"".join(words_to_bytes(block) for block in decrypted_blocks))
    success = recovered == message

    enc_time_ms = benchmark_encrypt(K, k, S, blocks, benchmark_iterations)
    dec_time_ms = benchmark_decrypt(K, k, S, cipher_blocks, benchmark_iterations)
    return success, enc_time_ms, dec_time_ms


def format_milliseconds(duration_ms: float) -> str:
    if duration_ms != duration_ms:  # NaN check
        return "n/a"
    return f"{duration_ms:8.3f} ms"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate and benchmark the reference Twofish implementation",
    )
    parser.add_argument(
        "--key-sizes",
        nargs="*",
        type=int,
        default=[128, 192, 256],
        help="Key sizes (in bits) to exercise",
    )
    parser.add_argument(
        "--message-sizes",
        nargs="*",
        type=int,
        default=[16, 64, 256, 1024],
        help="Plaintext lengths (in bytes) to encrypt",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=3,
        help="Number of random samples per key/message combination",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Seed for deterministic pseudo-random data generation",
    )
    parser.add_argument(
        "--benchmark-iterations",
        type=int,
        default=100,
        help="Repetitions for timing measurement",
    )
    args = parser.parse_args()

    print("Twofish validation and benchmark harness")
    print(f"Block size: {BLOCK_LEN} bytes")
    print(f"Benchmark iterations: {args.benchmark_iterations}")

    for key_bits in args.key_sizes:
        if key_bits % 64:
            print(f"- Skipping unsupported key length {key_bits} bits")
            continue

        print(f"\n=== Key size: {key_bits} bits ===")
        for message_len in args.message_sizes:
            if message_len <= 0:
                print(f"  * Skipping non-positive message length {message_len}")
                continue

            enc_times: List[float] = []
            dec_times: List[float] = []
            for sample_idx in range(args.samples):
                success, enc_time, dec_time = run_validation(
                    key_bits,
                    message_len,
                    seed=args.seed,
                    benchmark_iterations=args.benchmark_iterations,
                    sample_seed=sample_idx + message_len,
                )
                if not success:
                    raise AssertionError(
                        f"Round-trip failure for key={key_bits} bits message={message_len} bytes"
                    )
                enc_times.append(enc_time)
                dec_times.append(dec_time)

            print(
                f"  * Message length {message_len:5d} bytes | "
                f"enc avg {format_milliseconds(mean(enc_times))} | "
                f"dec avg {format_milliseconds(mean(dec_times))}"
            )


if __name__ == "__main__":
    main()

