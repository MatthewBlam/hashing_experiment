import csv
import hashlib
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt


MAX_BITS = 50
OUTPUT_DIR = Path("task1_results")
CSV_FIELDS = ["bits", "inputs", "seconds", "first_hex", "second_hex", "digest_hex"]


def truncated_hash(message, bits):
    digest = hashlib.sha256(message).digest()
    value = int.from_bytes(digest, "big")
    return value >> (256 - bits)


def birthday_collision(bits, prefix, max_seconds=0, max_entries=0):
    seen = {}
    started = time.perf_counter()
    count = 0

    while True:
        if max_seconds and time.perf_counter() - started >= max_seconds:
            return None, None, count, "time_limit"

        message = prefix + count.to_bytes(8, "big")
        digest = truncated_hash(message, bits)
        count += 1

        previous = seen.get(digest)
        if previous is not None:
            first = prefix + previous.to_bytes(8, "big")
            return first, message, count, "found"

        if max_entries and len(seen) >= max_entries:
            return None, None, count, "entry_limit"

        seen[digest] = count - 1


def avalanche_tests():
    lines = []
    for original in [b"A", b"hello", b"computer security"]:
        changed = bytes([original[0] ^ 1]) + original[1:]
        input_bits = sum((a ^ b).bit_count()
                         for a, b in zip(original, changed))
        assert input_bits == 1

        first = hashlib.sha256(original).digest()
        second = hashlib.sha256(changed).digest()
        different_bits = sum((a ^ b).bit_count()
                             for a, b in zip(first, second))
        different_bytes = sum(a != b for a, b in zip(first, second))

        lines.extend([
            f"Inputs: {original!r} and {changed!r}",
            f"Input Hamming distance: {input_bits} bit",
            f"First digest:  {first.hex()}",
            f"Second digest: {second.hex()}",
            f"Different digest bits: {different_bits}/256",
            f"Different digest bytes: {different_bytes}/32",
            "",
        ])

    output = "\n".join(lines)
    print(output)
    (OUTPUT_DIR / "avalanche_results.txt").write_text(output, encoding="utf-8")


def collision_experiments():
    path = OUTPUT_DIR / "collisions.csv"
    completed = set()
    if path.exists():
        with path.open(newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            if reader.fieldnames != CSV_FIELDS:
                raise ValueError("CSV columns do not match this script")
            completed = {int(row["bits"]) for row in reader}

    with path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)
        if file.tell() == 0:
            writer.writeheader()
            file.flush()

        for bits in range(8, MAX_BITS + 1, 2):
            if bits in completed:
                print(f"Skipping {bits} bits: already recorded", flush=True)
                continue

            print(f"Searching for a {bits}-bit collision...", flush=True)
            start = time.perf_counter()
            first, second, count, status = birthday_collision(
                bits, prefix=f"test-{bits}:".encode("ascii"))
            elapsed = time.perf_counter() - start

            if status != "found":
                print(f"{bits} bits: stopped with status {status}", flush=True)
                continue

            digest = truncated_hash(first, bits)
            assert first != second
            assert digest == truncated_hash(second, bits)
            digest_hex = f"{digest:0{(bits + 3) // 4}x}"

            writer.writerow({
                "bits": bits, "inputs": count, "seconds": elapsed,
                "first_hex": first.hex(), "second_hex": second.hex(),
                "digest_hex": digest_hex,
            })
            file.flush()

            print(f"{bits} bits: {count:,} inputs, {elapsed:.6f} seconds")
            print("First input:", first.hex())
            print("Second input:", second.hex())
            print("Matching truncated digest:", digest_hex, flush=True)


def create_graphs():
    with (OUTPUT_DIR / "collisions.csv").open(newline="", encoding="utf-8") as file:
        rows = sorted(csv.DictReader(file), key=lambda row: int(row["bits"]))

    if not rows:
        print("No completed collisions to graph")
        return

    sizes = [int(row["bits"]) for row in rows]
    for field, ylabel, filename in [
        ("seconds", "Collision time (seconds)", "collision_time.png"),
        ("inputs", "Number of inputs hashed", "collision_inputs.png"),
    ]:
        values = [float(row[field]) for row in rows]
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(sizes, values, "o-")
        ax.set_xlabel("Truncated digest size (bits)")
        ax.set_ylabel(ylabel)
        ax.set_yscale("log")
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(OUTPUT_DIR / filename, dpi=200)
        plt.close(fig)


def main():
    if not 8 <= MAX_BITS <= 50 or MAX_BITS % 2:
        raise ValueError("MAX_BITS must be an even number from 8 through 50")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    message = input("Enter a message to hash: ").encode("utf-8")
    print("SHA-256:", hashlib.sha256(message).hexdigest())

    avalanche_tests()
    collision_experiments()
    create_graphs()
    print(f"Results saved in {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
