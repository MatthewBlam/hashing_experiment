import argparse
import csv
import hashlib
import multiprocessing as mp
import re
import time
from pathlib import Path

import bcrypt
from nltk.corpus import words


BASE_DIR = Path(__file__).resolve().parent
FIELDS = [
    "username", "password", "status", "cost", "candidates_checked",
    "seconds", "checks_per_second", "workers", "dictionary_size",
    "dictionary_sha256", "stored_hash",
]


def load_candidates():
    # Keep original spelling and case; remove duplicates in corpus order
    candidates = list(dict.fromkeys(
        word for word in words.words()
        if re.fullmatch(r"[A-Za-z]{6,10}", word)
    ))

    if not candidates:
        raise ValueError("The corpus contains no suitable words.")

    return candidates


def load_accounts(path):
    accounts = []
    usernames = set()

    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue

        username, separator, stored_hash = line.strip().partition(":")

        valid_hash = re.fullmatch(
            r"\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}",
            stored_hash,
        )

        if not separator or not username or not valid_hash:
            raise ValueError(f"Invalid account on line {number}.")

        if username in usernames:
            raise ValueError(f"Duplicate username: {username}")

        usernames.add(username)
        accounts.append((username, stored_hash.encode("ascii")))

    if not accounts:
        raise ValueError("The shadow file contains no accounts.")

    return accounts


def initialize_worker(candidates, stored_hash, stop_event):
    # Each process gets its own word list and the same shared stop signal
    global worker_words, worker_hash, worker_stop
    worker_words = [word.encode("ascii") for word in candidates]
    worker_hash = stored_hash
    worker_stop = stop_event


def check_chunk(bounds):
    start, end = bounds
    checked = 0

    for index in range(start, end):
        if worker_stop.is_set():
            break

        checked += 1

        if bcrypt.checkpw(worker_words[index], worker_hash):
            worker_stop.set()
            return worker_words[index].decode("ascii"), checked

    return None, checked


def crack_password(stored_hash, candidates, workers, chunk_size):
    started = time.perf_counter()
    checked = 0
    password = None

    if workers == 1:
        for word in candidates:
            checked += 1

            if bcrypt.checkpw(word.encode("ascii"), stored_hash):
                password = word
                break

            if checked % chunk_size == 0:
                print(f"  Checked {checked:,} words", flush=True)
    else:
        context = mp.get_context("spawn")
        stop_event = context.Event()
        chunks = [
            (start, min(start + chunk_size, len(candidates)))
            for start in range(0, len(candidates), chunk_size)
        ]

        with context.Pool(
            processes=workers,
            initializer=initialize_worker,
            initargs=(candidates, stored_hash, stop_event),
        ) as pool:
            for result, count in pool.imap_unordered(check_chunk, chunks):
                checked += count

                if result is not None:
                    password = result

                if count and password is None:
                    print(f"  Completed {checked:,} checks", flush=True)

    elapsed = time.perf_counter() - started
    return password, checked, elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shadow", type=Path, default=BASE_DIR / "shadow.txt")
    parser.add_argument("--out", type=Path, default=BASE_DIR / "task2_results.csv")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--chunk-size", type=int, default=64)
    parser.add_argument("--user", help="Search one username instead of all users")

    args = parser.parse_args()
    if args.workers < 1 or args.chunk_size < 1:
        parser.error("Workers and chunk size must be positive.")

    candidates = load_candidates()
    accounts = load_accounts(args.shadow)
    dictionary_hash = hashlib.sha256(
        "\n".join(candidates).encode("ascii")
    ).hexdigest()

    print(f"Loaded {len(candidates):,} distinct 6-10 letter words.")

    if args.user:
        accounts = [(user, hashed) for user, hashed in accounts
                    if user == args.user]
        if not accounts:
            parser.error("That username is not in the shadow file.")

    completed = set()
    if args.out.exists() and args.out.stat().st_size:
        with args.out.open(newline="") as file:
            reader = csv.DictReader(file)
            if reader.fieldnames != FIELDS:
                raise ValueError("Results format differs; choose a new --out file.")

            for row in reader:
                if row["dictionary_sha256"] != dictionary_hash:
                    raise ValueError("Dictionary changed; choose a new --out file.")
                if row["status"] == "found":
                    completed.add((row["username"], row["stored_hash"]))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        if file.tell() == 0:
            writer.writeheader()

        for username, stored_hash in accounts:
            if (username, stored_hash.decode("ascii")) in completed:
                print(f"Skipping {username}: already found.")
                continue
            cost = int(stored_hash[4:6])
            print(f"Searching {username}, bcrypt cost {cost}...", flush=True)
            password, checked, elapsed = crack_password(
                stored_hash, candidates, args.workers, args.chunk_size
            )
            writer.writerow({
                "username": username,
                "password": password or "",
                "status": "found" if password is not None else "not_found",
                "cost": cost,
                "candidates_checked": checked,
                "seconds": f"{elapsed:.6f}",
                "checks_per_second": f"{checked / elapsed:.6f}",
                "workers": args.workers,
                "dictionary_size": len(candidates),
                "dictionary_sha256": dictionary_hash,
                "stored_hash": stored_hash.decode("ascii"),
            })
            file.flush()
            print(f"{username}: {password or 'NOT FOUND'}; "
                  f"{checked:,} checks; {elapsed:.2f} seconds", flush=True)

    print(f"Results saved to {args.out}")


if __name__ == "__main__":
    main()
