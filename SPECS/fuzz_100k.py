#!/usr/bin/env python3
"""Z.3: 100,000-mutation fuzz campaign for MARP decoder. Zero accepts required."""
import os, random, subprocess, sys, tempfile

def main():
    if len(sys.argv) < 3:
        print("usage: fuzz_100k.py <valid.mapr> <mapr_binary>")
        sys.exit(1)
    src_path, mapr_bin = sys.argv[1], sys.argv[2]
    with open(src_path, 'rb') as f:
        orig = bytearray(f.read())
    n = len(orig)
    rng = random.Random(5551234)
    rejected = 0
    accepted = 0
    total = 100000
    tmp = tempfile.mktemp(suffix='.mapr')
    try:
        for trial in range(total):
            mut = bytearray(orig)
            if trial < 5000:
                # truncation
                new_len = rng.randrange(0, n)
                mut = mut[:new_len]
            elif trial < 50000:
                # 1-4 bit flips
                flips = 1 + (trial % 4)
                for _ in range(flips):
                    pos = rng.randrange(n)
                    bit = 1 << (rng.randrange(8))
                    mut[pos] ^= bit
            else:
                # 1-8 byte overwrites
                k = 1 + (trial % 8)
                for _ in range(k):
                    pos = rng.randrange(max(1, len(mut)))
                    mut[pos] = rng.randrange(256)
            if mut == orig:
                rejected += 1
                continue
            with open(tmp, 'wb') as f:
                f.write(mut)
            r = subprocess.run([mapr_bin, 'decode', '--input', tmp, '--output', '/dev/null'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode == 0:
                accepted += 1
                print(f"ACCEPTED at trial {trial}")
                break
            rejected += 1
            if (trial + 1) % 10000 == 0:
                print(f"progress: {trial+1}/{total} rejected={rejected} accepted={accepted}", flush=True)
    finally:
        try: os.unlink(tmp)
        except: pass
    print(f"RESULT: total={total} rejected={rejected} accepted={accepted}")
    if accepted != 0:
        sys.exit(1)

if __name__ == '__main__':
    main()
