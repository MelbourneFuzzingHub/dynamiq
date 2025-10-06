import sys
import os

def dedup_file(filepath, key_func):
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return 0, 0, 0

    with open(filepath, "r") as f:
        lines = f.readlines()

    seen = set()
    unique_lines = []
    for line in lines:
        key = key_func(line.strip())
        if key not in seen:
            seen.add(key)
            unique_lines.append(line)

    with open(filepath, "w") as f:
        f.writelines(unique_lines)

    original = len(lines)
    remaining = len(unique_lines)
    removed = original - remaining
    return original, removed, remaining


def dedup_all(prefix):
    base_path = f"/tmp/{prefix}"
    results = {}

    # func_ids.log: "fname hash"
    fid_file = os.path.join(base_path, "func_ids.log")
    fid_key = lambda l: l.strip()  # full line as key
    results["func_ids.log"] = dedup_file(fid_file, fid_key)

    # func_bbs.log: "filename:functionname: bbcount"
    fbb_file = os.path.join(base_path, "func_bbs.log")
    fbb_key = lambda l: l.strip()
    results["func_bbs.log"] = dedup_file(fbb_file, fbb_key)

    # covered_functions.log: "Function: a->b"
    cfn_file = os.path.join(base_path, "covered_functions.log")
    cfn_key = lambda l: l.strip()
    results["covered_functions.log"] = dedup_file(cfn_file, cfn_key)

    print("\nDeduplication Summary")
    print("----------------------")
    for name, (orig, rem, remain) in results.items():
        print(f"{name}: Original={orig}, Removed={rem}, Remaining={remain}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 dedup_logs.py <binary_name>")
        sys.exit(1)
    dedup_all(sys.argv[1])
