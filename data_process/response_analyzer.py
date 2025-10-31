# response_analyzer.py (Prioritization & Insight Version)

import os
import argparse
import re
from collections import defaultdict, Counter

DNS_SW_LIST = ['bind9', 'unbound', 'powerdns', 'knot', 'technitium']

def aggressive_normalize(content: str):
    # This function remains the same as it correctly extracts core semantics.
    if content.startswith("--- FILE NOT FOUND ---") or content.startswith("No response"):
        return content
    rcode_pattern = re.compile(r"^\s*rcode\s*=\s*(\w+)", re.MULTILINE)
    record_pattern = re.compile(
        r"\|\s*rrname\s*=\s*'(.*?)'\s*\|.*?\|\s*type\s*=\s*(\w+)\s*\|.*?\|\s*rdata\s*=\s*'(.*?)'", re.DOTALL)
    rcode_match = rcode_pattern.search(content)
    core_rcode = f"RCODE:{rcode_match.group(1)}" if rcode_match else "RCODE:UNKNOWN"
    records = record_pattern.findall(content)
    sorted_records = sorted([(name, type, rdata) for name, type, rdata in records])
    fingerprint = [core_rcode]
    for name, type, rdata in sorted_records:
        fingerprint.append(f"RECORD:{name}|{type}|{rdata}")
    return "\n".join(fingerprint)

# +++ NEW: Advanced classification function +++
def classify_detailed_difference(grouped_responses: dict) -> str:
    """Classifies the inconsistency with more detail for prioritization."""
    fingerprints = list(grouped_responses.keys())
    
    # --- Timeout Classification ---
    has_timeout = any("No response" in fp for fp in fingerprints)
    if has_timeout:
        responding_rcodes = set()
        for fp in fingerprints:
            if fp.startswith("RCODE:"):
                responding_rcodes.add(fp.split('\n')[0].split(':')[1])
        if not responding_rcodes:
            return "All Timed Out (Inconclusive)"
        # e.g., "Timeout vs. Response(FORMERR, SERVFAIL)"
        return f"Timeout vs. Response({','.join(sorted(list(responding_rcodes)))})"

    # --- RCODE Mismatch Classification ---
    rcodes = set()
    for fp in fingerprints:
        if fp.startswith("RCODE:"):
            rcodes.add(fp.split('\n')[0].split(':')[1])
    if len(rcodes) > 1:
        # e.g., "RCODE Mismatch (FORMERR vs. SERVFAIL)"
        return f"RCODE Mismatch ({' vs. '.join(sorted(list(rcodes)))})"

    # --- Answer Content Mismatch ---
    record_sets = set()
    for fp in fingerprints:
        records = tuple(sorted([line for line in fp.split('\n') if line.startswith("RECORD:")]))
        record_sets.add(records)
    if len(record_sets) > 1:
        return "Answer Content Mismatch"

    return "Other Minor Difference"

def analyze_responses_for_index(base_path: str):
    responses_data = {}
    for sw_name in DNS_SW_LIST:
        file_path = os.path.join(base_path, sw_name, 'response_parsed.txt')
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read().strip()
                normalized_content = aggressive_normalize(content)
                responses_data[sw_name] = normalized_content
        except FileNotFoundError:
            responses_data[sw_name] = "--- FILE NOT FOUND ---"
    unique_responses = set(responses_data.values())
    if len(unique_responses) <= 1:
        return None, None
    grouped_responses = defaultdict(list)
    for sw_name, content in responses_data.items():
        grouped_responses[content].append(sw_name)
    
    diff_type = classify_detailed_difference(grouped_responses)
    return grouped_responses, diff_type

# --- main() function remains the same, it will now display detailed stats ---
def main():
    parser = argparse.ArgumentParser(description="Analyzes and classifies DNS resolver responses.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--res_folder', type=str, required=True, help="Path to the main results folder.")
    parser.add_argument('--verbose', '-v', action='store_true', help="Show detailed differences for each inconsistent test case.")
    parser.add_argument('--limit', type=int, default=0, help="Limit the number of sub-directories to process for a quick test run.")
    args = parser.parse_args()
    print(f"[*] Starting response analysis in folder: {args.res_folder}")
    if not os.path.isdir(args.res_folder):
        print(f"[!] Error: Provided path is not a valid directory.")
        return
    total_indices_processed = 0
    total_indices_with_diffs = 0
    diff_type_counter = Counter()
    top_level_dirs = sorted([d.name for d in os.scandir(args.res_folder) if d.is_dir() and d.name.isdigit()])

    for top_dir in top_level_dirs:
        top_dir_path = os.path.join(args.res_folder, top_dir)
        sub_level_dirs = sorted([int(d.name) for d in os.scandir(top_dir_path) if d.is_dir() and d.name.isdigit()])
        
        # Optional limit for faster testing
        if args.limit > 0:
            sub_level_dirs = sub_level_dirs[:args.limit]

        for sub_dir_int in sub_level_dirs:
            sub_dir = str(sub_dir_int)
            total_indices_processed += 1
            index_path = os.path.join(top_dir_path, sub_dir)
            diff_groups, diff_type = analyze_responses_for_index(index_path)
            if diff_groups:
                total_indices_with_diffs += 1
                diff_type_counter[diff_type] += 1
                if args.verbose:
                     print(f"  --- Index: {top_dir}/{sub_dir} -> Result: Difference found! Type: [{diff_type}]")
                     for i, (content, sw_list) in enumerate(diff_groups.items()):
                        print(f"    - Group {i+1}: Responded by {', '.join(sw_list)}")
                        print("    - Core Semantic Fingerprint:")
                        indented_content = "      " + content.replace('\n', '\n      ')
                        print(indented_content)
                        print("-" * 20)

    print("\n\n" + "="*20 + " Analysis Summary " + "="*20)
    print(f"[*] Total test indices processed: {total_indices_processed}")
    print(f"[*] Total test indices with response differences: {total_indices_with_diffs}")
    print("\n--- Breakdown of Difference Types (Top 20) ---")
    if not diff_type_counter:
        print("No differences to classify.")
    else:
        print(f"{'Difference Type':<50} | {'Count':<10}")
        print("-" * 63)
        for diff_type, count in diff_type_counter.most_common(20):
            print(f"{diff_type:<50} | {count:<10}")

if __name__ == "__main__":
    main()