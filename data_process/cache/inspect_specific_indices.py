# inspect_specific_indices.py
# Author: Gemini
# Description: Loads and displays detailed cache information for a specific list of indices provided in a JSON file.

import os
import argparse
import json
from cache_analyzer import CacheAnalyzer

# -------------------------
# 从 cache_insight_analyzer.py 复制过来的辅助函数
# 确保此脚本也能正确解析 qname 和 qtype
# -------------------------
_QTYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 46: 'RRSIG', 47: 'NSEC', 50: 'NSEC3', 51: 'NSEC3PARAM',
    255: 'ANY'
}

def _safe_qname_to_str(qname):
    if qname is None: return None
    try:
        return qname.decode('utf-8') if isinstance(qname, bytes) else str(qname)
    except Exception:
        try: return qname.decode('utf-8', errors='ignore')
        except Exception: return str(qname)

def _safe_qtype_to_str(qtype):
    if qtype is None: return None
    try: qtype_int = int(qtype)
    except (ValueError, TypeError): return str(qtype)
    
    # 优先使用 scapy 的映射（如果可用且安装）
    try:
        from scapy.layers.dns import QTYPE
        for k, v in QTYPE.items():
            if v == qtype_int: return k
    except Exception: pass
    
    return _QTYPE_MAP.get(qtype_int, str(qtype_int))

# -------------------------
# 主逻辑
# -------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Inspects detailed cache differences for a specific list of indices from a JSON file.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--res_folder', type=str, required=True, help="Path to the main results folder (e.g., ../../test_infra/recursive_test_res).")
    parser.add_argument('--json_file', type=str, required=True, help="Path to the JSON file containing the 'indices' to inspect (e.g., cache_insight_analysis_result/CP2.json).")
    args = parser.parse_args()

    # --- 1. 验证路径 ---
    if not os.path.isdir(args.res_folder):
        print(f"[!] Error: Results folder not found at '{args.res_folder}'")
        return
    if not os.path.isfile(args.json_file):
        print(f"[!] Error: JSON file not found at '{args.json_file}'")
        return

    # --- 2. 读取并解析 JSON 文件 ---
    try:
        with open(args.json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        indices_to_check = data.get("indices")
        filter_name = data.get("filter_name", "Unknown Filter")

        if not isinstance(indices_to_check, list) or not indices_to_check:
            print(f"[!] Error: The key 'indices' in '{args.json_file}' is missing, empty, or not a list.")
            return
    except json.JSONDecodeError:
        print(f"[!] Error: Failed to parse JSON from '{args.json_file}'.")
        return
    except Exception as e:
        print(f"[!] An unexpected error occurred while reading the JSON file: {e}")
        return

    print(f"[*] Starting inspection for filter: '{filter_name}'")
    print(f"[*] Found {len(indices_to_check)} indices to analyze from '{os.path.basename(args.json_file)}'.")

    # --- 3. 遍历并分析每个指定的 Index ---
    for index_str in indices_to_check:
        print("\n" + "="*80)
        print(f"🔍 Inspecting Index: {index_str}")
        print("="*80)

        try:
            # 这里的 index_str 格式是 '10/820'，需要拆分
            parts = index_str.split('/')
            if len(parts) != 2:
                print(f"[!] Warning: Skipping invalid index format '{index_str}'. Expected 'toplevel/sublevel'.")
                continue
            
            top_dir, sub_dir = parts
            
            # 使用 CacheAnalyzer 加载数据
            # directory 指向顶级目录（如 '10'），index 指向次级目录（如 '820'）
            analyzer = CacheAnalyzer(directory=os.path.join(args.res_folder, top_dir), index=sub_dir)

            if not analyzer.res:
                print("[i] No cache differences were recorded for this index. Skipping.")
                continue

            # 打印客户端查询
            if analyzer.client_query and hasattr(analyzer.client_query, 'qd') and analyzer.client_query.qd:
                qname = _safe_qname_to_str(analyzer.client_query.qd.qname)
                qtype = _safe_qtype_to_str(analyzer.client_query.qd.qtype)
                print(f"➡️ Client Query:\n    Name: {qname}\n    Type: {qtype}")
            else:
                print("➡️ Client Query: Not available.")

            # 打印详细的缓存差异
            print("\n📋 Cache Differences Found:")
            for domain, records_by_sw in analyzer.res.items():
                print(f"\n  Domain: {domain}")
                for sw, sw_records in records_by_sw.items():
                    print(f"    - Resolver: {sw.upper()}")
                    if not sw_records:
                        print("      (no records cached)")
                        continue
                    for rec in sw_records:
                        rec_type = rec.get('type', 'N/A')
                        rec_data = rec.get('data', 'N/A')
                        rec_ttl = rec.get('ttl', 'N/A')
                        
                        # 特别高亮显示可能触发 CP2 漏洞的记录
                        highlight = ""
                        if sw.lower() == 'powerdns' and qname in domain and qname != domain and rec_type == 'NS':
                            highlight = "  <-- 🎯 SUSPICIOUS NS RECORD!"

                        print(f"      - Type: {rec_type:<8} TTL: {rec_ttl:<8} Data: {rec_data}{highlight}")

        except FileNotFoundError:
             print(f"[!] Error: Could not find data files for index '{index_str}'. Please check the path.")
        except Exception as e:
            print(f"[!] An error occurred while processing index '{index_str}': {e}")
            # 可以加上 traceback 打印更详细的错误堆栈
            # import traceback
            # traceback.print_exc()

    print("\n" + "="*80)
    print("[*] Inspection complete.")


if __name__ == "__main__":
    main()

# sample usage:
# python inspect_specific_indices.py \
#  --res_folder ../../test_infra/recursive_test_res \
#  --json_file cache_insight_analysis_result/CP2.json > cp2_detailed_inspection.txt