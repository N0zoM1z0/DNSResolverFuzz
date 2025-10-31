# cache_insight_analyzer.py
# Author: Gemini (based on ResolverFuzz author's clustering.py and filters.py)
# Extended to include all filters from filters.py (CP4, R6, R7, and collect_info)

import os
import argparse
from collections import Counter, defaultdict
from scapy import all as scapy

# 我们需要 CacheAnalyzer 来加载数据
from cache_analyzer import CacheAnalyzer

# -------------------------
# 辅助函数：安全地把 qname/qtype 转为字符串
# -------------------------
# 本字典覆盖常见的 DNS 类型码（兼容没有 scapy 提供映射的情况）
_QTYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 46: 'RRSIG', 47: 'NSEC', 50: 'NSEC3', 51: 'NSEC3PARAM',
    255: 'ANY'
}

def _safe_qname_to_str(qname):
    """接受 bytes 或 str，并返回以 . 结尾的域名字符串（保持原来行为）。"""
    if qname is None:
        return None
    # qname 有时是 bytes，也有时是 scapy 的 Field 等，尽量处理
    try:
        if isinstance(qname, bytes):
            # scapy qname bytes 通常带结尾的点
            return qname.decode('utf-8')
        # scapy 的 DNSQR.qname 有时是类型 scapy.fields.StrField，直接 str() 通常能得到带点的形式
        # 也可能是 object with .fields, handle gracefully
        return str(qname)
    except Exception:
        # 回退：尽量安全返回可打印表示
        try:
            return qname.decode('utf-8', errors='ignore')
        except Exception:
            return str(qname)

def _safe_qtype_to_str(qtype):
    """
    尝试把 qtype（可能是 int、bytes、str）转换为标准的字符串类型（例如 'A', 'NS', 'NSEC3'）。
    优先尝试从 scapy 动态获取映射，如果失败则使用本地映射 _QTYPE_MAP，最后回退为数字字符串。
    """
    if qtype is None:
        return None

    # 先把 bytes/str 转为 int（如果可能）
    try:
        if isinstance(qtype, bytes):
            # 有时候 scapy 会把 qtype 当成 2 字节数据，这里尝试转 int
            try:
                qtype_int = int.from_bytes(qtype, byteorder='big')
            except Exception:
                qtype_int = int(qtype)
        elif isinstance(qtype, str):
            # 如果是数字字符串
            if qtype.isdigit():
                qtype_int = int(qtype)
            else:
                # 可能已经是 'A' 之类
                return qtype
        else:
            # 假设是 int 或可转为 int
            qtype_int = int(qtype)
    except Exception:
        # 最后回退为字符串表示
        return str(qtype)

    # 尝试从 scapy 中读取已有的映射（如果可用）
    try:
        dns_module = scapy.layers.dns
        if hasattr(dns_module, 'QTYPE'):
            # QTYPE 是字典 name->value，先尝试反查
            qname = None
            for k, v in dns_module.QTYPE.items():
                if v == qtype_int:
                    qname = k
                    break
            if qname:
                return qname
        # 另：有些 scapy 版本可能提供 qtypes 列表
        if hasattr(dns_module, 'qtypes'):
            try:
                return dns_module.qtypes[qtype_int]
            except Exception:
                pass
    except Exception:
        # 忽略 scapy 读取异常，继续回退
        pass

    # 使用本地硬编码映射
    if qtype_int in _QTYPE_MAP:
        return _QTYPE_MAP[qtype_int]

    # 回退为数字字符串
    return str(qtype_int)

# ##################################################################################
# 移植并整合自 filters.py 的所有过滤器函数（完整覆盖）
# ##################################################################################

def collect_info(caches):
    """
    collect_info: 返回解析器存在情况统计，兼容 cache.count 或按照 cache.res 的内容判定。
    返回 (count_dict, total_cases)
    count_dict keys: 'bind9', 'pdns', 'unbound', 'technitium'
    """
    count = {'bind9': 0, 'pdns': 0, 'technitium': 0, 'unbound': 0}
    for cache in caches:
        # 优先使用 cache.count（如果存在并有预期字段），兼容 filters.py 原始实现
        used_flag = False
        try:
            if hasattr(cache, 'count') and isinstance(cache.count, dict):
                # 原 filters.py 用 'bind9' 和 'powerdns'
                if cache.count.get('bind9', 0) > 0:
                    count['bind9'] += 1
                    used_flag = True
                if cache.count.get('powerdns', 0) > 0:
                    count['pdns'] += 1
                    used_flag = True
                if cache.count.get('unbound', 0) > 0:
                    count['unbound'] += 1
                    used_flag = True
                if cache.count.get('technitium', 0) > 0:
                    count['technitium'] += 1
                    used_flag = True
        except Exception:
            used_flag = False

        if used_flag:
            continue

        # 回退：基于 cache.res 的内容来判断（更健壮）
        try:
            if getattr(cache, 'res', None):
                seen_bind = False
                seen_pdns = False
                seen_unbound = False
                seen_technitium = False
                for domain, record in cache.res.items():
                    # record 预期是 dict 包含 'bind','pdns','unbound','technitium' 等
                    if not seen_bind and record.get('bind'):
                        # 有非空列表则认为存在
                        if len(record.get('bind') or []) > 0:
                            seen_bind = True
                    if not seen_pdns and record.get('pdns'):
                        if len(record.get('pdns') or []) > 0:
                            seen_pdns = True
                    if not seen_unbound and record.get('unbound'):
                        if len(record.get('unbound') or []) > 0:
                            seen_unbound = True
                    if not seen_technitium and record.get('technitium'):
                        if len(record.get('technitium') or []) > 0:
                            seen_technitium = True
                    if seen_bind and seen_pdns and seen_unbound and seen_technitium:
                        break
                if seen_bind:
                    count['bind9'] += 1
                if seen_pdns:
                    count['pdns'] += 1
                if seen_unbound:
                    count['unbound'] += 1
                if seen_technitium:
                    count['technitium'] += 1
        except Exception:
            # 忽略异常，继续下一个 cache
            pass

    return count, len(caches)


def filter_cp1(caches):
    """
    CP1: 寻找 BIND 或 Technitium 缓存了某些非预期域名的案例
    """
    sw_list = ['bind', 'technitium']
    ignore_domain = ['merlin.ns.cloudflare.com.', 'stephane.ns.cloudflare.com.', 'qifanzhang.com.', 'ns.cloudflare.com.', 'cloudflare.com.', 'gtld-servers.net.', 'CK0POJMG874LJREF7EFN8430QVIT8BSM.com.', '3RL2Q58205687C8I9KC9MV46DGHCNS45.com.', 'nstld.com.', 'av4.nstld.com.', 'av2.nstld.com.', 'av1.nstld.com.', 'av3.nstld.com.', 'G1DHAQQ6L74TAIA763K3US9DMVGSGPP2.com.', 'j.root-servers.', 'nia.ns.cloudflare.com.', 'chad.ns.cloudflare.com.']
    
    hits = []
    for cache in caches:
        is_hit = False
        if not cache.res: continue
        for domain, record in cache.res.items():
            if ".xuesongb.com." not in domain and domain not in ignore_domain:
                for sw in sw_list:
                    sw_recs = record.get(sw)
                    if sw_recs:
                        # sw_recs 预期为 list
                        for rec in sw_recs:
                            # 如果存在任何记录则认为命中（保持原来行为）
                            is_hit = True
                            break
                    if is_hit:
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits


def filter_cp2(caches):
    """
    CP2: 寻找 PowerDNS 缓存了某个域名的“子域名NS记录”的案例
    """
    hits = []
    for cache in caches:
        if not (cache.res and cache.client_query and hasattr(cache.client_query, 'qd') and cache.client_query.qd):
            continue
        is_hit = False
        qname_raw = cache.client_query.qd.qname
        qname_str = _safe_qname_to_str(qname_raw)
        
        for domain, record in cache.res.items():
            pdns_recs = record.get('pdns')
            if pdns_recs:
                for rec in pdns_recs:
                    # 如果缓存中的域名是查询域名的子域名，并且记录类型是NS
                    if qname_str in domain and qname_str != domain and rec.get('type') == 'NS':
                        is_hit = True
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits


def filter_cp4(caches):
    """
    CP4: 类似 CP2，但对所有解析器（bind/pdns/unbound/technitium）检查：查询域名为某域名的父域且缓存里存在 NS 记录的情况。
    对应 filters.py 中的 filter_cp4。
    """
    sw_list = ['bind', 'pdns', 'unbound', 'technitium']
    hits = []
    for cache in caches:
        if not (cache.res and cache.client_query and hasattr(cache.client_query, 'qd') and cache.client_query.qd):
            continue
        is_hit = False
        qname_raw = cache.client_query.qd.qname
        qname_str = _safe_qname_to_str(qname_raw)

        for domain, record in cache.res.items():
            for sw in sw_list:
                sw_recs = record.get(sw)
                if sw_recs:
                    for rec in sw_recs:
                        # 需要确保 domain 是 qname_str 的子域名且记录类型为 NS
                        if qname_str in domain and qname_str != domain and rec.get('type') == 'NS':
                            is_hit = True
                            break
                if is_hit:
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits


def filter_r1(caches):
    """
    R1: 缓存中包含了与查询完全匹配的域名和类型的记录
    """
    hits = []
    for cache in caches:
        if not (cache.res and cache.client_query and hasattr(cache.client_query, 'qd') and cache.client_query.qd):
            continue
        is_hit = False
        qname_raw = cache.client_query.qd.qname
        qtype_raw = cache.client_query.qd.qtype

        qname_str = _safe_qname_to_str(qname_raw)
        qtype_str = _safe_qtype_to_str(qtype_raw)
        
        for domain, record in cache.res.items():
            if domain == qname_str:
                # 检查所有解析器的缓存记录
                for sw_name in ['bind', 'pdns', 'unbound', 'technitium']:
                    sw_recs = record.get(sw_name)
                    if sw_recs:
                        for rec in sw_recs:
                            if rec.get('type') == qtype_str:
                                is_hit = True
                                break
                    if is_hit:
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits


def filter_r2(caches):
    """
    R2: 寻找 Fallback 行为 (缓存了 Cloudflare 的 NS)
    """
    target_domain = {'merlin.ns.cloudflare.com.', 'stephane.ns.cloudflare.com.', 'nia.ns.cloudflare.com.', 'chad.ns.cloudflare.com.'}
    hits = []
    for cache in caches:
        if not cache.res: continue
        is_hit = False
        for domain, record in cache.res.items():
            if domain in target_domain:
                # 只要在这些域名存在任何解析器的缓存就算命中
                for sw in ['bind', 'pdns', 'unbound', 'technitium']:
                    if record.get(sw):
                        if len(record.get(sw) or []) > 0:
                            is_hit = True
                            break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits


def create_type_filter(target_types):
    """一个创建类型过滤器的辅助函数"""
    def type_filter(caches):
        hits = []
        for cache in caches:
            if not cache.res: continue
            is_hit = False
            for domain, record in cache.res.items():
                for sw_name in ['bind', 'pdns', 'unbound', 'technitium']:
                    sw_recs = record.get(sw_name)
                    if sw_recs:
                        for rec in sw_recs:
                            if rec.get('type') in target_types:
                                is_hit = True
                                break
                    if is_hit:
                        break
                if is_hit:
                    break
            if is_hit:
                hits.append(cache)
        return hits
    return type_filter

filter_r3 = create_type_filter({'NSEC3'})
filter_r4 = create_type_filter({'NSEC'})
filter_r5 = create_type_filter({'NSEC', 'NSEC3'})


def filter_r6(caches):
    """
    R6: 缓存中对目标域名存在记录但类型与查询类型不同（例如缓存了 A 但查询的是 AAAA）
    对应 filters.py 中的 filter_r6。
    """
    hits = []
    for cache in caches:
        if not (cache.res and cache.client_query and hasattr(cache.client_query, 'qd') and cache.client_query.qd):
            continue
        is_hit = False
        qname_raw = cache.client_query.qd.qname
        qtype_raw = cache.client_query.qd.qtype

        qname_str = _safe_qname_to_str(qname_raw)
        qtype_str = _safe_qtype_to_str(qtype_raw)

        for domain, record in cache.res.items():
            if domain == qname_str:
                for sw_name in ['bind', 'pdns', 'unbound', 'technitium']:
                    sw_recs = record.get(sw_name)
                    if sw_recs:
                        for rec in sw_recs:
                            # 如果缓存里存在与查询 qname 相同但 type 不同的记录则命中
                            if rec.get('type') != qtype_str:
                                is_hit = True
                                break
                    if is_hit:
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits


def filter_r7(caches):
    """
    R7: Revalidation 情况（缓存中包含 cloudflare.com.）
    对应 filters.py 中的 filter_r7。
    """
    target_domain = {'cloudflare.com.'}
    hits = []
    for cache in caches:
        if not cache.res: continue
        is_hit = False
        for domain, record in cache.res.items():
            if domain in target_domain:
                for sw_name in ['bind', 'pdns', 'unbound', 'technitium']:
                    sw_recs = record.get(sw_name)
                    if sw_recs and len(sw_recs) > 0:
                        is_hit = True
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

# ##################################################################################
# 主分析逻辑（保持你的原实现）
# ##################################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Analyzes cache differences, classifies them, and applies vulnerability pattern filters.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--res_folder', type=str, required=True, help="Path to the main results folder.")
    parser.add_argument('--verbose', '-v', action='store_true', help="Show detailed hit information for each filter.")
    args = parser.parse_args()

    print(f"[*] Starting cache insight analysis in folder: {args.res_folder}")

    if not os.path.isdir(args.res_folder):
        print(f"[!] Error: Provided path is not a valid directory.")
        return

    # --- 1. 加载所有存在差异的 CacheAnalyzer 对象 ---
    print("[*] Phase 1/3: Loading all cache differences... (This may take a while)")
    diff_cases = []
    total_indices_processed = 0
    top_level_dirs = sorted([d.name for d in os.scandir(args.res_folder) if d.is_dir() and d.name.isdigit()])

    for top_dir in top_level_dirs:
        top_dir_path = os.path.join(args.res_folder, top_dir)
        sub_level_dirs = sorted([d.name for d in os.scandir(top_dir_path) if d.is_dir() and d.name.isdigit()])

        for sub_dir in sub_level_dirs:
            total_indices_processed += 1
            if total_indices_processed % 500 == 0:
                print(f"    ...processed {total_indices_processed} indices...")
            try:
                analyzer = CacheAnalyzer(directory=top_dir_path, index=sub_dir)
                if analyzer.res:
                    diff_cases.append(analyzer)
            except Exception:
                # 忽略单个索引加载错误，继续
                continue
    
    print(f"[*] Phase 1/3: Complete. Found {len(diff_cases)} total differences out of {total_indices_processed} indices.")

    # --- 2. 按“活跃缓存组合”对差异进行分类 ---
    print("\n[*] Phase 2/3: Classifying differences by active cache combinations...")
    
    combination_counter = Counter()
    for case in diff_cases:
        # case.active_caches 预期是 list/iterable
        try:
            combination_key = ",".join(sorted(case.active_caches))
        except Exception:
            # 回退为基于 case.count 或 case.res 的简单组合表示
            try:
                comb = []
                if getattr(case, 'res', None):
                    # 检查是否存在每个解析器的数据
                    sample = next(iter(case.res.values()))
                    for sw in ['bind', 'pdns', 'unbound', 'technitium']:
                        if sample.get(sw):
                            comb.append(sw)
                combination_key = ",".join(sorted(comb)) or "unknown"
            except Exception:
                combination_key = "unknown"
        combination_counter[combination_key] += 1

    print("[*] Phase 2/3: Complete.")

    # --- 3. 应用所有过滤器并统计命中 ---
    print("\n[*] Phase 3/3: Applying vulnerability pattern filters...")

    all_filters = {
        "CP1: Suspicious Caching (BIND/Technitium)": filter_cp1,
        "CP2: Subdomain NS Record Caching (PowerDNS)": filter_cp2,
        "CP4: Subdomain NS Record Caching (All resolvers)": filter_cp4,
        "R1: Direct Match Caching": filter_r1,
        "R2: Fallback Behavior (Cloudflare NS)": filter_r2,
        "R3: NSEC3 Record Caching": filter_r3,
        "R4: NSEC Record Caching": filter_r4,
        "R5: Any NSEC/NSEC3 Record Caching": filter_r5,
        "R6: Cached Different Type Than Query": filter_r6,
        "R7: Revalidation (cloudflare.com.)": filter_r7
    }

    filter_hits = {}
    result_dir = os.path.join(os.getcwd(), "cache_insight_analysis_result")
    os.makedirs(result_dir, exist_ok=True)

    import json
    from datetime import datetime

    # 如果需要，先输出 collect_info 统计（与 filters.py 中的使用相似）
    try:
        count_info, total_cases = collect_info(diff_cases)
    except Exception:
        count_info, total_cases = None, len(diff_cases)

    for name, func in all_filters.items():
        try:
            hits = func(diff_cases)
        except Exception:
            # 如果某个 filter 在运行时出错，记录为空并继续
            hits = []
        indices = []
        for hit_case in hits:
            try:
                # hit_case.bind_path 在原实现中存在，我们按原方式回退
                case_directory = os.path.dirname(os.path.dirname(hit_case.bind_path))
                rel_index = os.path.relpath(case_directory, args.res_folder)
                indices.append(rel_index.replace(os.sep, '/'))
            except Exception:
                # 如果没有 bind_path，尝试使用其他属性回退
                try:
                    # 若有 index/dir 信息，可拼接；否则跳过
                    base = getattr(hit_case, 'directory', None) or getattr(hit_case, 'base_dir', None) or getattr(hit_case, 'path', None)
                    if base:
                        rel_index = os.path.relpath(base, args.res_folder)
                        indices.append(rel_index.replace(os.sep, '/'))
                except Exception:
                    continue
        
        # 保存统计信息
        filter_hits[name] = {
            "count": len(hits),
            "indices": indices
        }

        # 写入 JSON 文件
        safe_name = name.split(":")[0].strip().replace(" ", "_").replace("/", "_")
        json_path = os.path.join(result_dir, f"{safe_name}.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "filter_name": name,
                    "hit_count": len(hits),
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "indices": indices
                }, f, ensure_ascii=False, indent=2)
        except Exception:
            # 忽略单个写入错误
            pass

    print(f"[*] Phase 3/3: Complete. Results saved to folder: {result_dir}")

    # --- 4. 打印最终总结 ---
    print("\n\n" + "="*25 + " Cache Insight Summary " + "="*25)
    print(f"[*] Total test indices processed: {total_indices_processed}")
    print(f"[*] Total indices with cache differences: {len(diff_cases)}")

    # 如果 collect_info 成功，输出汇总
    if count_info is not None:
        print("\n" + "--- Collector Info ---")
        print(f"Total cases considered for collect_info: {total_cases}")
        print(f"Resolver presence counts (approx): {count_info}")

    print("\n" + "--- Breakdown by Active Cache Combinations (Top 10) ---")
    print(f"{'Resolver Combination':<50} | {'Count':<10}")
    print("-" * 63)
    for combo, count in combination_counter.most_common(10):
        print(f"{combo:<50} | {count:<10}")

    print("\n" + "--- Breakdown by Vulnerability Pattern Filter ---")
    print(f"{'Filter Name':<50} | {'Hits':<10}")
    print("-" * 63)
    sorted_filter_hits = sorted(filter_hits.items(), key=lambda item: item[1]['count'], reverse=True)
    for name, result in sorted_filter_hits:
        print(f"{name:<50} | {result['count']:<10}")

    if args.verbose:
        print("\n\n" + "="*25 + " Verbose Filter Hit Details " + "="*25)
        for name, result in sorted_filter_hits:
            if result['count'] > 0:
                print(f"\n--- Hits for filter: [{name}] ({result['count']} total) ---")
                for idx in result["indices"]:
                    print(f"  - {idx}")
    
if __name__ == "__main__":
    main()
