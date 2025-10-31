# cache_insight_analyzer.py
# Super version: integrates CP1-CP22, RC8-RC22, CC2-CC8 (heuristic detection)
# Compatible with provided CacheAnalyzer implementation (cache_analyzer.py).
# Usage: python cache_insight_analyzer.py --res_folder /path/to/results [--verbose]

import os
import argparse
from collections import Counter, defaultdict
from scapy import all as scapy

# 使用你提供的 CacheAnalyzer 类来加载每个索引的比较结果
from cache_analyzer import CacheAnalyzer

# -------------------------
# 辅助：安全地把 qname/qtype 转为字符串
# -------------------------
_QTYPE_MAP = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 46: 'RRSIG', 47: 'NSEC', 50: 'NSEC3', 51: 'NSEC3PARAM',
    255: 'ANY'
}

def _safe_qname_to_str(qname):
    if qname is None:
        return None
    try:
        if isinstance(qname, bytes):
            return qname.decode('utf-8')
        return str(qname)
    except Exception:
        try:
            return qname.decode('utf-8', errors='ignore')
        except Exception:
            return str(qname)

def _safe_qtype_to_str(qtype):
    if qtype is None:
        return None
    try:
        if isinstance(qtype, bytes):
            try:
                qtype_int = int.from_bytes(qtype, byteorder='big')
            except Exception:
                qtype_int = int(qtype)
        elif isinstance(qtype, str):
            if qtype.isdigit():
                qtype_int = int(qtype)
            else:
                return qtype
        else:
            qtype_int = int(qtype)
    except Exception:
        return str(qtype)
    try:
        dns_module = scapy.layers.dns
        if hasattr(dns_module, 'QTYPE'):
            for k, v in dns_module.QTYPE.items():
                if v == qtype_int:
                    return k
        if hasattr(dns_module, 'qtypes'):
            try:
                return dns_module.qtypes[qtype_int]
            except Exception:
                pass
    except Exception:
        pass
    if qtype_int in _QTYPE_MAP:
        return _QTYPE_MAP[qtype_int]
    return str(qtype_int)

# -------------------------
# collect_info（兼容，基于 CacheAnalyzer 的 res）
# -------------------------
def collect_info(caches):
    count = {'bind9': 0, 'pdns': 0, 'technitium': 0, 'unbound': 0}
    for cache in caches:
        used_flag = False
        try:
            if hasattr(cache, 'count') and isinstance(cache.count, dict):
                if cache.count.get('bind9', 0) > 0:
                    count['bind9'] += 1; used_flag = True
                if cache.count.get('powerdns', 0) > 0:
                    count['pdns'] += 1; used_flag = True
                if cache.count.get('unbound', 0) > 0:
                    count['unbound'] += 1; used_flag = True
                if cache.count.get('technitium', 0) > 0:
                    count['technitium'] += 1; used_flag = True
        except Exception:
            used_flag = False
        if used_flag:
            continue
        try:
            if getattr(cache, 'res', None):
                seen_bind = seen_pdns = seen_unbound = seen_technitium = False
                for domain, record in cache.res.items():
                    if not seen_bind and record.get('bind') and len(record.get('bind') or []) > 0:
                        seen_bind = True
                    if not seen_pdns and record.get('pdns') and len(record.get('pdns') or []) > 0:
                        seen_pdns = True
                    if not seen_unbound and record.get('unbound') and len(record.get('unbound') or []) > 0:
                        seen_unbound = True
                    if not seen_technitium and record.get('technitium') and len(record.get('technitium') or []) > 0:
                        seen_technitium = True
                    if seen_bind and seen_pdns and seen_unbound and seen_technitium:
                        break
                if seen_bind: count['bind9'] += 1
                if seen_pdns: count['pdns'] += 1
                if seen_unbound: count['unbound'] += 1
                if seen_technitium: count['technitium'] += 1
        except Exception:
            pass
    return count, len(caches)

# -------------------------
# 原始基本 filters（R1-R7, CP1-CP4）
# -------------------------
def filter_cp1(caches):
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
                        for rec in sw_recs:
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
                    if qname_str in domain and qname_str != domain and rec.get('type') == 'NS':
                        is_hit = True
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp4(caches):
    # 与 filters.py 中 filter_cp4 等价：对所有解析器检查 query 的 qname 是否为某缓存域名的父域并且该记录是 NS
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
                for rec in record.get(sw) or []:
                    try:
                        if qname_str in domain and qname_str != domain and rec.get('type') == 'NS':
                            is_hit = True
                            break
                    except Exception:
                        continue
                if is_hit:
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def create_type_filter(target_types):
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

def filter_r1(caches):
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
    target_domain = {'merlin.ns.cloudflare.com.', 'stephane.ns.cloudflare.com.', 'nia.ns.cloudflare.com.', 'chad.ns.cloudflare.com.'}
    hits = []
    for cache in caches:
        if not cache.res: continue
        is_hit = False
        for domain, record in cache.res.items():
            if domain in target_domain:
                for sw in ['bind', 'pdns', 'unbound', 'technitium']:
                    if record.get(sw) and len(record.get(sw) or []) > 0:
                        is_hit = True
                        break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_r6(caches):
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

# -------------------------
# 新增 CP5 - CP22 Filters（启发式）
# -------------------------
def filter_cp5_glue_ttl_overreach(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        is_hit = False
        for domain, record in cache.res.items():
            ns_ttl_map = {}
            glue_ttl_map = {}
            # collect NS TTLs from this record
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    try:
                        if rec.get('type') == 'NS':
                            nsname = rec.get('rdata') or rec.get('nsdname') or rec.get('target') or rec.get('value')
                            ttl = int(rec.get('ttl') or 0)
                            if nsname:
                                prev = ns_ttl_map.get(nsname)
                                ns_ttl_map[nsname] = ttl if prev is None else min(prev, ttl)
                    except Exception:
                        continue
            if not ns_ttl_map:
                continue
            # scan globally for A/AAAA whose owner equals nsname
            for dom2, record2 in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec2 in record2.get(sw) or []:
                        try:
                            if rec2.get('type') in ('A','AAAA'):
                                owner = dom2
                                for nsname in ns_ttl_map.keys():
                                    if owner == nsname:
                                        ttl2 = int(rec2.get('ttl') or 0)
                                        prev = glue_ttl_map.get(nsname)
                                        glue_ttl_map[nsname] = ttl2 if prev is None else max(prev, ttl2)
                        except Exception:
                            continue
            for nsname, ns_ttl in ns_ttl_map.items():
                glue_ttl = glue_ttl_map.get(nsname)
                if glue_ttl is None:
                    continue
                if ns_ttl == 0:
                    continue
                if glue_ttl > ns_ttl and (glue_ttl - ns_ttl) >= 30:
                    is_hit = True
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp6_ad_trust_forwarders(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        is_hit = False
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    try:
                        if rec.get('ad') or rec.get('ad_from_upstream') or (rec.get('flags') and 'AD' in rec.get('flags')):
                            if not rec.get('validated') and not rec.get('validated_locally'):
                                is_hit = True
                                break
                    except Exception:
                        continue
                if is_hit:
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp7_cd1_caching_mix(caches):
    hits = []
    for cache in caches:
        if not (getattr(cache, 'res', None) and getattr(cache, 'client_query', None)): continue
        # detect if client query used CD
        cd_flag = False
        try:
            q = cache.client_query
            if hasattr(q, 'flags'):
                try:
                    flags = getattr(q, 'flags')
                    if isinstance(flags, dict):
                        cd_flag = bool(flags.get('cd', False))
                except Exception:
                    pass
            if not cd_flag and hasattr(q, 'cd'):
                cd_flag = bool(getattr(q, 'cd'))
            if not cd_flag and hasattr(q, 'summary'):
                try:
                    if 'CD' in q.summary():
                        cd_flag = True
                except Exception:
                    pass
        except Exception:
            cd_flag = False

        is_hit = False
        if cd_flag:
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        try:
                            if rec.get('inserted_with_cd') or rec.get('client_cd_used'):
                                if not rec.get('validated'):
                                    is_hit = True
                                    break
                        except Exception:
                            continue
                    if is_hit:
                        break
                if is_hit:
                    break
        if not is_hit:
            for domain, record in cache.res.items():
                has_valid = False
                has_unvalid = False
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('validated'):
                            has_valid = True
                        else:
                            has_unvalid = True
                        if has_valid and has_unvalid:
                            is_hit = True
                            break
                    if is_hit:
                        break
                if is_hit:
                    break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp8_do_flag_mixing(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        for domain, record in cache.res.items():
            has_with_dnssec = False
            has_without_dnssec = False
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    try:
                        if rec.get('type') in ('RRSIG','NSEC','NSEC3') or rec.get('rrsig') or rec.get('nsec') or rec.get('dnssec'):
                            has_with_dnssec = True
                        else:
                            if rec.get('do_context') == False or rec.get('do_stripped') or not rec.get('rrsig'):
                                has_without_dnssec = True
                    except Exception:
                        continue
                    if has_with_dnssec and has_without_dnssec:
                        hits.append(cache)
                        break
                if cache in hits:
                    break
            if cache in hits:
                break
    return list(dict.fromkeys(hits))

def filter_cp9_aggressive_nsec(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        nsec_count = 0
        synth_neg_count = 0
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    t = rec.get('type')
                    if t in ('NSEC','NSEC3'):
                        nsec_count += 1
                    if rec.get('synthesized_negative') or rec.get('synthesized'):
                        synth_neg_count += 1
        if nsec_count > 20 or synth_neg_count > 5:
            hits.append(cache)
    return list(dict.fromkeys(hits))

def filter_cp10_nsec3_optout_confusion(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        for domain, record in cache.res.items():
            optout_found = False
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('type') == 'NSEC3' and rec.get('optout'):
                        optout_found = True
                        break
                if optout_found:
                    break
            if optout_found:
                hits.append(cache)
                break
    return list(dict.fromkeys(hits))

def filter_cp11_wildcard_misbinding(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        is_hit = False
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('wildcard_expansion'):
                        cached_at = rec.get('cached_at') or rec.get('cached_owner')
                        if cached_at and cached_at != domain:
                            is_hit = True
                            break
                if is_hit:
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return list(dict.fromkeys(hits))

def filter_cp12_dname_bailiwick_confusion(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        try:
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('type') == 'DNAME':
                            target = rec.get('rdata') or rec.get('target')
                            if not target: 
                                continue
                            for dom2, recs2_wrapper in cache.res.items():
                                for sw2 in ['bind','pdns','unbound','technitium']:
                                    for rec2 in recs2_wrapper.get(sw2) or []:
                                        try:
                                            if rec2.get('type') in ('A','AAAA') and dom2 == target:
                                                if rec2.get('cached_under') and rec2.get('cached_under') != dom2:
                                                    hits.append(cache)
                                                    raise StopIteration
                                        except StopIteration:
                                            break
                                    else:
                                        continue
                                    break
                                else:
                                    continue
                                break
        except StopIteration:
            pass
    return list(dict.fromkeys(hits))

def filter_cp13_parent_child_ns_precedence(caches):
    hits = []
    for cache in caches:
        if not getattr(cache, 'res', None): continue
        is_hit = False
        for domain, record in cache.res.items():
            child_ns_ttls = {}
            parent_ns_ttls = {}
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('type') == 'NS':
                        name = rec.get('rdata') or rec.get('nsdname')
                        ttl = int(rec.get('ttl') or 0)
                        if name:
                            prev = child_ns_ttls.get(name)
                            child_ns_ttls[name] = ttl if prev is None else min(prev, ttl)
            if '.' in domain:
                parent = '.'.join(domain.split('.',1)[1])
            else:
                parent = ''
            if parent and parent in cache.res:
                parent_record = cache.res[parent]
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in parent_record.get(sw) or []:
                        if rec.get('type') == 'NS':
                            name = rec.get('rdata') or rec.get('nsdname')
                            ttl = int(rec.get('ttl') or 0)
                            if name:
                                prev = parent_ns_ttls.get(name)
                                parent_ns_ttls[name] = ttl if prev is None else min(prev, ttl)
            for nsname, child_ttl in child_ns_ttls.items():
                parent_ttl = parent_ns_ttls.get(nsname)
                if parent_ttl is not None and child_ttl > parent_ttl and (child_ttl - parent_ttl) >= 30:
                    is_hit = True
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp14_serve_stale_referral(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        is_hit = False
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('type') in ('NS','A','AAAA') and (rec.get('stale') or rec.get('served_while_stale') or rec.get('stale_used')):
                        is_hit = True
                        break
                if is_hit:
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp15_dns64_synthesis_misuse(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        is_hit = False
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('type') == 'AAAA' and (rec.get('synthesized_by') == 'dns64' or rec.get('dns64') or rec.get('synthesized')):
                        is_hit = True
                        break
                if is_hit:
                    break
            if is_hit:
                break
        if is_hit:
            hits.append(cache)
    return hits

def filter_cp16_svcb_from_additional(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('type') in ('SVCB','HTTPS') and (rec.get('from_additional') or rec.get('additional_origin')):
                        hits.append(cache)
                        break
                if cache in hits:
                    break
            if cache in hits:
                break
    return list(dict.fromkeys(hits))

def filter_cp17_cross_transport_sharing(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        for domain, record in cache.res.items():
            transports_seen = set()
            low_trust_seen = False
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    tr = rec.get('transport') or rec.get('via') or rec.get('upstream_transport')
                    if tr:
                        transports_seen.add(tr)
                        if rec.get('low_trust') or rec.get('untrusted_source') or rec.get('multi_tenant'):
                            low_trust_seen = True
            if len(transports_seen) > 1 and low_trust_seen:
                hits.append(cache)
                break
    return list(dict.fromkeys(hits))

def filter_cp18_nx_vs_nodata_mis_cache(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        for domain, record in cache.res.items():
            negative_nxdomain = False
            positive_types = False
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('negative_type') == 'NXDOMAIN' or rec.get('is_nxdomain'):
                        negative_nxdomain = True
                    if rec.get('type') and rec.get('type') not in ('SOA','RRSIG','NSEC','NSEC3') and not rec.get('is_negative'):
                        positive_types = True
                if negative_nxdomain and positive_types:
                    hits.append(cache)
                    break
            if cache in hits:
                break
    return list(dict.fromkeys(hits))

def filter_cp19_dns_cookie_scope(caches):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache, 'meta', None) or getattr(cache, 'metadata', None) or {}
            server_cookies = meta.get('server_cookies') if isinstance(meta, dict) else None
            if isinstance(server_cookies, dict):
                for cookie, servers in server_cookies.items():
                    if isinstance(servers, (list,tuple)) and len(servers) > 1:
                        hits.append(cache)
                        break
        except Exception:
            pass
    return list(dict.fromkeys(hits))

def filter_cp20_cname_in_glue(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('is_glue') and rec.get('type') == 'CNAME':
                        hits.append(cache)
                        break
                if cache in hits:
                    break
            if cache in hits:
                break
    return list(dict.fromkeys(hits))

def filter_cp21_sticky_lame_delegation(caches):
    hits = []
    for cache in caches:
        if not getattr(cache,'res', None): continue
        for domain, record in cache.res.items():
            for sw in ['bind','pdns','unbound','technitium']:
                for rec in record.get(sw) or []:
                    if rec.get('type') in ('NS','A','AAAA') and (rec.get('dangling') or rec.get('lame') or rec.get('stale_delegation')):
                        hits.append(cache)
                        break
                if cache in hits:
                    break
            if cache in hits:
                break
    return list(dict.fromkeys(hits))

def filter_cp22_mixed_case_cache_key(caches):
    hits = []
    for cache in caches:
        try:
            if not getattr(cache, 'res', None): continue
            keys = list(cache.res.keys())
            lowered = {}
            for k in keys:
                lk = k.lower()
                lowered.setdefault(lk,set()).add(k)
            for lk, originals in lowered.items():
                if len(originals) > 1:
                    hits.append(cache)
                    break
        except Exception:
            continue
    return list(dict.fromkeys(hits))

# -------------------------
# RC8 - RC22 Filters（资源/DoS 启发式）
# -------------------------
def filter_rc8_ecs_cardinality_explosion(caches, threshold=20):
    hits = []
    for cache in caches:
        try:
            if not getattr(cache,'res', None): continue
            for domain, record in cache.res.items():
                ecs_variants = set()
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        ev = rec.get('ecs_subnet') or rec.get('ecs_prefix') or rec.get('ecs')
                        if ev:
                            ecs_variants.add(ev)
                if len(ecs_variants) > threshold:
                    hits.append(cache)
                    break
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc9_cache_hash_collision_storm(caches):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict):
                if meta.get('hash_collision_count', 0) > 100 or meta.get('bucket_overflow', False):
                    hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc10_prefetch_storm(caches, per_cache_threshold=50):
    hits = []
    for cache in caches:
        try:
            if not getattr(cache,'res', None): continue
            prefetched = 0
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('prefetched') or rec.get('prefetch'):
                            prefetched += 1
            if prefetched > per_cache_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc11_tc_fallback_thrash(caches, truncated_threshold=50):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict):
                if meta.get('truncated_count', 0) > truncated_threshold or meta.get('tc_events',0) > truncated_threshold:
                    hits.append(cache)
                    continue
            tc_events = 0
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('tc') or rec.get('truncated'):
                            tc_events += 1
            if tc_events > truncated_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc12_dot_doh_handshake_proliferation(caches, tls_threshold=100):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and (meta.get('tls_open_count',0) > tls_threshold or meta.get('tls_short_lived_connections',0) > tls_threshold):
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc13_negative_proof_hoarding(caches, nsec_threshold=200):
    hits = []
    for cache in caches:
        try:
            nsec_count = 0
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('type') in ('NSEC','NSEC3') or rec.get('is_negative_proof'):
                            nsec_count += 1
            if nsec_count > nsec_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc14_pending_query_dedup_failure(caches, inflight_threshold=10):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and (meta.get('inflight_duplicate_count',0) > inflight_threshold or meta.get('pending_table_mult',0) > 1):
                hits.append(cache)
                continue
            inflight_count = 0
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('inflight'):
                            inflight_count += 1
            if inflight_count > inflight_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc15_cname_dname_chain_explosion(caches, chain_limit=8):
    hits = []
    for cache in caches:
        try:
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        chain_len = rec.get('chain_length') or rec.get('alias_chain_length') or rec.get('dname_chain_length')
                        if chain_len and chain_len > chain_limit:
                            hits.append(cache)
                            raise StopIteration
        except StopIteration:
            continue
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc16_dnssec_validation_amplification(caches, rrsig_threshold=10):
    hits = []
    for cache in caches:
        try:
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('rrsig_count',0) > rrsig_threshold or rec.get('rrset_size',0) > 500:
                            hits.append(cache)
                            break
                    if cache in hits:
                        break
                if cache in hits:
                    break
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc17_edns_buf_oscillation(caches, probe_threshold=10):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and meta.get('edns_probe_count',0) > probe_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc18_tcp_blackhole_retry_inflation(caches, retry_threshold=50):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and meta.get('tcp_retry_count',0) > retry_threshold:
                hits.append(cache)
                continue
            tcp_retries = 0
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('tcp_retried'):
                            tcp_retries += 1
            if tcp_retries > retry_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc19_svcb_alias_chasing_fanout(caches, fetch_threshold=20):
    hits = []
    for cache in caches:
        try:
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('svcb_fetches',0) > fetch_threshold or rec.get('svcb_alias_depth',0) > 5:
                            hits.append(cache)
                            raise StopIteration
        except StopIteration:
            continue
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc20_random_subdomain_bypass_flood(caches, label_threshold=200):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and meta.get('random_subdomain_rate',0) > 100:
                hits.append(cache); continue
            parent_map = defaultdict(set)
            for domain in cache.res.keys():
                parts = domain.rstrip('.').split('.')
                if len(parts) >= 2:
                    parent = '.'.join(parts[1:]) + '.'
                    label = parts[0]
                    parent_map[parent].add(label)
            for parent, labels in parent_map.items():
                if len(labels) > label_threshold:
                    hits.append(cache)
                    break
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc21_cache_eviction_thrash_via_ttls(caches, short_ttl_threshold=10, count_threshold=200):
    hits = []
    for cache in caches:
        try:
            short_count = 0
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        try:
                            ttl = int(rec.get('ttl') or 0)
                            if ttl > 0 and ttl < short_ttl_threshold:
                                if not rec.get('out_of_bailiwick'):
                                    short_count += 1
                        except Exception:
                            continue
            if short_count > count_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_rc22_parent_walk_backtracking_qname_minimization(caches, backtrack_threshold=10):
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and meta.get('minimization_backtracks',0) > backtrack_threshold:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

# -------------------------
# CC2 - CC8 Crash & Corruption Filters（启发式）
# -------------------------
def filter_cc2_compression_pointer_loop(caches):
    """
    CC2: compression-pointer loop/overflow in name decompression
    Heuristic:
      - 检测记录/metadata 中出现 'compression_loop'、'decompression_error'、'compression_pointer' 等标记
      - 或者 name label 长度异常 (>63) / 总名长度 > 255 的记录（解析器可能记录原始 label）
    """
    hits = []
    for cache in caches:
        try:
            flagged = False
            # 检查全局元信息
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict):
                if meta.get('compression_loop') or meta.get('decompression_error') or meta.get('compression_pointer_loop'):
                    hits.append(cache)
                    continue
            # 检查每条记录的解析标记或名称组成
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('compression_loop') or rec.get('name_decompression_error') or rec.get('decompression_error'):
                            flagged = True
                            break
                        name = rec.get('name') or rec.get('owner') or domain
                        try:
                            # 检查单标签长度与总长度启发式（若解析器暴露原始 labels）
                            if isinstance(name, str):
                                labels = name.rstrip('.').split('.')
                                for lab in labels:
                                    if len(lab) > 63:
                                        flagged = True
                                        break
                                if flagged:
                                    break
                                if len(name) > 255:
                                    flagged = True
                                    break
                        except Exception:
                            pass
                    if flagged:
                        break
                if flagged:
                    break
            if flagged:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_cc3_label_rr_length_overflow(caches):
    """
    CC3: Label length and RR length overflows
    Heuristic:
      - 如果记录中存在不合理的 rdlength/label-length / rdata 长度不匹配 / 超过 RFC 上限值，则可疑
    """
    hits = []
    for cache in caches:
        try:
            bad = False
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        rdlen = rec.get('rdlength') or rec.get('rdata_len') or rec.get('rdata_length')
                        rdata = rec.get('rdata')
                        if rdlen is not None:
                            try:
                                rdlen_v = int(rdlen)
                                # RFC: RDLENGTH is 16-bit unsigned -> max 65535, label max 63, total name <=255
                                if rdlen_v < 0 or rdlen_v > 65535:
                                    bad = True; break
                                if isinstance(rdata, (bytes, bytearray)) and len(rdata) != rdlen_v:
                                    bad = True; break
                                if isinstance(rdata, str):
                                    # utf length heuristic
                                    if len(rdata.encode('utf-8')) != rdlen_v and abs(len(rdata.encode('utf-8'))-rdlen_v) > 16:
                                        bad = True; break
                            except Exception:
                                continue
                        # check name labels if exposed
                        name = rec.get('name') or rec.get('owner') or domain
                        if isinstance(name, str):
                            try:
                                for lab in name.rstrip('.').split('.'):
                                    if len(lab) > 63:
                                        bad = True; break
                                if bad:
                                    break
                                if len(name) > 255:
                                    bad = True; break
                            except Exception:
                                pass
                    if bad:
                        break
                if bad:
                    break
            if bad:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_cc4_malformed_opt_edns_parsing(caches):
    """
    CC4: Malformed OPT/EDNS option parsing
    Heuristic:
      - 检测 rec/meta 中的 'edns_malformed', 'opt_parsing_error', 'edns_option_length_error'
    """
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and (meta.get('edns_malformed') or meta.get('opt_parsing_error') or meta.get('edns_option_length_error')):
                hits.append(cache)
                continue
            flagged = False
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('edns_malformed') or rec.get('opt_parsing_error') or rec.get('edns_option_length_error'):
                            flagged = True
                            break
                    if flagged:
                        break
                if flagged:
                    break
            if flagged:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_cc5_rrsig_ds_key_parser_issues(caches):
    """
    CC5: RRSIG/DS/KEY parser edge cases
    Heuristic:
      - 检测 rrsig/DS/KEY 解析错误标记（'rrsig_parse_error','ds_parse_error','key_parse_error','unsupported_algo'）
      - 或者存在不合理的 signer name 长度/算法标记
    """
    hits = []
    for cache in caches:
        try:
            flagged = False
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('rrsig_parse_error') or rec.get('ds_parse_error') or rec.get('key_parse_error') or rec.get('unsupported_algo'):
                            flagged = True
                            break
                        if rec.get('type') in ('RRSIG','DS','DNSKEY'):
                            # check for unreasonable fields
                            if rec.get('algorithm') and (rec.get('algorithm') < 0 or rec.get('algorithm') > 255):
                                flagged = True; break
                            signer = rec.get('signer') or rec.get('signer_name')
                            if isinstance(signer, str) and len(signer) > 300:
                                flagged = True; break
                    if flagged:
                        break
                if flagged:
                    break
            if flagged:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_cc6_svcb_https_param_parsing_bugs(caches):
    """
    CC6: SVCB/HTTPS parameter parsing bugs
    Heuristic:
      - 检测 'svc_param_error'、'svc_param_too_long'、'svc_duplicate_key' 等标记
      - 或者某条 SVCB record 的参数长度异常
    """
    hits = []
    for cache in caches:
        try:
            flagged = False
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('type') in ('SVCB','HTTPS'):
                            if rec.get('svc_param_error') or rec.get('svc_param_too_long') or rec.get('svc_duplicate_key') or rec.get('svc_param_parsing_failed'):
                                flagged = True; break
                            params = rec.get('svc_params') or rec.get('params')
                            if isinstance(params, dict):
                                for k, v in params.items():
                                    try:
                                        if hasattr(v, '__len__') and len(v) > 10000:
                                            flagged = True; break
                                    except Exception:
                                        continue
                                if flagged:
                                    break
                    if flagged:
                        break
                if flagged:
                    break
            if flagged:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_cc7_fragment_reassembly_inconsistencies(caches):
    """
    CC7: Fragment reassembly inconsistencies
    Heuristic:
      - 检测元数据 'fragment_reassembly_error', 'overlap_fragment', 'fragment_mismatch'
    """
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and (meta.get('fragment_reassembly_error') or meta.get('overlap_fragment') or meta.get('fragment_mismatch')):
                hits.append(cache)
                continue
            flagged = False
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('fragment_reassembly_error') or rec.get('overlap_fragment') or rec.get('fragment_mismatch'):
                            flagged = True
                            break
                    if flagged:
                        break
                if flagged:
                    break
            if flagged:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

def filter_cc8_concurrent_cache_mutation_races(caches):
    """
    CC8: Concurrent cache mutation races
    Heuristic:
      - 检测 meta 中 'concurrent_mutation', 'race_detected', 'use_after_free', 'corruption' 等标记
    """
    hits = []
    for cache in caches:
        try:
            meta = getattr(cache,'meta', None) or getattr(cache,'metadata', None) or {}
            if isinstance(meta, dict) and (meta.get('concurrent_mutation') or meta.get('race_detected') or meta.get('use_after_free') or meta.get('corruption')):
                hits.append(cache)
                continue
            flagged = False
            for domain, record in cache.res.items():
                for sw in ['bind','pdns','unbound','technitium']:
                    for rec in record.get(sw) or []:
                        if rec.get('corruption') or rec.get('race_detected') or rec.get('use_after_free'):
                            flagged = True
                            break
                    if flagged:
                        break
                if flagged:
                    break
            if flagged:
                hits.append(cache)
        except Exception:
            continue
    return list(dict.fromkeys(hits))

# -------------------------
# 主分析逻辑（保持你最初版本的用法）
# -------------------------
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
        try:
            combination_key = ",".join(sorted(case.active_caches))
        except Exception:
            try:
                comb = []
                if getattr(case, 'res', None):
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
        # original / basic
        "CP1: Suspicious Caching (BIND/Technitium)": filter_cp1,
        "CP2: Subdomain NS Record Caching (PowerDNS)": filter_cp2,
        "CP4: Subdomain NS Record Caching (All resolvers)": filter_cp4,
        "R1: Direct Match Caching": filter_r1,
        "R2: Fallback Behavior (Cloudflare NS)": filter_r2,
        "R3: NSEC3 Record Caching": filter_r3,
        "R4: NSEC Record Caching": filter_r4,
        "R5: Any NSEC/NSEC3 Record Caching": filter_r5,
        "R6: Cached Different Type Than Query": filter_r6,
        "R7: Revalidation (cloudflare.com.)": filter_r7,
        # CP5-CP22
        "CP5: Glue TTL Overreach": filter_cp5_glue_ttl_overreach,
        "CP6: AD-bit Trust Propagation (Forwarders)": filter_cp6_ad_trust_forwarders,
        "CP7: CD=1 Caching Pollution": filter_cp7_cd1_caching_mix,
        "CP8: DO=0/DO=1 Answer Mixing": filter_cp8_do_flag_mixing,
        "CP9: Aggressive NSEC Caching Overreach": filter_cp9_aggressive_nsec,
        "CP10: NSEC3 Opt-Out Confusion": filter_cp10_nsec3_optout_confusion,
        "CP11: Wildcard Synthesis Mis-binding": filter_cp11_wildcard_misbinding,
        "CP12: DNAME Rewriting Bailiwick Confusion": filter_cp12_dname_bailiwick_confusion,
        "CP13: Parent vs Child NS Precedence Errors": filter_cp13_parent_child_ns_precedence,
        "CP14: Serve-Stale Referral Pinning": filter_cp14_serve_stale_referral,
        "CP15: DNS64 Synthesis Cache Misuse": filter_cp15_dns64_synthesis_misuse,
        "CP16: SVCB/HTTPS Mis-caching from Additional": filter_cp16_svcb_from_additional,
        "CP17: Cross-transport Cache Sharing": filter_cp17_cross_transport_sharing,
        "CP18: NXDOMAIN vs NODATA Mis-caching": filter_cp18_nx_vs_nodata_mis_cache,
        "CP19: DNS Cookie Scope Confusion": filter_cp19_dns_cookie_scope,
        "CP20: CNAME-in-Glue Acceptance": filter_cp20_cname_in_glue,
        "CP21: Sticky Lame/Dangling Delegation Cache": filter_cp21_sticky_lame_delegation,
        "CP22: Mixed-case (0x20) Cache Key Error": filter_cp22_mixed_case_cache_key,
        # RC8-RC22
        "RC8: ECS Cardinality Explosion": filter_rc8_ecs_cardinality_explosion,
        "RC9: Cache Hash-bucket Collision Storm": filter_rc9_cache_hash_collision_storm,
        "RC10: Prefetch Storm": filter_rc10_prefetch_storm,
        "RC11: TC=1 Fallback Thrash": filter_rc11_tc_fallback_thrash,
        "RC12: DoT/DoH Handshake Proliferation": filter_rc12_dot_doh_handshake_proliferation,
        "RC13: Negative Proof Hoarding": filter_rc13_negative_proof_hoarding,
        "RC14: Pending-query Deduplication Failure": filter_rc14_pending_query_dedup_failure,
        "RC15: CNAME/DNAME Chain Explosion": filter_rc15_cname_dname_chain_explosion,
        "RC16: DNSSEC Validation Workload Amplification": filter_rc16_dnssec_validation_amplification,
        "RC17: EDNS Buffer-size Oscillation": filter_rc17_edns_buf_oscillation,
        "RC18: TCP Blackhole Retry Inflation": filter_rc18_tcp_blackhole_retry_inflation,
        "RC19: SVCB/HTTPS Alias-chasing Fan-out": filter_rc19_svcb_alias_chasing_fanout,
        "RC20: Random-subdomain Cache-bypass Flood": filter_rc20_random_subdomain_bypass_flood,
        "RC21: Cache Eviction Thrash via Attacker-chosen TTLs": filter_rc21_cache_eviction_thrash_via_ttls,
        "RC22: Parent-walk Backtracking with QNAME-minimization": filter_rc22_parent_walk_backtracking_qname_minimization,
        # CC2-CC8 (crash/corruption)
        "CC2: Compression-pointer Loop/Overflow": filter_cc2_compression_pointer_loop,
        "CC3: Label / RR-length Overflows": filter_cc3_label_rr_length_overflow,
        "CC4: Malformed OPT/EDNS Option Parsing": filter_cc4_malformed_opt_edns_parsing,
        "CC5: RRSIG/DS/KEY Parser Edge Cases": filter_cc5_rrsig_ds_key_parser_issues,
        "CC6: SVCB/HTTPS Parameter Parsing Bugs": filter_cc6_svcb_https_param_parsing_bugs,
        "CC7: Fragment Reassembly Inconsistencies": filter_cc7_fragment_reassembly_inconsistencies,
        "CC8: Concurrent Cache Mutation Races": filter_cc8_concurrent_cache_mutation_races
    }

    filter_hits = {}
    result_dir = os.path.join(os.getcwd(), "cache_insight_analysis_result")
    os.makedirs(result_dir, exist_ok=True)

    import json
    from datetime import datetime

    try:
        count_info, total_cases = collect_info(diff_cases)
    except Exception:
        count_info, total_cases = None, len(diff_cases)

    for name, func in all_filters.items():
        try:
            hits = func(diff_cases)
        except Exception:
            hits = []
        indices = []
        for hit_case in hits:
            try:
                case_directory = os.path.dirname(os.path.dirname(hit_case.bind_path))
                rel_index = os.path.relpath(case_directory, args.res_folder)
                indices.append(rel_index.replace(os.sep, '/'))
            except Exception:
                try:
                    base = getattr(hit_case, 'directory', None) or getattr(hit_case, 'base_dir', None) or getattr(hit_case, 'path', None)
                    if base:
                        rel_index = os.path.relpath(base, args.res_folder)
                        indices.append(rel_index.replace(os.sep, '/'))
                except Exception:
                    continue
        
        filter_hits[name] = {
            "count": len(hits),
            "indices": indices
        }

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
            pass

    print(f"[*] Phase 3/3: Complete. Results saved to folder: {result_dir}")

    # --- 4. 打印最终总结（与最初版本保持一致的输出风格） ---
    print("\n\n" + "="*25 + " Cache Insight Summary " + "="*25)
    print(f"[*] Total test indices processed: {total_indices_processed}")
    print(f"[*] Total indices with cache differences: {len(diff_cases)}")

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
    print(f"{'Filter Name':<70} | {'Hits':<10}")
    print("-" * 83)
    sorted_filter_hits = sorted(filter_hits.items(), key=lambda item: item[1]['count'], reverse=True)
    for name, result in sorted_filter_hits:
        print(f"{name:<70} | {result['count']:<10}")

    if args.verbose:
        print("\n\n" + "="*25 + " Verbose Filter Hit Details " + "="*25)
        for name, result in sorted_filter_hits:
            if result['count'] > 0:
                print(f"\n--- Hits for filter: [{name}] ({result['count']} total) ---")
                for idx in result["indices"]:
                    print(f"  - {idx}")
    
if __name__ == "__main__":
    main()
