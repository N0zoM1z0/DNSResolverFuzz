# cache_analyzer.py (Final version with targeted main() function update)

import os
import argparse
from scapy.layers.dns import DNS

from bind9_parser import Bind9Cache
from powerdns_parser import PdnsCache
from unbound_parser import UnboundCache
from technitium_parser import TechCache

# --- 脚本上半部分，完全保持您提供的版本，不做任何改动 ---

ignore_domains = {'powerdns.com.', 'pdns-public-ns1.powerdns.com.',
                  'recursor-4.7.0.security-status.secpoll.powerdns.com.', 'pdns-public-ns2.powerdns.com.',
                  'secpoll.powerdns.com.', '0.security-status.secpoll.powerdns.com.',
                  '7.0.security-status.secpoll.powerdns.com.', 'security-status.secpoll.powerdns.com.', 'com.', 'net.',
                  'm.root-servers.net.', 'e.root-servers.net.', 'b.root-servers.net.', 'k.gtld-servers.net.',
                  'e.gtld-servers.net.', 'h.root-servers.net.', 'f.root-servers.net.', 'd.gtld-servers.net.',
                  'i.gtld-servers.net.', 'c.gtld-servers.net.', 'k.root-servers.net.', 'j.gtld-servers.net.',
                  'l.root-servers.net.', 'a.root-servers.net.', 'b.gtld-servers.net.', 'g.root-servers.net.',
                  'a.gtld-servers.net.', 'h.gtld-servers.net.', 'd.root-servers.net.', 'g.gtld-servers.net.',
                  'c.root-servers.net.', 'j.root-servers.net.', 'm.gtld-servers.net.', 'f.gtld-servers.net.',
                  'l.gtld-servers.net.', 'i.root-servers.net.', '.'}

ignore_domains_mode_specific = {}
ignore_types = {}
resolver_list = {1: "bind", 2: "unbound", 3: "pdns", 4: "tech", "bind": 1, "unbound": 2, "pdns": 3, "tech": 4}

def compare(bind, unbound, pdns, tech, target):
    matrics = {}
    flag = 1
    for li in [bind, unbound, pdns, tech]:
        if li:
            for i in li:
                if i['type'] not in ignore_types:
                    if (i['type'], i['rdata']) not in matrics:
                        matrics[i['type'], i['rdata']] = flag
                    else:
                        matrics[i['type'], i['rdata']] += flag
        flag += 1
    for key, val in matrics.items():
        if val != target:
            return {"bind": bind, "unbound": unbound, "pdns": pdns, 'technitium': tech}
    return {}

def decode_query(filepath: str):
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'r') as f:
        res = f.read()
    try:
        query_packet = DNS(bytes.fromhex(res))
        return query_packet
    except Exception as e:
        print(f"Error decoding query file {filepath}: {e}")
        return None

def get_domain_list(target, domain_list, cache, path, sw_key, sw_name, debug):
    if cache:
        target += resolver_list[sw_key]
        domain_list.extend(list(cache.keys()))
    else:
        if debug:
            if not os.path.exists(path):
                 print(f"Info: {sw_name} cache dump missing, path not found: {path}")
            else:
                 print(f"Info: {sw_name} cache dump is empty: {path}")
    return target, domain_list

class CacheAnalyzer:
    def __init__(self, directory=None, index=None, bind_path=None, unbound_path=None, pdns_path=None, tech_path=None,
                 client_query_path=None, debug=False):
        self.debug=debug
        self.res = None
        self.mode = None
        self.count = {'bind9': 0, 'powerdns': 0, 'unbound': 0, 'technitium': 0}
        self.compared_domains = []
        self.active_caches = []
        if directory and index is not None:
            if directory[-1] != "/":
                directory += "/"
            base_path = directory + str(index) + "/"
            self.bind_path = base_path + "bind9/named_dump.db"
            self.unbound_path = base_path + "unbound/unbound.cache.db"
            self.pdns_path = base_path + "powerdns/powerdns.cache.db"
            self.tech_path = base_path + "technitium/cache.json"
            self.client_query_path = base_path + "query.txt"
        elif bind_path and unbound_path and pdns_path and tech_path and client_query_path:
            self.bind_path = bind_path
            self.unbound_path = unbound_path
            self.pdns_path = pdns_path
            self.tech_path = tech_path
            self.client_query_path = client_query_path
        else:
            raise RuntimeError("Parameters missing...")
        self.client_query = decode_query(self.client_query_path)
        self.bind_cache = Bind9Cache(self.bind_path)
        self.pdns_cache = PdnsCache(self.pdns_path)
        self.unbound_cache = UnboundCache(self.unbound_path)
        self.tech_cache = TechCache(self.tech_path)
        self.get_difference()
        self.calc_count()
    
    def set_bind_path(self, bind_path):
        self.bind_path = bind_path
        self.bind_cache = Bind9Cache(self.bind_path)
    def set_pdns_path(self, pdns_path):
        self.pdns_path = pdns_path
        self.pdns_cache = PdnsCache(self.pdns_path)
    def set_unbound_path(self, unbound_path):
        self.unbound_path = unbound_path
        self.unbound_cache = UnboundCache(self.unbound_path)
    def set_tech_path(self, tech_path):
        self.tech_path = tech_path
        self.tech_cache = TechCache(self.tech_path)

    def get_difference(self):
        bind_cache = self.bind_cache.cache_data
        unbound_cache = self.unbound_cache.cache_data
        pdns_cache = self.pdns_cache.cache_data
        tech_cache = self.tech_cache.cache_data
        if bind_cache: self.active_caches.append("Bind9")
        if unbound_cache: self.active_caches.append("Unbound")
        if pdns_cache: self.active_caches.append("PowerDNS")
        if tech_cache: self.active_caches.append("Technitium")
        if not self.active_caches:
            if self.debug:
                print("Info: All resolver caches are empty or missing. No analysis performed.")
            self.res = {} 
            return
        if self.client_query and self.client_query.qd:
            try:
                tmp = self.client_query.qd.qname.decode("utf-8")
                if "-fwd-fallback.qifanzhang.com." in tmp: self.mode = "forward_fallback"
                elif "-fwd-global.qifanzhang.com." in tmp: self.mode = "forward_global"
                elif "-recursive.qifanzhang.com." in tmp: self.mode = "recursive"
                elif ".qifanzhang.com." in tmp: self.mode = "forward_only"
                else: self.mode = "alexa_domain"
            except (AttributeError, IndexError):
                self.mode = "unknown_query"
        target = 0
        domain_list = []
        target, domain_list = get_domain_list(target, domain_list, bind_cache, self.bind_path, 'bind', 'Bind9', self.debug)
        target, domain_list = get_domain_list(target, domain_list, unbound_cache, self.unbound_path, 'unbound', 'Unbound', self.debug)
        target, domain_list = get_domain_list(target, domain_list, pdns_cache, self.pdns_path, 'pdns', 'PowerDNS', self.debug)
        target, domain_list = get_domain_list(target, domain_list, tech_cache, self.tech_path, 'tech', 'Technitium', self.debug)
        domain_list = list(set(domain_list))
        self.compared_domains = domain_list
        res = {}
        ignore_list = ignore_domains.union(ignore_domains_mode_specific.get(self.mode, {}))
        for domain in domain_list:
            if domain not in ignore_list:
                is_in_bind = domain in bind_cache if bind_cache else False
                is_in_unbound = domain in unbound_cache if unbound_cache else False
                is_in_pdns = domain in pdns_cache if pdns_cache else False
                is_in_tech = domain in tech_cache if tech_cache else False
                active_caches_contain_domain = [
                    is_in_bind if bind_cache else True,
                    is_in_unbound if unbound_cache else True,
                    is_in_pdns if pdns_cache else True,
                    is_in_tech if tech_cache else True
                ]
                if not all(active_caches_contain_domain):
                    res[domain] = {
                        "bind": bind_cache.get(domain) if bind_cache else None,
                        "unbound": unbound_cache.get(domain) if unbound_cache else None,
                        "pdns": pdns_cache.get(domain) if pdns_cache else None,
                        "technitium": tech_cache.get(domain) if tech_cache else None
                    }
                else:
                    tmp = compare(bind_cache.get(domain), unbound_cache.get(domain), pdns_cache.get(domain), tech_cache.get(domain), target)
                    if tmp:
                        res[domain] = tmp
        self.res = res

    def set_count(self):
        self.count = {'bind9': 0, 'powerdns': 0, 'unbound': 0, 'technitium': 0}
        if self.res is not None:
            for domain in self.res:
                record = self.res[domain]
                if record['bind']: self.count['bind9'] += 1
                if record['unbound']: self.count['unbound'] += 1
                if record['pdns']: self.count['powerdns'] += 1
                if record['technitium']: self.count['technitium'] += 1
    def get_count(self):
        return [self.count['bind9'], self.count['unbound'], self.count['powerdns'], self.count['technitium']]
    def calc_count(self):
        self.set_count()
        return self.get_count()

# --- main 函数被修改以补全 verbose 输出 ---

def main():
    """
    主执行函数
    """
    parser = argparse.ArgumentParser(description="Analyze and compare DNS resolver cache dumps.")
    parser.add_argument('--res_folder', type=str, required=True, help="Path to the results folder containing indexed subdirectories.")
    parser.add_argument('--verbose', '-v', action='store_true', help="Enable verbose output for debugging.")
    args = parser.parse_args()

    print(f"[*] Starting cache analysis in folder: {args.res_folder}")

    if not os.path.isdir(args.res_folder):
        print(f"[!] Error: Provided path is not a valid directory: {args.res_folder}")
        return

    total_dirs_processed = 0
    total_dirs_with_diffs = 0

    top_level_dirs = sorted([d.name for d in os.scandir(args.res_folder) if d.is_dir() and d.name.isdigit()])

    for top_dir in top_level_dirs:
        top_dir_path = os.path.join(args.res_folder, top_dir)
        print(f"\n--- Processing Super-Index: {top_dir} ---")
        
        sub_level_dirs = sorted([d.name for d in os.scandir(top_dir_path) if d.is_dir() and d.name.isdigit()])

        for sub_dir in sub_level_dirs:
            total_dirs_processed += 1
            print(f"  --- Analyzing Index: {top_dir}/{sub_dir} ---")
            try:
                analyzer = CacheAnalyzer(directory=top_dir_path, index=sub_dir, debug=args.verbose)
                
                if analyzer.res is None:
                    print("  -> Result: Analysis could not be completed.")
                elif not analyzer.res:
                    num_domains = len([d for d in analyzer.compared_domains if d not in ignore_domains])
                    active_caches_str = ", ".join(analyzer.active_caches) if analyzer.active_caches else "None"
                    print(f"  -> Result: No differences found. Compared {num_domains} domains across: [{active_caches_str}].")
                else:
                    total_dirs_with_diffs += 1
                    print(f"  -> Result: Found differences in {len(analyzer.res)} domain(s).")
                    
                    # +++ 这是我们新加入的、用于显示详细差异的核心逻辑 +++
                    if args.verbose:
                        print("    --- CACHE DIFFERENCE DETAILS ---")
                        # 遍历所有有差异的域名
                        for domain, data in analyzer.res.items():
                            print(f"    - Domain: {domain}")
                            # 打印每个解析器关于这个域名的缓存内容
                            for resolver_name in ['bind', 'unbound', 'pdns', 'technitium']:
                                resolver_records = data.get(resolver_name)
                                
                                # 检查是否有缓存记录
                                if resolver_records is not None:
                                    print(f"      - {resolver_name.capitalize()}:")
                                    # 为了美观，逐条打印记录
                                    for record in resolver_records:
                                        print(f"        - {record}")
                                else:
                                    # 明确指出哪个解析器的缓存中没有这个域名
                                    print(f"      - {resolver_name.capitalize()}: Not in cache")
                        print("    ----------------------------------")
            
            except Exception as e:
                import traceback
                print(f"  [!] An unexpected error occurred while processing index {top_dir}/{sub_dir}: {e}")
                if args.verbose:
                    traceback.print_exc()

    print("\n--- Analysis Complete ---")
    print(f"[*] Total directories processed: {total_dirs_processed}")
    print(f"[*] Total directories with cache differences: {total_dirs_with_diffs}")

if __name__ == "__main__":
    main()