# bind9_parser.py (Robust Version)
import os

def parse_soa(record_str):
    try:
        tmp = record_str.split(" ", 3)
        if len(tmp) < 4: return None, None # Add guard
        rrset = {'name': tmp[1], 'type': tmp[2], 'rdata': tmp[3]}
        return rrset['name'], rrset
    except (IndexError, ValueError):
        return None, None

def parse_rrset(record_str, domain_name, source_type, view):
    try:
        rrset = {'source_type': source_type, 'view': view}
        record = record_str.split('\t')
        if len(record) < 3:
            record = record_str.split(' ')
        
        # Add guard for insufficient parts
        if len(record) < 5: return None, None

        if domain_name:
            rrset['name'] = domain_name
        else:
            rrset['name'] = record[0]
            
        if record[-2][:3] == 'IN ':
            rrset['type'] = record[-2][3:]
            rrset['ttl'] = record[-3]
        else:
            rrset['type'] = record[-2]
            if record[-3] == 'IN':
                rrset['ttl'] = record[-4]
            else:
                rrset['ttl'] = record[-3]
        rrset['rdata'] = record[-1]
        return rrset['name'], rrset
    except (IndexError, ValueError):
        return None, None

class Bind9Cache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        self.config = None # Ensure config is initialized
        if os.path.exists(self.cache_file) and os.path.getsize(self.cache_file) > 0:
            try:
                self.cache_data, self.config = self.parse_cache()
            except Exception as e:
                print(f"[!] Bind9Parser failed for {cache_file}: {e}")
                self.cache_data = {}
                self.config = {}

    def parse_cache(self):
        cache = {}
        view = "default" # Assume a default view
        status = None
        source_type = None
        config = {}
        domain = ""
        with open(self.cache_file, 'r', errors='ignore') as f: # Ignore decoding errors
            lines = f.readlines()
            for line in lines:
                try:
                    line = line.strip('\n')
                    if not line or line == ';':
                        continue

                    if line[:12] == '; Start view':
                        view = line[13:]
                        config[view] = {}
                    elif line[:12] == '; Cache dump': status = 'cache'
                    elif line[:23] == '; Address database dump': status = 'address'
                    elif line[:22] == '; Unassociated entries': status = 'unassociated'
                    elif line[:11] == '; Bad cache': status = 'bad_cache'
                    elif line[:16] == '; SERVFAIL cache': status = 'servfail_cache'
                    elif line[:15] == '; Dump complete': break
                    elif line.startswith('; using a'):
                        tmp = line.split()
                        if len(tmp) > 3 and view in config: config[view]['stale_ttl'] = tmp[3]
                    elif line.startswith('$DATE'):
                        tmp = line.split()
                        if len(tmp) > 1 and view in config: config[view]['date'] = tmp[1]
                    elif line.startswith(';'):
                        tmp = line.split(' ', 3)
                        if len(tmp) < 2: continue
                        if len(tmp) < 3:
                            source_type = tmp[1]
                        else:
                            if status == 'cache':
                                name, soa = parse_soa(line)
                                if name and soa:
                                    cache.setdefault(name, []).append(soa)
                    elif status == 'cache':
                        if line.startswith('\t\t\t\t\t'):
                            if domain and domain in cache and cache[domain]:
                                cache[domain][-1]['rdata'] += line[5:]
                        else:
                            if line.startswith('\t'):
                                name, rrset = parse_rrset(line, domain_name=domain, source_type=source_type, view=view)
                            else:
                                name, rrset = parse_rrset(line, domain_name=None, source_type=source_type, view=view)
                                if name: domain = name
                            
                            if name and rrset:
                                cache.setdefault(name, []).append(rrset)
                except (IndexError, ValueError) as e:
                    # print(f"Skipping malformed line in BIND cache: {line} -> Error: {e}")
                    continue
        return cache, config