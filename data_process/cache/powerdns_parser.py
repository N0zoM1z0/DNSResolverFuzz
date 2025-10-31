# powerdns_parser.py (Robust Version)
import os

def parse_rrset(record_str, positive_record=False):
    try:
        rr_str = record_str.split(' ; ')
        if not rr_str: return None, None

        record = rr_str[0].split(' ', 5)
        if len(record) < 6: return None, None # Guard against short records

        rrset = {
            'name': record[0],
            'ttl': record[1],
            'current_ttl': record[2],
            'class': record[3],
            'type': record[4],
            'rdata': record[5],
            'rr_type': 'negative_record'
        }
        
        if positive_record:
            rrset['rr_type'] = 'positive_record'
            if len(rr_str) > 1:
                record_meta = rr_str[1].split(' ')
                if len(record_meta) >= 4:
                    rrset['source_type'] = record_meta[0]
                    rrset['auth'] = record_meta[1].split('=')[1]
                    rrset['zone'] = record_meta[2].split('=')[1]
                    rrset['from'] = record_meta[3].split('=')[1]
        return rrset['name'], rrset
    except (IndexError, ValueError):
        return None, None

def parse_packet(packet_str):
    try:
        packet = packet_str.split(' ; ')
        if len(packet) < 2: return None, None

        record = packet[0].split(' ')
        if len(record) < 4: return None, None
        
        rrset = {
            'name': record[0],
            'ttl': record[1],
            'type': record[2],
            'rdata': record[3]
        }
        
        record_meta = packet[1].split(' ')
        if len(record_meta) < 3: return None, None

        rrset['rr_type'] = record_meta[0]
        rrset['val1'] = record_meta[1]
        rrset['val2'] = record_meta[2]
        return rrset['name'], rrset
    except (IndexError, ValueError):
        return None, None

class PdnsCache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        if os.path.exists(self.cache_file) and os.path.getsize(self.cache_file) > 0:
            try:
                self.cache_data = self.parse_cache()
            except Exception as e:
                print(f"[!] PdnsParser failed for {cache_file}: {e}")
                self.cache_data = {}

    def parse_cache(self):
        cache = {}
        status = None
        with open(self.cache_file, 'r', errors='ignore') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip('\n')
                if not line or line.startswith(';'):
                    if line == '; main record cache dump follows': status = 'positive_record'
                    elif line == '; negcache dump follows': status = 'negative_record'
                    elif line == '; main packet cache dump from thread follows': status = 'packet_cache'
                    continue

                if status == 'positive_record':
                    name, rrset = parse_rrset(line, positive_record=True)
                elif status == 'negative_record':
                    name, rrset = parse_rrset(line, positive_record=False)
                elif status == 'packet_cache':
                    name, rrset = parse_packet(line)
                else:
                    continue
                
                if name and rrset:
                    cache.setdefault(name, []).append(rrset)

        return cache