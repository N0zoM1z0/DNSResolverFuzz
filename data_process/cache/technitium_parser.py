# technitium_parser.py (Robust Version)
import json
import os

class TechCache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        if os.path.exists(self.cache_file) and os.path.getsize(self.cache_file) > 2: # Check for more than empty {}
            try:
                self.cache_data = self.parse_cache()
            except Exception as e:
                print(f"[!] TechParser failed for {cache_file}: {e}")
                self.cache_data = {}

    def parse_cache(self):
        try:
            with open(self.cache_file, 'r', errors='ignore') as json_file:
                cache = json.load(json_file)
        except json.JSONDecodeError:
            return {} # Return empty if JSON is invalid

        if not isinstance(cache, dict):
            return {} # Expecting a dictionary

        new_cache = {}
        for label, records in cache.items():
            tmp = []
            if not isinstance(records, list): continue

            for record in records:
                if not isinstance(record, dict) or 'rData' not in record: continue
                
                is_valid = True
                rdata = record.get('rData', {})
                if isinstance(rdata, dict) and rdata.get('dataType') == 'DnsSpecialCacheRecordData':
                    is_valid = False
                
                else:
                    rec_type = record.get('type')
                    if rec_type == 'NS': record['rdata'] = rdata.get('nameServer')
                    elif rec_type == 'A': record['rdata'] = rdata.get('ipAddress')
                    elif rec_type == 'CNAME': record['rdata'] = rdata.get('cname')
                    elif rec_type == 'PTR': record['rdata'] = rdata.get('ptrName')
                    elif rec_type == 'MX': record['rdata'] = rdata.get('exchange')
                    elif rec_type == 'SOA': record['rdata'] = rdata.get('primaryNameServer')
                    elif rec_type == 'TXT': record['rdata'] = rdata.get('text')
                    elif rec_type == 'AAAA': record['rdata'] = rdata.get('ipAddress')
                    elif rec_type == 'RRSIG': record['rdata'] = rdata.get('signersName')
                    else:
                        is_valid = False # Skip unknown types for safety

                if is_valid and 'rdata' in record and record['rdata'] is not None:
                    tmp.append(record)
            
            if tmp:
                new_cache[label + "."] = tmp
        return new_cache