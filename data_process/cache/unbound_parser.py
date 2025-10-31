# unbound_parser.py (Robust Version)
import os

def parse_rrset(rrset_str):
    try:
        if rrset_str.startswith(';'):
            target = {'res_type': 'rrset', 'records': []}
            rrset = rrset_str.split(' ')
            if len(rrset) < 6: return target # Return partially parsed if malformed
            target['ttl'] = rrset[1]
            target['rr_count'] = rrset[2]
            target['rrsig_count'] = rrset[3]
            target['trust'] = rrset[4]
            target['security'] = rrset[5]
            return target
        else:
            rrset = rrset_str.split('\t')
            if len(rrset) >= 5:
                return {'name': rrset[0], 'ttl': rrset[1], 'class': rrset[2], 'type': rrset[3], 'rdata': rrset[4]}
        return None
    except (IndexError, ValueError):
        return None

def parse_msg(msg_str):
    try:
        if msg_str.startswith('msg'):
            msg = {'res_type': 'msg', 'records': []}
            msgset = msg_str.split(' ')
            if len(msgset) < 11: return msg
            msg.update({
                'name': msgset[1], 'class': msgset[2], 'type': msgset[3],
                'flags': msgset[4], 'qdcount': msgset[5], 'ttl': msgset[6],
                'security': msgset[7], 'an': msgset[8], 'ns': msgset[9], 'ar': msgset[10]
            })
            return msg
        else:
            msgset = msg_str.split(' ')
            if len(msgset) < 4: return None
            return {'name': msgset[0], 'class': msgset[1], 'type': msgset[2], 'flags': msgset[3]}
    except (IndexError, ValueError):
        return None

def convert_cache(cache):
    res = {}
    for i in cache:
        if not isinstance(i, dict) or not i.get('records'): continue
        
        name = i['records'][0].get('name')
        if not name: continue
        
        tmp = []
        for record in i['records']:
             if isinstance(record, dict):
                base_info = {k: v for k, v in i.items() if k != 'records'}
                record.update(base_info)
                tmp.append(record)

        res.setdefault(name, []).extend(tmp)
    return res

class UnboundCache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache_data = None
        self.cache_msg = None
        if os.path.exists(self.cache_file) and os.path.getsize(self.cache_file) > 0:
            try:
                self.cache_data, self.cache_msg = self.parse_cache()
            except Exception as e:
                print(f"[!] UnboundParser failed for {cache_file}: {e}")
                self.cache_data = {}
                self.cache_msg = []

    def parse_cache(self):
        cache = []
        msg = []
        status = None
        with open(self.cache_file, 'r', errors='ignore') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip('\n')
                if not line: continue

                if line == 'START_RRSET_CACHE': status = 'RRSET_CACHE'
                elif line == 'START_MSG_CACHE': status = 'MSG_CACHE'
                elif line in ['END_RRSET_CACHE', 'END_MSG_CACHE']: status = None
                elif line == 'EOF': break
                elif status == 'RRSET_CACHE':
                    if line.startswith(';'):
                        parsed = parse_rrset(line)
                        if parsed: cache.append(parsed)
                    else:
                        if cache:
                            tmp = parse_rrset(line)
                            if tmp: cache[-1].setdefault('records', []).append(tmp)
                elif status == 'MSG_CACHE':
                    if line.startswith('msg'):
                        parsed = parse_msg(line)
                        if parsed: msg.append(parsed)
                    else:
                        if msg:
                            parsed = parse_msg(line)
                            if parsed: msg[-1].setdefault('records', []).append(parsed)
        return convert_cache(cache), msg