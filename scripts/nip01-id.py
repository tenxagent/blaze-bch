# Independent NIP-01 id: sha256 of json.dumps([0,pubkey,created_at,kind,tags,content]) with no spaces, raw UTF-8.
import hashlib, json, sys
path = sys.argv[1]
doc = json.load(open(path, encoding='utf-8'))
e = doc['event']
ser = json.dumps([0, e['pubkey'], e['created_at'], e['kind'], e['tags'], e['content']], separators=(',', ':'), ensure_ascii=False)
doc['python_id'] = hashlib.sha256(ser.encode('utf-8')).hexdigest()
json.dump(doc, open(path, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
open(path, 'a').write('\n')
