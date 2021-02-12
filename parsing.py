# -*- encoding: utf-8 -*-

import json
import sys
import urllib.parse

args = sys.argv[1]

i = 1
result = {}

def parse_uri(uri) :
    parsed = urllib.parse.urlparse(urllib.parse.unquote(uri))

    part = parsed.path.split('/')
    path = parsed.path
    fname = None
    ext = None
    if '.' in part[-1]:
        path = path[:-len(part[-1])]
        pt = part[-1].split('.')
        ext = pt[-1]
        fname = part[-1][:-len(pt[-1])-1]
    return path, fname, ext ,urllib.parse.parse_qs(parsed.query)

with open(args) as f:
    lines = f.readlines()
    for line in lines:
        r = line.split(' ')#'\t\t'
        result[i] = {'IP': r[0],
         'DATE': r[3], 'METHOD': r[5][1:], 'PATH': None, 'FNAME': None, 'EXT' : None,
                     'VERSION':r[7][:-1], 'STATUS':r[8], 'SIZE': r[9][:-1], 'ARGS' : None}
        result[i]['PATH'] , result[i]['FNAME'], result[i]['EXT'], result[i]['ARGS'] \
            =  parse_uri(r[6])
        i += 1 
#print(result) 
with open('data.json', 'w',encoding="utf-8") as fp:
    json.dump(result, fp, ensure_ascii=False, indent="\t")