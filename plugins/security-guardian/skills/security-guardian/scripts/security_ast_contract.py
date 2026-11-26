"""Shared contract for optional trusted JS AST adapters. No target module loading."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

VERSION = '5.9.3'
CONTRACT_VERSION = 1
MAX_SOURCE_LINES = 16
MAX_BYTES = 128_000
MAX_BATCH_BYTES = 2_000_000
MAX_FILES = 128
MAX_HITS = 100
TIMEOUT = 20
ADAPTERS = frozenset({'js_dom_flow.mjs','js_sql_flow.mjs','js_ssr_flow.mjs','js_authz_flow.mjs'})
REASONS = frozenset({'parse_error','node_limit','path_limit','analysis_error','unmodeled_module','unmodeled_global_use',
                     'unmodeled_page','unmodeled_angular_server','unmodeled_transfer_state','unmodeled_server_entry'})

def trusted_runtime(root, parser):
    """Explicit external compiler path and Node; not an OS sandbox."""
    if not parser:
        return None
    candidate = Path(parser).expanduser()
    node = shutil.which('node')
    if not candidate.is_absolute() or not node:
        return None
    compiler, node = candidate.resolve(), Path(node).resolve()
    if not compiler.is_file() or not node.is_file() or compiler.is_relative_to(root) or node.is_relative_to(root):
        return None
    return node, compiler

def lines(value, limit, allow_empty=False):
    if (not isinstance(value,list) or (not value and not allow_empty)
            or len(value)>MAX_SOURCE_LINES or any(type(n) is not int or not 1<=n<=limit for n in value)):
        raise ValueError('Invalid evidence lines')
    return sorted(set(value))

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate parser JSON key')
        result[key]=value
    return result


def validate_rows(data, sizes):
    if len(sizes)>MAX_FILES or any(type(n) is not int or n<1 for n in sizes):
        raise ValueError('Invalid parser line budget')
    if not isinstance(data,dict) or data.get('status')!='OK' or data.get('version')!=VERSION:
        raise ValueError('Parser unavailable')
    rows = data.get('results')
    if not isinstance(rows,list) or len(rows)!=len(sizes):
        raise ValueError('Invalid result count')
    for row, limit in zip(rows,sizes):
        if (not isinstance(row,dict) or type(row.get('parsed')) is not bool
                or type(row.get('partial')) is not bool
                or (row.get('reason') is not None and (not isinstance(row['reason'],str) or row['reason'] not in REASONS))
                or not isinstance(row.get('hits'),list)):
            raise ValueError('Invalid parser result')
        if (not row['parsed'] and (not row['partial'] or row['hits'])) or (row['reason'] and not row['partial']):
            raise ValueError('Inconsistent parser state')
        for hit in row['hits']:
            if not isinstance(hit,dict) or type(hit.get('line')) is not int or not 1<=hit['line']<=limit:
                raise ValueError('Invalid sink line')
            hit['source_lines'] = lines(hit.get('source_lines'),limit,allow_empty=True)
            if 'source_lines_truncated' in hit and type(hit['source_lines_truncated']) is not bool:
                raise ValueError('Invalid truncation flag')
    return rows

def run_parser(adapter, runtime, inputs, sizes):
    if adapter not in ADAPTERS or len(inputs)>MAX_FILES or len(inputs)!=len(sizes):
        raise ValueError('Invalid adapter input')
    if any(not isinstance(x,dict) or not isinstance(x.get('content'),str) for x in inputs):
        raise ValueError('Invalid parser source input')
    lengths=[len(x['content'].encode('utf-8')) for x in inputs]
    if any(n>MAX_BYTES for n in lengths) or sum(lengths)>MAX_BATCH_BYTES:
        raise ValueError('Parser source budget exceeded')
    if any(type(n) is not int or n<1 for n in sizes):
        raise ValueError('Invalid parser line budget')
    node, compiler = runtime
    with tempfile.TemporaryDirectory(prefix='sg-js-parser-') as cwd:
        env = {'PATH':os.defpath,'LANG':'C.UTF-8','HOME':cwd}
        cp = subprocess.run([str(node),'--max-old-space-size=128',
                 str(Path(__file__).with_name(adapter)),str(compiler)],
                 input=json.dumps(inputs,ensure_ascii=False),encoding='utf-8',
                 capture_output=True,timeout=TIMEOUT,cwd=cwd,env=env,check=False)
    if cp.returncode or len(cp.stdout)>2_000_000:
        raise ValueError('Parser unavailable')
    return validate_rows(json.loads(cp.stdout,object_pairs_hook=unique_object),sizes)

def unique_hits(hits):
    """Stable exact-evidence dedup; never join independent branch/route contexts."""
    seen = set()
    for hit in sorted(hits,key=lambda h:(h['line'],json.dumps(h,sort_keys=True,ensure_ascii=True))):
        k = json.dumps(hit,sort_keys=True,ensure_ascii=True)
        if k not in seen:
            seen.add(k)
            yield hit
