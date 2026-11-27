#!/usr/bin/env python3
"""Export only tracked human-facing Mermaid fences for isolated validation."""
import json
import subprocess
from audit_documentation import FENCE, ROOT, is_human_documentation


def extract(path, text):
    fence = None
    blocks = []
    lines = []
    start = 0
    for n, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= fence[1] and not match[2].strip():
                if fence[2] == 'mermaid':
                    blocks.append({'document': path, 'line': start, 'source': '\n'.join(lines)})
                fence = None
            elif fence[2] == 'mermaid':
                lines.append(line)
        elif match:
            fence = (match[1][0], len(match[1]), match[2].strip().lower())
            lines = []
            start = n
    if fence:
        raise ValueError('Unclosed fence: ' + path)
    return blocks


def main():
    paths = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z']).decode().split('\0')
    blocks = []
    for path in sorted(set(paths)):
        if path.endswith('.md') and is_human_documentation(path):
            blocks.extend(extract(path, (ROOT / path).read_text(encoding='utf-8')))
    if not blocks or len(blocks) > 1000:
        raise ValueError('Unexpected Mermaid inventory')
    print(json.dumps(blocks, ensure_ascii=False))


if __name__ == '__main__':
    main()
