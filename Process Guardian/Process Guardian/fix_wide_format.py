#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fix msvcrt wide-char printf format strings: in L"..." literals,
%s means char* while %ls means wchar_t*. This project passes wchar_t*
almost everywhere, so convert bare %s to %ls inside wide string literals.
Skips %%s (literal percent followed by s) and %.*s.
"""

import re
import sys

def fix_line(line):
    # Find all L"..." substrings and fix %s -> %ls inside them.
    # Regex to match wide string literal (handles escaped quotes and backslashes)
    def repl(m):
        s = m.group(0)
        # Replace %s with %ls, but not %%s or %.*s or %*s
        # Pattern: %(not %) followed optionally by .* or * then s
        # We want to match %s, %-10s, %10s but not %%s, %.*s, %*s
        result = re.sub(
            r'(?<!%)%([0-9]*\.?[0-9]*|-?[0-9]+)?s',
            lambda x: '%ls' if not x.group(1) or x.group(1).isdigit() or x.group(1).startswith('-') or x.group(1).startswith('.') else x.group(0),
            s
        )
        return result

    # Match L"..." allowing escaped chars
    return re.sub(r'L"(?:[^"\\]|\\.)*"', repl, line)

def fix_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    new_lines = [fix_line(line) for line in lines]
    new_text = ''.join(new_lines)

    if new_text != ''.join(lines):
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_text)
        print(f'Fixed: {path}')
    else:
        print(f'No changes: {path}')

if __name__ == '__main__':
    paths = sys.argv[1:] if len(sys.argv) > 1 else ['daemon_core.c']
    for p in paths:
        fix_file(p)
