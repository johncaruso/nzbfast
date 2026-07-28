#!/usr/bin/env python3
"""Structural parity for translated MANUALS vs docs/MANUAL.html:
identical id/anchor sets, tag counts, byte-identical <code>, lang + switcher."""
import re, sys

LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']

def ids(s): return sorted(re.findall(r'\bid="([^"]+)"', s))
def tagc(s, t): return len(re.findall(rf'<{t}\b', s))
# Multiset, not ordered: two adjacent inline <code> refs legitimately swap
# order when a sentence's word order changes in translation. Comparing the
# sorted bag still catches any added / removed / translated code block.
def codes(s): return sorted(re.findall(r'<code[^>]*>(.*?)</code>', s, re.S))

fail = 0
en = open('docs/MANUAL.html', encoding='utf-8').read()
for l in LANGS:
    p = f'docs/i18n/MANUAL.{l}.html'
    tr = open(p, encoding='utf-8').read()
    probs = []
    if ids(en) != ids(tr):
        probs.append(f'id mismatch only-en={set(ids(en))-set(ids(tr))} only-tr={set(ids(tr))-set(ids(en))}')
    for t in ['h2', 'h3', 'pre', 'table', 'a']:
        if tagc(en, t) != tagc(tr, t):
            probs.append(f'<{t}> {tagc(en,t)} vs {tagc(tr,t)}')
    if codes(en) != codes(tr):
        probs.append(f'<code> content differs ({len(codes(en))} vs {len(codes(tr))})')
    if f'lang="{l}"' not in tr:
        probs.append(f'missing lang="{l}"')
    if 'langsw' not in tr:
        probs.append('switcher missing')
    print(f'{p}: {"OK" if not probs else "PROBLEMS"}')
    for x in probs:
        print('   -', x)
    if probs:
        fail += 1
sys.exit(1 if fail else 0)
