#!/usr/bin/env python3
"""Structural parity for the localized website pages vs their English base:
identical id= sets, tag counts, byte-identical <code> content, lang attr,
langsw + hreflang present, and (benchmarks) an anonymity grep for leaked
city/provider names. Run BEFORE the cross-link rewrite (structure only)."""
import re, sys

BAN = re.compile(r'\b(Miami|London|Natasha|Amsterdam|Frankfurt|Ashburn|Newark|'
                 r'Eweka|Newshosting|Usenetserver|Tweaknews|XS ?News|Giganews)\b', re.I)

def ids(s): return sorted(re.findall(r'\bid="([^"]+)"', s))
def tagc(s, t): return len(re.findall(f'<{t}\\b', s))
def codes(s): return re.findall(r'<code[^>]*>(.*?)</code>', s, re.S)

fail = 0
def check(en_path, tr_path, lang, anon=False):
    global fail
    en = open(en_path, encoding='utf-8').read()
    tr = open(tr_path, encoding='utf-8').read()
    probs = []
    if ids(en) != ids(tr):
        probs.append(f'id mismatch only-en={set(ids(en))-set(ids(tr))} only-tr={set(ids(tr))-set(ids(en))}')
    for t in ['section', 'table', 'tr', 'h1', 'h2', 'h3', 'pre', 'a', 'span', 'li']:
        if tagc(en, t) != tagc(tr, t):
            probs.append(f'<{t}> {tagc(en,t)} vs {tagc(tr,t)}')
    if codes(en) != codes(tr):
        probs.append(f'<code> content differs ({len(codes(en))} vs {len(codes(tr))})')
    if f'lang="{lang}"' not in tr:
        probs.append(f'missing lang="{lang}"')
    if 'langsw' not in tr:
        probs.append('picker missing')
    if 'hreflang' not in tr:
        probs.append('hreflang missing')
    if anon:
        # strip code/pre, then scan visible+attr text for banned names
        body = re.sub(r'<(script|style|code|pre)[^>]*>.*?</\1>', '', tr, flags=re.S)
        hits = sorted(set(m.group(0) for m in BAN.finditer(body)))
        if hits:
            probs.append(f'ANONYMITY LEAK: {hits}')
    print(f'{tr_path}: {"OK" if not probs else "PROBLEMS"}')
    for p in probs:
        print('   -', p)
    if probs:
        fail += 1

for base in ['index', 'features', 'download', 'benchmarks']:
    for l in ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
              'he', 'ar', 'fa']:
        check(f'website/{base}.html', f'website/{base}.{l}.html', l, anon=(base == 'benchmarks'))
sys.exit(1 if fail else 0)
