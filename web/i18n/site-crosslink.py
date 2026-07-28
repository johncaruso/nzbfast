#!/usr/bin/env python3
"""Rewrite internal cross-page links on every localized website page so a
visitor stays in-language: href="index.html" -> href="index.<L>.html" for
the four site pages, everywhere EXCEPT the hreflang <link> block and the
langsw picker span (both of which must keep the bare English filenames and
their explicit per-language names). MANUAL.html and absolute URLs untouched.
Idempotent."""
import re, glob, os, sys

BASES = ['index', 'features', 'benchmarks', 'download']
LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']
PAT = re.compile(r'href="(' + '|'.join(BASES) + r')\.html(#[^"]*)?"')

def rewrite(path, lang):
    s = open(path, encoding='utf-8').read()
    protected = {}
    def stash(m):
        key = f'\x00{len(protected)}\x00'
        protected[key] = m.group(0)
        return key
    # Protect the hreflang alternates (each <link rel="alternate" ...>) and
    # the whole langsw picker span - these legitimately hold bare + explicit
    # per-language filenames.
    s = re.sub(r'<link rel="alternate"[^>]*>', stash, s)
    s = re.sub(r'<span class="langsw".*?</span>', stash, s, flags=re.S)
    # Rewrite the rest.
    s2 = PAT.sub(lambda m: f'href="{m.group(1)}.{lang}.html{m.group(2) or ""}"', s)
    for k, v in protected.items():
        s2 = s2.replace(k, v)
    changed = s2 != open(path, encoding='utf-8').read()
    open(path, 'w', encoding='utf-8').write(s2)
    return changed

n = 0
for base in BASES:
    for lang in LANGS:
        p = f'website/{base}.{lang}.html'
        if os.path.exists(p):
            if rewrite(p, lang):
                n += 1
                print('relinked', p)
print(f'{n} files rewritten')

# Verify: no bare cross-page href leaked outside picker/hreflang.
bad = 0
for base in BASES:
    for lang in LANGS:
        p = f'website/{base}.{lang}.html'
        if not os.path.exists(p):
            continue
        s = open(p, encoding='utf-8').read()
        s = re.sub(r'<link rel="alternate"[^>]*>', '', s)
        s = re.sub(r'<span class="langsw".*?</span>', '', s, flags=re.S)
        leaks = PAT.findall(s)
        if leaks:
            bad += 1
            print(f'  LEAK {p}: {leaks[:6]}')
print('cross-link verify:', 'OK' if not bad else f'{bad} files with leaks')
sys.exit(1 if bad else 0)
