#!/usr/bin/env python3
"""Regenerate the language picker + hreflang alternates on every website
page, and the switcher on every manual page, to the full 12-locale set.
Idempotent: replaces the existing langsw span / hreflang block / switcher
div in place, base-aware (index picker -> index.<l>.html)."""
import re, glob, os

LANGS = ['fr', 'de', 'it', 'es', 'nl', 'pt', 'sv', 'da', 'nb', 'fi', 'tr', 'ro',
         'he', 'ar', 'fa']
LABEL = {l: l.upper() for l in LANGS}
# margin-inline-start (not -left) so the picker sits correctly in RTL pages.
PICKER_STYLE = 'font-size:11.5px;opacity:.75;margin-inline-start:10px;white-space:nowrap'
SW_STYLE = 'font-size:11.5px;margin-top:6px;color:var(--dim)'

def web_picker(base):
    links = [f'<a href="{base}.html">EN</a>'] + \
            [f'<a href="{base}.{l}.html">{LABEL[l]}</a>' for l in LANGS]
    return f'<span class="langsw" style="{PICKER_STYLE}">' + ' · '.join(links) + '</span>'

def web_hreflang(base):
    lines = [f'<link rel="alternate" hreflang="en" href="{base}.html">']
    lines += [f'<link rel="alternate" hreflang="{l}" href="{base}.{l}.html">' for l in LANGS]
    lines.append(f'<link rel="alternate" hreflang="x-default" href="{base}.html">')
    return '\n'.join(lines)

def manual_switcher():
    links = ['<a href="/manual">EN</a>'] + \
            [f'<a href="/manual/{l}">{LABEL[l]}</a>' for l in LANGS]
    return f'<div class="langsw" style="{SW_STYLE}">' + ' · '.join(links) + '</div>'

n = 0
# ---- website ----
for p in glob.glob('website/*.html'):
    base = os.path.basename(p).split('.')[0]
    if base not in ('index', 'features', 'download', 'benchmarks'):
        continue
    s = open(p, encoding='utf-8').read()
    orig = s
    s = re.sub(r'<span class="langsw".*?</span>', lambda m: web_picker(base), s, flags=re.S)
    # collapse the existing run of hreflang <link> tags into the fresh block
    s = re.sub(r'(<link rel="alternate"[^>]*>\s*)+',
               lambda m: web_hreflang(base) + '\n', s, count=1)
    if s != orig:
        open(p, 'w', encoding='utf-8').write(s)
        n += 1
# ---- manual ----
for p in ['docs/MANUAL.html'] + glob.glob('docs/i18n/MANUAL.*.html'):
    s = open(p, encoding='utf-8').read()
    orig = s
    s = re.sub(r'<div class="langsw".*?</div>', lambda m: manual_switcher(), s, flags=re.S)
    if s != orig:
        open(p, 'w', encoding='utf-8').write(s)
        n += 1
print(f'{n} files regenerated (pickers/hreflang/switchers -> 15 locales + EN)')
