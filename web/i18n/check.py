#!/usr/bin/env python3
"""Validate translated catalogues against the English reference:
key parity, placeholder parity, markup preservation, JSON validity,
and per-locale plural-category completeness. Locales are auto-discovered
from web/i18n/*.json (adding a new one is translation-only - this picks
it up).

Plurals: the English reference carries the two CLDR categories English
uses - base.one and base.many (".many" is the historical suffix for the
non-one bucket, CLDR 'other'). At runtime tn() selects via
Intl.PluralRules. Locales whose grammar needs a distinct 2-4 form
(Russian, Polish, Czech, Ukrainian, Slovak, Croatian, Serbian) must ADD a
base.few key to every plural family; Czech's 5+/0 form lands in .many
through the runtime category->many fallback, so it needs no separate
.other. Slovenian and Hebrew add a dual (base.two); Slovenian also takes
base.few (one/two/few/many). Arabic takes all six categories
(base.zero/.two/.few on top of .one/.many). Two-form locales (the Latin
scripts, Greek, Hungarian, Bulgarian, Persian, and CJK such as Japanese)
keep just .one/.many and must NOT ship a stray .few. This script enforces
exactly that per locale."""
import json, re, sys, glob, os

ref = json.load(open('web/i18n/en.reference.json'))
PH = re.compile(r'\{[a-z]+\}')
TAGS = re.compile(r'</?(?:b|code|a|i|br)\b')

# Plural families: bases carrying BOTH English categories. extract.js
# guarantees .one/.many always come as a pair (its pairing self-check),
# so this reconstructs the family set without a hand-maintained list.
PLURAL_BASES = sorted(k[:-4] for k in ref if k.endswith('.one')
                      and k[:-4] + '.many' in ref)

# Locales that add a CLDR 'few' (2-4) category to every plural family.
SLAVIC_FEW = {'ru', 'pl', 'cs', 'uk', 'sk', 'hr', 'sr', 'sl'}
# Locales that add a CLDR 'two' (dual) category - Hebrew (phase 2b) and
# Slovenian (phase 2a-ext, one/two/few/many; sl is also in SLAVIC_FEW,
# so the two sets together give it both .two and .few).
DUAL_TWO = {'he', 'sl'}
# Arabic (phase 2b) uses all six CLDR categories. The runtime tn() falls
# back to .many for any category with no stored key, so 'other' rides
# .many and Arabic must supply .zero/.two/.few on top of .one/.many.
ARABIC_PLURALS = {'ar'}


def expected_keys(lang):
    """Reference key set adjusted for this locale's plural categories."""
    keys = set(ref)
    if lang in SLAVIC_FEW:
        keys |= {b + '.few' for b in PLURAL_BASES}
    if lang in DUAL_TWO:
        keys |= {b + '.two' for b in PLURAL_BASES}
    if lang in ARABIC_PLURALS:
        keys |= {b + suf for b in PLURAL_BASES
                 for suf in ('.zero', '.two', '.few')}
    return keys


def en_for(k):
    """The reference English a translated key is checked against. A .two
    (dual) is a specific-number form like the singular, so it mirrors .one
    for placeholder parity; the plural-quantity forms (.few/.zero) mirror
    the .many bucket they augment."""
    if k in ref:
        return ref[k]
    base, _, cat = k.rpartition('.')
    if cat == 'two':
        return ref.get(base + '.one')
    if cat in ('few', 'zero'):
        return ref.get(base + '.many')
    return None


LOCALES = sorted(os.path.basename(p)[:-5] for p in glob.glob('web/i18n/*.json')
                 if not p.endswith('en.reference.json'))
fail = 0
for lang in LOCALES:
    path = f'web/i18n/{lang}.json'
    try:
        d = json.load(open(path))
    except Exception as e:
        print(f'{lang}: INVALID JSON: {e}'); fail += 1; continue
    exp = expected_keys(lang)
    missing = exp - set(d)
    extra = set(d) - exp
    ph_bad, tag_bad, empty = [], [], []
    for k, tr in d.items():
        en = en_for(k)
        if en is None:
            continue  # unexpected key - already reported under 'extra'
        if not isinstance(tr, str) or not tr.strip():
            empty.append(k); continue
        if sorted(PH.findall(en)) != sorted(PH.findall(tr)):
            ph_bad.append(k)
        if len(TAGS.findall(en)) != len(TAGS.findall(tr)):
            tag_bad.append(k)
    ident = sum(1 for k in d
                if en_for(k) is not None and d[k] == en_for(k) and len(en_for(k)) > 12
                and not k.startswith(('bench.bn.', 'status.')))
    print(f'{lang}: {len(d)} keys · missing {len(missing)} · extra {len(extra)} · '
          f'placeholder-mismatch {len(ph_bad)} · markup-mismatch {len(tag_bad)} · '
          f'empty {len(empty)} · left-English(>12ch) {ident}')
    for name, lst in (('missing', sorted(missing)), ('extra', sorted(extra)),
                      ('ph', ph_bad), ('tags', tag_bad), ('empty', empty)):
        if lst:
            fail += 1
            print(f'  {name}: {lst[:12]}{" …" if len(lst) > 12 else ""}')
sys.exit(1 if fail else 0)
