# i18n toolchain (§5)

All scripts are run **from the repo root**. English is the source
language and lives inline in the pages (`data-i18n` markup + `t()`
call-site defaults) - it ships no catalogue.

## Files
- `en.reference.json` - the extracted English key→string reference
  (regenerated; do not hand-edit).
- `<lang>.json` - translated UI catalogues, embedded in the binary via
  `include_str!` and served at `/i18n/<lang>.json`. Shipped locales (27,
  + en inline): ar bg cs da de el es fa fi fr he hr hu it ja nb nl pl pt
  ro ru sk sl sr sv tr uk. Three are RTL (ar fa he). `check.py`
  auto-discovers this set from `web/i18n/*.json`, so it is the list that
  cannot go stale - re-derive from there rather than trusting this line.

## Key order (the trap)

The two file kinds sort DIFFERENTLY, and rewriting one with the other's
comparator churns hundreds of untouched lines into your diff:

- `en.reference.json` - plain `Object.keys().sort()` (code-point order,
  so `status.Idle` sorts before `status.idle`). That is what `extract.js`
  writes; never hand-edit it, just rerun the script.
- `<lang>.json` - `Object.keys().sort((a,b)=>a.localeCompare(b))`
  localeCompare order (re-verified byte-for-byte against all 27 shipped
  files on 7 Aug 2026: localeCompare re-serializes every file
  identically, plain code-point sort churns ~19 lines per file). Do not
  trust a claim here without re-running the byte-identity test.

Both use `JSON.stringify(obj, null, 1)` plus a trailing newline. To add
keys to every catalogue, merge them in and re-serialize with the matching
comparator - this rewrites all 27 files byte-identically apart from your
additions:

```js
const s={}; for(const k of Object.keys(d).sort((a,b)=>a.localeCompare(b))) s[k]=d[k];
fs.writeFileSync(p, JSON.stringify(s,null,1)+'\n');
```

Also note: regenerating `en.reference.json` picks up every `t()` default
added to the pages since the last run, so a UI string someone landed
without regenerating turns `check.py` red the moment you regenerate for
your own keys. Translate those too (or the gate ships red on your
commit) - and check whether the strings arrived on origin/main first, so
you are not duplicating an in-flight session's work.

## Scripts
- `extract.js` - `node web/i18n/extract.js` regenerates
  `en.reference.json` from `web/dashboard.html` + `web/wall.html`
  (data-i18n attrs, `t()/tn()` defaults, plus the hand-maintained
  dynamic-key families for `status.*` / `err.*` / `bench.bn.*` /
  `snd.ev.*`).
- `check.py` - `python3 web/i18n/check.py` validates every `<lang>.json`
  against the reference: key parity, placeholder parity, markup parity,
  JSON validity. **Auto-discovers** locales from `web/i18n/*.json`.
- `nav-regen.py` - regenerates the language picker + hreflang alternates
  on every `website/*.html` and the switcher on every manual
  (`docs/MANUAL.html` + `docs/i18n/MANUAL.*.html`) to the full locale set.
  Edit its `LANGS` list to add a locale, then run it.
- `site-crosslink.py` - rewrites internal cross-page links (nav + body
  CTAs) on every localized `website/*.<lang>.html` to its same-language
  sibling, so a visitor stays in one language. Protects the picker span
  and hreflang block (they keep the bare + explicit-per-language names).
  Idempotent; run after translating website pages.
- `site-check.py` - structural parity for localized website pages vs
  their English base (id sets, tag counts, byte-identical `<code>`, lang
  attr, picker/hreflang present) + an **anonymity grep** on
  `benchmarks.*` for leaked city/provider names.
- `manual-check.py` - structural parity for translated manuals vs
  `docs/MANUAL.html` (id/anchor sets, tag counts, byte-identical `<code>`,
  lang, switcher).
- `pullsearch/port.py` - the pattern for adding a NEW manual section to
  all 16 languages at once, kept as a worked example. The blocks live one
  file per locale (`pullsearch/<lang>.html`, marked off with
  `<!--BLOCK name-->`), rendered from `pullsearch/en.html` so only the
  prose differs; `port.py --check` compares the tag stream, `href=` and
  `<code>` content of every block against English BEFORE writing, and
  each insertion anchors on an `id=` or a byte-identical `<code>` and
  asserts a single match. Hand-writing the locale pages instead is what
  puts `manual-check.py` red at gate time.

## Adding a locale (Latin / simple plural)
1. `web/i18n/<tag>.json` - translate from `en.reference.json`.
2. `crates/nzbfast/src/serve/assets.rs`: add the tag to `UI_LOCALES` + an
   `i18n_catalog()` arm (and a `manual_i18n()` arm once a manual exists,
   else it falls back to English). This used to be one `serve.rs`; the
   daemon is a module tree under `src/serve/` now.
3. `web/dashboard.html` + `web/wall.html`: add to the `LOCALES` array, plus
   one `LOCALE_NAMES` line in dashboard.html (`[native, English]` - both
   Settings selects are generated from it at boot).
4. Website/manual (optional): seed English copies, add tag to
   `nav-regen.py` LANGS + `site-crosslink.py`/`site-check.py`/
   `manual-check.py`, run nav-regen, translate, run site-crosslink,
   validate.
5. `node --check` the inline JS, `cargo build --release -p nzbfast`,
   live-verify on a scratch daemon (its own port + scratch dirs), commit
   per safe-git.

Multi-plural locales need no engine work - `tn()` is category-generic. A
locale whose grammar adds CLDR categories just ships the extra keys and
declares them in `check.py`: `SLAVIC_FEW` (ru/pl/cs/uk/sk/hr/sr add
`base.few`) or `DUAL_TWO` (sl adds `base.two` **and** `base.few`). Any
category a catalogue doesn't stock falls back to `.many` at runtime.
