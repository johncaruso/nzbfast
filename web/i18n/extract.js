// Extract the English reference catalogue from the instrumented pages.
// Sources of keys:
//  - data-i18n="k">TEXT           (first text node / textContent)
//  - data-i18n-html="k">…</div>   (rich text, markup kept)
//  - data-i18n-title="k" + title="…"
//  - data-i18n-placeholder="k" + placeholder="…"
//  - t('k','default') / t2('k','default') in JS (t2 is an alias)
//  - tn('base',n,'one','many') → base.one / base.many
// Plus hand-maintained lists: dynamic-key families (status.*, err.*,
// bench.bn.*) whose keys are computed at runtime.
//
// Plurals: English (the reference) has just the CLDR one|other categories,
// stored as base.one / base.many (".many" is the historical suffix for the
// non-one bucket). tn() at runtime selects via Intl.PluralRules, and Slavic
// catalogues add a base.few form by hand - that extra category is per-locale
// and never appears in this English reference, so it isn't scraped here.
// check.py validates per-locale plural-category completeness against the
// base.one/base.many families this file emits.
const fs = require('fs');
const files = ['web/dashboard.html', 'web/wall.html'];
const out = {};
const clash = [];
function put(k, v) {
  v = v.replace(/\s+/g, ' ').trim();
  if (k in out && out[k] !== v) clash.push([k, out[k], v]);
  else out[k] = v;
}
const decode = s => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<')
  .replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#10;/g, '\n');
const unesc = s => s.replace(/\\(['"\\n])/g, (m, c) => c === 'n' ? '\n' : c);

for (const f of files) {
  const s = fs.readFileSync(f, 'utf8');
  // element text. Two guards keep JS out of the scrape: keys are dotted
  // identifiers ([\w.\-]+, so `data-i18n="${k}"` template literals are
  // skipped), and the (?<!\[) lookbehind rejects attribute-SELECTOR uses
  // like `querySelector('a[data-i18n="hdr.manual"]')` - in real HTML the
  // attribute is preceded by whitespace, never by '['. Without these the
  // injected contextual-help code was scraped as bogus keys / giant values.
  for (const m of s.matchAll(/(?<!\[)data-i18n="([\w.\-]+)"[^>]*>([^<]*)/g)) {
    const txt = decode(m[2]);
    if (txt.trim()) put(m[1], txt);
    else if (!(m[1] in out)) clash.push([m[1], '<EMPTY TEXT>', f]);
  }
  // rich text (both -html sites are <div>…</div> with no nested div)
  for (const m of s.matchAll(/(?<!\[)data-i18n-html="([\w.\-]+)"[^>]*>([\s\S]*?)<\/div>/g))
    put(m[1], m[2]);
  // attribute pairs
  for (const m of s.matchAll(/<[^>]*data-i18n-(title|placeholder)="[\w.\-]+"[^>]*>/g)) {
    const tag = m[0];
    const k = tag.match(/data-i18n-(?:title|placeholder)="([\w.\-]+)"/)[1];
    const which = m[1];
    const v = tag.match(new RegExp('(?<!data-i18n-)' + which + '="([^"]*)"'));
    if (v) put(k, decode(v[1]));
    else clash.push([k, '<NO ' + which + ' ATTR>', f]);
  }
  // t('key','default')
  // t2 is an alias for t, used where a local `t` shadows the helper. It
  // was not scraped, so its keys never reached any catalogue and fell
  // back to English at runtime (toast.lookreset had been missing since
  // it was written).
  for (const m of s.matchAll(/\bt2?\(\s*(['"])([\w.\-]+)\1\s*,\s*(')((?:\\.|[^'\\])*)'|\bt2?\(\s*(['"])([\w.\-]+)\5\s*,\s*(")((?:\\.|[^"\\])*)"/g)) {
    const k = m[2] ?? m[6], d = m[4] ?? m[8];
    put(k, unesc(d));
  }
  // tn('base',expr,'one','many')
  for (const m of s.matchAll(/\btn\(\s*'([\w.\-]+)'\s*,\s*[^,]+,\s*(['"])((?:\\.|(?!\2).)*)\2\s*,\s*(['"])((?:\\.|(?!\4).)*)\4/g)) {
    put(m[1] + '.one', unesc(m[3]));
    put(m[1] + '.many', unesc(m[5]));
  }
}

// Dynamic-key families (computed at runtime, no literal to scrape).
Object.assign(out, {
  // §Stage2 settings rail: the group names live in the SETGROUPS table and
  // are rendered via t(g.i, g.d), so the key is a variable at the call site
  // and the scrape above cannot see it.
  'set.g.start': 'Getting started',
  'set.g.download': 'Downloading',
  'set.g.organise': 'Organising',
  'set.g.alerts': 'Alerts',
  'set.g.look': 'Look and feel',
  'set.g.system': 'System',
  // hist.vh: t(totBad===1?'hist.vh.bad.one':…)
  'hist.vh.bad.one': '{n} bad block across the last {m}',
  'hist.vh.bad.many': '{n} bad blocks across the last {m}',
  // Archive-shape badge tokens: rendered via t('shape.'+tok, SHAPE_EN[tok])
  // from the daemon's token list, so the key is computed at the call site.
  'shape.rar5': 'RAR5', 'shape.rar4': 'RAR4', 'shape.7z': '7z',
  'shape.store': 'stored', 'shape.compressed': 'compressed', 'shape.mixed': 'mixed',
  'shape.encrypted': 'encrypted',
  'shape.one-pass': 'one-pass', 'shape.unlock-at-end': 'unlocked at the end',
  'shape.on-disk': 'unpacked after download', 'shape.mixed-pass': 'partly on disk',
  'shape.inner-7z': '7z inside', 'shape.inner-rar': 'RAR inside',
  // sysbench bottleneck tags
  'bench.bn.network': 'network', 'bench.bn.compute': 'compute', 'bench.bn.disk': 'disk',
  // Speed units: rendered via unit(k) = t('unit.'+k, UNIT_EN[k]). Latin
  // scripts keep the SI abbreviations; Cyrillic/Greek localize (e.g. ГБ/с).
  'unit.MB': 'MB', 'unit.GB': 'GB', 'unit.TB': 'TB',
  'unit.MBs': 'MB/s', 'unit.GBs': 'GB/s', 'unit.Mbs': 'Mb/s', 'unit.Gbs': 'Gb/s',
  // Group-browser category chips: rendered via t('grp.cat.'+c, GB_CAT_EN[c])
  'grp.cat.all': 'All', 'grp.cat.movies': 'Movies', 'grp.cat.tv': 'TV',
  'grp.cat.music': 'Music', 'grp.cat.books': 'Books', 'grp.cat.comics': 'Comics',
  'grp.cat.games': 'Games', 'grp.cat.software': 'Software', 'grp.cat.anime': 'Anime',
  'grp.cat.sports': 'Sports & motors', 'grp.cat.adult': 'Adult', 'grp.cat.other': 'Other',
  // Sounds card event labels: rendered via t('snd.ev.'+key, SND[key].label)
  'snd.ev.click': 'Button press', 'snd.ev.added': 'Download added',
  'snd.ev.watchlist': 'Watchlist grab', 'snd.ev.complete': 'Download complete',
  'snd.ev.alldone': 'Queue finished', 'snd.ev.failed': 'Download failed',
  'snd.ev.password': 'Password needed', 'snd.ev.pause': 'Paused / resumed',
  'snd.ev.conn': 'Connection lost / restored', 'snd.ev.update': 'Update available',
  // INTEREST_LABELS: the opt-in indexing choices. Built from a table
  // keyed by the daemon's interest keys, so t() is called with a
  // variable and the scraper cannot see them.
  'idx.want.linux': 'Linux and other freely distributable software',
  'idx.want.movies': 'Films',
  'idx.want.tv': 'TV shows',
  'idx.want.sports': 'Sport',
  'idx.want.music': 'Music',
  'idx.want.books': 'Books and audiobooks',
  'idx.want.comics': 'Comics',
  'idx.want.anime': 'Anime',
  'idx.want.games': 'Games',
  'idx.want.apps': 'Applications',
  // tStatus(): SAB-compatible wire statuses (English stays on the wire)
  'status.Downloading': 'Downloading', 'status.Queued': 'Queued',
  'status.Paused': 'Paused', 'status.Completed': 'Completed',
  'status.Failed': 'Failed', 'status.Idle': 'Idle', 'status.idle': 'idle',
  // tErr(): fixed daemon error strings (serve.rs), keyed by wire text
  'err.unknown nzo_id': 'unknown nzo_id',
  'err.empty password': 'empty password',
  'err.POST required': 'POST required',
  'err.text too long': 'text too long',
  'err.invalid folder name': 'invalid folder name',
  'err.no nzb file in request': 'no nzb file in request',
  'err.empty query': 'empty query',
  'err.index unavailable': 'index unavailable',
  'err.key and title are required': 'key and title are required',
  'err.key is required': 'key is required',
  'err.unknown title key': 'unknown title key',
  'err.image too large (8 MB max)': 'image too large (8 MB max)',
  "err.that isn't an image (JPEG/PNG/GIF/WebP)": "that isn't an image (JPEG/PNG/GIF/WebP)",
  "err.couldn't write the art cache": "couldn't write the art cache",
  'err.a valid email address is required': 'a valid email address is required',
  'err.release not found': 'release not found',
  'err.cannot move the active download': 'cannot move the active download',
  'err.no servers configured': 'no servers configured',
  'err.no such server': 'no such server',
  'err.unknown server index': 'unknown server index',
  'err.connect timed out (12 s)': 'connect timed out (12 s)',
  'err.move failed (files in use, or target exists?)': 'move failed (files in use, or target exists?)',
});

// Plural families must ship BOTH English categories (base.one + base.many);
// check.py infers the family set from exactly this invariant, so a lone .one
// or .many (a typo'd tn() call) would silently break per-locale validation.
for (const k of Object.keys(out)) {
  if (k.endsWith('.one') && !(k.slice(0, -4) + '.many' in out))
    clash.push([k, '<PLURAL .one WITHOUT MATCHING .many>', '']);
  if (k.endsWith('.many') && !(k.slice(0, -5) + '.one' in out))
    clash.push([k, '<PLURAL .many WITHOUT MATCHING .one>', '']);
}

if (clash.length) { console.error('CLASHES/GAPS:'); for (const c of clash) console.error(' ', c); }
const sorted = {};
for (const k of Object.keys(out).sort()) sorted[k] = out[k];
fs.writeFileSync('web/i18n/en.reference.json', JSON.stringify(sorted, null, 1) + '\n');
console.log(Object.keys(sorted).length + ' keys → web/i18n/en.reference.json');
