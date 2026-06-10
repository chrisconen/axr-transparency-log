// ═══════════════════════════════════════════════════════════════════════════════
// AXR 0.3 Stage D - fuggetlen Monitor
// ═══════════════════════════════════════════════════════════════════════════════
// A horgonyzas (Stage B) onmagaban LATENS vedelem: a Signed Tree Head-ek leteznek,
// de csak akkor ernek valamit, ha valaki - az operatortol FUGGETLEN fel - tenylegesen
// figyeli oket. Ez a Monitor. A verifier egy logot EGY idopillanatban ellenoriz
// (belso konzisztencia); a Monitor IDOBEN es NEZETEK KOZOTT: sajat, megorzott
// naplot (journal) vezet, es riaszt, ha az uj nezet ellentmond a korabbinak.
//
// Mit fog el (spec 7.5, G5/G6):
//   - EQUIVOCATION: ugyanahhoz a tree_size-hoz mas root jelenik meg, mint amit a
//     monitor korabban naplozott -> az operator ket kulonbozo fat mutatott
//   - TRUNCATION:   a log zsugorodott (a jelenlegi max tree_size < naplozott max)
//   - NON_APPEND_ONLY: az egymast koveto STH-k kozott a consistency proof megbukik
//   - ROOT_MISMATCH: egy STH olyan rootot allit, ami nem egyezik a tenyleges
//     receiptek Merkle-gyokerevel (ha a monitor megkapja a recepteket)
//   - BAD_SIGNATURE: egy STH alairasa ervenytelen a rogzitett kulcsra
//
// Ket parancs:
//   poll    - egy operator STH-fajljanak figyelese, a journal frissitese
//   compare - ket monitor journaljanak osszevetese (split-view bizonyitas)
//
// Hasznalat:
//   node axr-monitor.js poll <sth.jsonl> <public-key.pem> \
//        [--state monitor-state.json] [--receipts receipts.jsonl] \
//        [--anchors anchors.jsonl] [--log-id axr:agent:v1]
//   node axr-monitor.js compare <monitor-state-A.json> <monitor-state-B.json>
//
// Nulla kulso fuggoseg - csak a Node beepitett moduljai + a kozos axr-core.js.
// Kilepesi kod: 0 ha minden konzisztens, 1 ha sertest talal, 2 ha rossz hasznalat.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axr = require('./axr-core');

const LEAF_TYPES = ['step', 'workflow', 'identity'];
const MONITOR_VERSION = '0.3';

function readJsonl(p) {
  if (!p || !fs.existsSync(p)) return [];
  return fs.readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}
function keyFingerprint(pem) {
  // a PEM-bol kinyert nyers kulcs-bajtok hash-e (whitespace-fuggetlen)
  const body = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return 'sha256:' + crypto.createHash('sha256').update(body, 'utf8').digest('hex');
}
function loadState(statePath) {
  if (statePath && fs.existsSync(statePath)) return JSON.parse(fs.readFileSync(statePath, 'utf8'));
  return null;
}
function sibling(p, name) { return path.join(path.dirname(path.resolve(p)), name); }
function saveState(statePath, state) {
  if (!statePath) return;
  const tmp = statePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2) + '\n');
  fs.renameSync(tmp, statePath);
}

// ═══════════════════════════════════════════════════════════════════════════════
// poll - egy operator STH-fajljanak figyelese
// ═══════════════════════════════════════════════════════════════════════════════
// opts:
//   sthPath      (kotelezo) - az operator sth.jsonl-je
//   publicKeyPem (kotelezo) - a rogzitett (pinned) operator-kulcs
//   statePath    (opc.)     - a monitor sajat journalja (default: <dir>/monitor-state.json)
//   receiptsPath (opc.)     - ha megvan, a monitor ujraszamolja a rootokat es a
//                             consistency proofokat (legerosebb ellenorzes)
//   anchorsPath  (opc.)     - kulso anchor cross-check (offline: jelzes)
//   logId        (opc.)     - elvart log_id (elso futaskor rogzul)
//   now          (opc.)     - () => ISO timestamp (tesztelhetoseghez)
function pollMonitor(opts) {
  if (!opts.sthPath) throw new Error('sthPath kotelezo');
  if (!opts.publicKeyPem) throw new Error('publicKeyPem kotelezo');
  const statePath = opts.statePath || sibling(opts.sthPath, 'monitor-state.json');
  const now = opts.now || (() => new Date().toISOString());
  const fp = keyFingerprint(opts.publicKeyPem);

  const violations = [];
  const notices = [];
  const V = (code, msg) => violations.push({ code, message: msg });
  const N = (msg) => notices.push(msg);

  // 1. journal betoltese / inicializalas + kulcs es log_id rogzitese
  let state = loadState(statePath);
  if (!state) {
    state = { axr_monitor_version: MONITOR_VERSION, log_id: opts.logId || null,
              public_key_fingerprint: fp, witnessed: [] };
  } else {
    if (state.public_key_fingerprint !== fp)
      V('KEY_CHANGED', `a rogzitett operator-kulcs megvaltozott (journal: ${state.public_key_fingerprint.slice(0, 20)}..., most: ${fp.slice(0, 20)}...)`);
    if (opts.logId && state.log_id && state.log_id !== opts.logId)
      V('LOG_ID_CHANGED', `a log_id megvaltozott (journal: ${state.log_id}, most: ${opts.logId})`);
  }

  // 2. STH-k beolvasasa, rendezes tree_size szerint
  const sths = readJsonl(opts.sthPath).filter(r => r.record_type === 'sth').sort((a, b) => a.tree_size - b.tree_size);
  if (!sths.length) {
    N('nincs STH a fajlban - nincs mit figyelni');
    saveState(statePath, state);
    return finalize(state, violations, notices);
  }
  if (state.log_id == null) state.log_id = sths[0].log_id || opts.logId || null;

  // 3. (opcionalis) receiptek -> levelhashek a root- es consistency-ellenorzeshez
  const receipts = readJsonl(opts.receiptsPath);
  const leafHashes = receipts.filter(r => LEAF_TYPES.includes(r.receipt_type)).map(axr.leafHash);
  const haveLeaves = leafHashes.length > 0;
  if (!haveLeaves && opts.receiptsPath) N('a receipts.jsonl ures vagy hianyzik - a root/consistency ellenorzes kimarad');

  // 4. minden STH: alairas, (ha van) root-egyezes, equivocation a journal ellen
  const journalBySize = {};
  for (const w of state.witnessed) journalBySize[w.tree_size] = w;

  for (const sth of sths) {
    if (!axr.verifyReceipt(sth, opts.publicKeyPem))
      V('BAD_SIGNATURE', `STH (tree_size=${sth.tree_size}): ERVENYTELEN ALAIRAS`);

    if (haveLeaves && sth.tree_size <= leafHashes.length) {
      const recomputed = axr.merkleRootFromLeaves(leafHashes.slice(0, sth.tree_size));
      if (recomputed !== sth.root_hash)
        V('ROOT_MISMATCH', `STH (tree_size=${sth.tree_size}): a root_hash nem egyezik a tenyleges receiptek Merkle-gyokerevel`);
    }

    const seen = journalBySize[sth.tree_size];
    if (seen && seen.root_hash !== sth.root_hash)
      V('EQUIVOCATION', `STH (tree_size=${sth.tree_size}): a root elter a korabban naplozottol ` +
        `(journal: ${seen.root_hash.slice(0, 20)}..., most: ${sth.root_hash.slice(0, 20)}...) - az operator ket kulonbozo fat mutatott`);
  }

  // 5. append-only az egymast koveto STH-k kozott (consistency proof, ha vannak levelek)
  for (let i = 1; i < sths.length; i++) {
    if (sths[i].previous_sth_hash !== axr.chainHash(sths[i - 1]))
      N(`STH-lanc: a(z) ${sths[i].tree_size}-meretu STH previous_sth_hash-e nem az elozore mutat (a fajlbeli sorrend hianyos lehet)`);
    if (haveLeaves && sths[i].tree_size <= leafHashes.length) {
      const m = sths[i - 1].tree_size, n = sths[i].tree_size;
      const proof = axr.consistencyProof(m, leafHashes.slice(0, n));
      if (!axr.verifyConsistency(m, n, sths[i - 1].root_hash, sths[i].root_hash, proof))
        V('NON_APPEND_ONLY', `STH ${m} -> ${n}: a consistency proof MEGBUKOTT - az ujabb fa nem az append-only bovitese a reginek`);
    } else if (!haveLeaves) {
      N(`STH ${sths[i - 1].tree_size} -> ${sths[i].tree_size}: a consistency receptek nelkul nem ellenorizheto (CONSISTENCY_UNVERIFIED)`);
    }
  }

  // 6. truncation: a jelenlegi max kisebb, mint a naplozott max
  const journalMax = state.witnessed.reduce((m, w) => Math.max(m, w.tree_size), 0);
  const currentMax = sths[sths.length - 1].tree_size;
  if (currentMax < journalMax)
    V('TRUNCATION', `a log zsugorodott: a jelenlegi max tree_size (${currentMax}) kisebb a korabban naplozottnal (${journalMax}) - rekordokat tavolitottak el`);

  // 7. cross-poll consistency: a naplozott legnagyobb fa -> a jelenlegi legnagyobb fa
  const journalTop = state.witnessed.slice().sort((a, b) => b.tree_size - a.tree_size)[0];
  if (journalTop && haveLeaves && currentMax <= leafHashes.length && journalTop.tree_size < currentMax) {
    const proof = axr.consistencyProof(journalTop.tree_size, leafHashes.slice(0, currentMax));
    if (!axr.verifyConsistency(journalTop.tree_size, currentMax, journalTop.root_hash, sths[sths.length - 1].root_hash, proof))
      V('NON_APPEND_ONLY', `cross-poll ${journalTop.tree_size} -> ${currentMax}: a korabban latott fa NEM prefixe a mostaninak - a multat atirtak`);
  }

  // 8. kulso anchor cross-check (offline: explicit jelzes)
  const anchors = readJsonl(opts.anchorsPath).filter(a => a.record_type === 'anchor');
  for (const a of anchors) {
    N(`ANCHOR_UNVERIFIED: ${a.backend} anchor (tree_size=${a.tree_size}) - offline mod, a backend nincs fuggetlenul lekerdezve`);
  }

  // 9. journal frissitese: minden uj (meg nem latott) tree_size felvetele
  for (const sth of sths) {
    if (!journalBySize[sth.tree_size]) {
      state.witnessed.push({
        tree_size: sth.tree_size, root_hash: sth.root_hash, sth_hash: axr.chainHash(sth),
        sth_timestamp: sth.timestamp, first_seen_at: now()
      });
    }
  }
  state.witnessed.sort((a, b) => a.tree_size - b.tree_size);
  saveState(statePath, state);

  return finalize(state, violations, notices);
}

function finalize(state, violations, notices) {
  return { ok: violations.length === 0, violations, notices,
           witnessedCount: state.witnessed.length,
           journalMax: state.witnessed.reduce((m, w) => Math.max(m, w.tree_size), 0) };
}

// ═══════════════════════════════════════════════════════════════════════════════
// compare - ket monitor journaljanak osszevetese (split-view / equivocation bizonyitas)
// ═══════════════════════════════════════════════════════════════════════════════
// Ha ket fuggetlen monitor UGYANAHHOZ a tree_size-hoz KULONBOZO rootot naplozott,
// az bizonyitja, hogy az operator ket eltero fat mutatott a ket monitornak.
function compareJournals(a, b) {
  const conflicts = [];
  const aBySize = {}; for (const w of a.witnessed || []) aBySize[w.tree_size] = w;
  for (const w of b.witnessed || []) {
    const av = aBySize[w.tree_size];
    if (av && av.root_hash !== w.root_hash)
      conflicts.push({ tree_size: w.tree_size, root_a: av.root_hash, root_b: w.root_hash });
  }
  if ((a.log_id || null) !== (b.log_id || null))
    conflicts.push({ log_id_mismatch: true, log_id_a: a.log_id || null, log_id_b: b.log_id || null });
  if ((a.public_key_fingerprint || null) !== (b.public_key_fingerprint || null))
    conflicts.push({ key_mismatch: true });
  return { equivocationDetected: conflicts.length > 0, conflicts };
}

module.exports = { pollMonitor, compareJournals, keyFingerprint, LEAF_TYPES };

// ── CLI ──────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);
  const positional = [];
  const flags = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i].startsWith('--')) { flags[rest[i].slice(2)] = rest[i + 1]; i++; }
    else positional.push(rest[i]);
  }

  function printResult(label, res) {
    console.log('-'.repeat(72));
    for (const n of res.notices) console.log(`  [megj] ${n}`);
    if (res.ok) {
      console.log(`${label}: KONZISZTENS. ${res.witnessedCount} STH a journalban (max tree_size=${res.journalMax}).`);
    } else {
      for (const v of res.violations) console.log(`  [SERTES:${v.code}] ${v.message}`);
      console.log(`${label}: SERTES TALALVA (${res.violations.length}). A log atirast/equivocationt mutat.`);
    }
    console.log('-'.repeat(72));
  }

  if (cmd === 'poll') {
    const [sthPath, keyPath] = positional;
    if (!sthPath || !keyPath) {
      console.error('Hasznalat: node axr-monitor.js poll <sth.jsonl> <public-key.pem> [--state monitor-state.json] [--receipts receipts.jsonl] [--anchors anchors.jsonl] [--log-id ...]');
      process.exit(2);
    }
    const publicKeyPem = fs.readFileSync(keyPath, 'utf8');
    const res = pollMonitor({
      sthPath, publicKeyPem, statePath: flags.state,
      receiptsPath: flags.receipts, anchorsPath: flags.anchors, logId: flags['log-id']
    });
    printResult('Monitor poll', res);
    process.exit(res.ok ? 0 : 1);
  } else if (cmd === 'compare') {
    const [aPath, bPath] = positional;
    if (!aPath || !bPath) {
      console.error('Hasznalat: node axr-monitor.js compare <monitor-state-A.json> <monitor-state-B.json>');
      process.exit(2);
    }
    const a = JSON.parse(fs.readFileSync(aPath, 'utf8'));
    const b = JSON.parse(fs.readFileSync(bPath, 'utf8'));
    const res = compareJournals(a, b);
    console.log('-'.repeat(72));
    if (!res.equivocationDetected) {
      console.log('Compare: a ket journal konzisztens - nincs split-view.');
      process.exit(0);
    } else {
      for (const c of res.conflicts) console.log('  [EQUIVOCATION]', JSON.stringify(c));
      console.log('Compare: EQUIVOCATION BIZONYITVA - az operator eltero fakat mutatott a ket monitornak.');
      process.exit(1);
    }
  } else {
    console.error('Ismeretlen parancs. Hasznalat: poll | compare');
    process.exit(2);
  }
}
