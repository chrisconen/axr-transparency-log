// ═══════════════════════════════════════════════════════════════════════════════
// AXR - Agent Execution Receipt - Core Library v0.2
// ═══════════════════════════════════════════════════════════════════════════════
// Ez a fuggvenykonyvtar mindket helyen hasznalhato:
//  - az N8N Code node-ban (receipt generalas)
//  - egy kulonallo verifikalo szkriptben (receipt ellenorzes)
// Nulla kulso fuggoseg - csak a Node beepitett crypto modulja.
//
// 0.2 valtozas: az input_hash mostantol minden lepesnel a lepes TENYLEGES
// inputjabol szamol, nem a kozos normalizalt payload-bol (spec 7.1). Ehhez
// minden tanusitando node a kimenetebe tesz egy __axr_input markert. A core
// itt csak a marker-konvencio kozos helpereit adja; a kiolvasas/eltavolitas
// logikaja egy helyen el, hogy a generator es a verifier ne terjen el.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// ── Protokoll-verzio ───────────────────────────────────────────────────────────
// Minden ujonnan generalt receipt ezt a verziot kapja. A verifier a receipt
// sajat axr_version mezoje szerint agazik el, igy a regi 0.1 lancok tovabbra is
// ervenyesek maradnak (spec: visszafele kompatibilis verifikalas).
const AXR_VERSION = '0.2';

// A marker mezo neve, amit minden tanusitando node a kimenetebe tesz.
// Alahuzas-prefix: jelzi hogy ez AXR-meta, nem uzleti adat.
const AXR_INPUT_KEY = '__axr_input';

// 0.3: a generativ (LLM) lepes ezt a markert csatolja a kimenetehez. A
// tartalma a modell-hivas evidenciaja: model, parameterek, prompt/tool/
// completion hash (vagy nyers tartalom), usage, finish_reason, reproducibility.
// A generator innen tolti a receipt 'generation' blokkjat (spec 5.3).
const AXR_GEN_KEY = '__axr_gen';

// ── Determinisztikus JSON szerializalas (RFC 8785 / JCS szellemeben) ───────────
// A hash es az alairas CSAK akkor reprodukalhato, ha a szerializalas BAJTRA
// azonos minden implementacioban (a "barki, barmely nyelven ellenorizheti" allitas
// ezen all vagy bukik). Szabalyok:
//   - objektum-kulcsok rendezese UTF-16 code unit szerint (JS String#sort default),
//     ami megegyezik az RFC 8785 kulcs-rendezesevel;
//   - szamok az ECMAScript Number->String szerint (amit az RFC 8785 atvesz);
//   - tomb-sorrend valtozatlan; null/true/false/string a JSON szerint.
//
// GUARDOK (a csendes korrupcio ellen): a JSON.stringify a NaN/Infinity erteket
// nemán "null"-la, az undefined-ot pedig kihagyja/„undefined"-da alakitja - ez
// kulonbozo szemantikat azonos (vagy ervenytelen) bajtokra kepezne. Ezert ezeket
// EXPLICIT eldobjuk, nem szerializaljuk. Igy az alairas sosem fed eltero jelentest.
// Megj.: ezek a guardok a MEGLEVO, ervenyes (string/veges-szam/bool/null) receiptek
// kimenetet NEM valtoztatjak - csak a korabban is hibas eseteket teszik hangossa.
function canonicalize(value) {
  if (value === undefined) {
    throw new Error('canonicalize: undefined nem szerializalhato determinisztikusan');
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('canonicalize: nem-veges szam (NaN/Infinity) nem szerializalhato');
  }
  if (typeof value === 'bigint') {
    throw new Error('canonicalize: bigint nem tamogatott');
  }
  if (typeof value === 'function' || typeof value === 'symbol') {
    throw new Error('canonicalize: ' + typeof value + ' nem szerializalhato');
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    // tomb-elemek: az undefined/function/symbol elemet a JSON null-na alakitja;
    // mi ezt is hangossa tesszuk (rekurzio dob), hogy ne legyen rejtett null.
    return '[' + value.map(canonicalize).join(',') + ']';
  }
  // csak sima (plain) objektumot fogadunk el: Date, Map, RegExp stb. tiltott,
  // mert a JSON-reprezentaciojuk nem egyertelmu/nem korrektul rekonstrualhato.
  const proto = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) {
    throw new Error('canonicalize: csak sima objektum engedelyezett (' +
      (value.constructor && value.constructor.name || 'ismeretlen') + ' tiltott)');
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

// ── SHA-256 hash egy tetszoleges ertekrol ──────────────────────────────────────
function sha256(value) {
  const input = typeof value === 'string' ? value : canonicalize(value);
  return 'sha256:' + crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// ── Verzio-osszehasonlitas ──────────────────────────────────────────────────────
// "0.3" >= "0.2" -> true. Egyszeru major.minor parse, elegendo amig a verzio
// "X.Y" formatumu. Kozos a verifierrel, hogy a ket oldal ne terjen el.
function versionAtLeast(v, min) {
  if (!v) return false;
  const pa = String(v).split('.').map(Number);
  const pb = String(min).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const a = pa[i] || 0, b = pb[i] || 0;
    if (a > b) return true;
    if (a < b) return false;
  }
  return true;
}

// ── Volatilis (alairason kivuli) mezok ─────────────────────────────────────────
// Ket mezo iródik/valtozik a receipt ELSO alairasa UTAN, ezert sem az alairast,
// sem a lanc-/level-hasht nem fedhetik - kulonben az utolagos irasuk eltorne a
// mar kiadott bizonyitekokat:
//   anchor_ref         - a horgonyzas keson, kotegelve tolti ki (0.3, spec 4.1)
//   redactable         - a torolheto mezok CLEARTEXT reszlete; a torlesnek (GDPR
//                        Art. 17) nem szabad eltornie az alairast/lancot (0.4).
//                        A commitment (redactable_root) ELLENBEN alairt marad.
// Mindkettot jelenlet-alapon toroljuk: 0.1/0.2 receiptnel egyik sincs -> no-op.
function _stripVolatile(clone) {
  delete clone.anchor_ref;
  delete clone.redactable;
  return clone;
}

// ── Alairhato resz - verzio-fuggo mezo-kihagyas ─────────────────────────────────
// 0.1/0.2: az alairas a receiptet a 'signature' mezo NELKUL fedi.
// 0.3:     a 'signature' ES az 'anchor_ref' is kimarad (anchor_ref az alairas utan
//          irodik, spec 4.1).
// 0.4:     ezen felul a 'redactable' detail is kimarad (a redactable_root marad
//          alairva). Igy egy mezo cleartextjenek torlese nem rontja el az alairast.
function signablePart(receipt) {
  const clone = { ...receipt };
  delete clone.signature;
  // Az anchor_ref MINDEN verzional az alairas UTAN irodik (sidecar write-back),
  // ezert sosem resze az alairt resznek. Jelenlet-alapon vagjuk le (ahogy a
  // chainHash is), nem verzio-alapon: igy a 0.3-as sidecar altal lehorgonyzott
  // 0.1/0.2-es (legacy) receiptek alairasa is helyesen verifikal.
  if ('anchor_ref' in clone) delete clone.anchor_ref;
  if ('redactable' in clone) delete clone.redactable;
  return clone;
}

// ── Lanc-hash (previous_receipt_hash / chain_root_hash / previous_sth_hash) ─────
// A lancolasi hash a volatilis mezok (anchor_ref, redactable) NELKUL szamol, hogy
// a horgonyzas illetve a kesobbi redakcio ne torje el a lancot. Egy helyen el,
// hogy a generator es a verifier garantaltan ugyanazt szamolja.
function chainHash(receipt) {
  if (receipt && typeof receipt === 'object' && ('anchor_ref' in receipt || 'redactable' in receipt)) {
    return sha256(_stripVolatile({ ...receipt }));
  }
  return sha256(receipt);
}

// ── Ed25519 alairas ────────────────────────────────────────────────────────────
// A receiptet kanonikus formaban, a verziohoz tartozo mezo-kihagyassal irjuk ala.
function signReceipt(receipt, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const message = Buffer.from(canonicalize(signablePart(receipt)), 'utf8');
  const signature = crypto.sign(null, message, privateKey);
  return signature.toString('base64');
}

// ── Ed25519 alairas ellenorzes ─────────────────────────────────────────────────
function verifyReceipt(receipt, publicKeyPem) {
  const publicKey = crypto.createPublicKey(publicKeyPem);
  if (!receipt.signature) return false;
  const message = Buffer.from(canonicalize(signablePart(receipt)), 'utf8');
  return crypto.verify(null, message, publicKey, Buffer.from(receipt.signature, 'base64'));
}

// ── UUID v4 ────────────────────────────────────────────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

// ── PII customer reference - nev+email+telefon egyiranyu hash ──────────────────
function customerRef(name, email, phone) {
  return sha256([name || '', email || '', phone || ''].join('|').toLowerCase());
}

// ── __axr_input marker kezelese ────────────────────────────────────────────────
// Minden tanusitando node a kimenetebe tesz egy __axr_input mezot, ami a node
// TENYLEGES bemenete. A generator innen szamolja az input_hash-t. Ez teszi a
// generatort workflow-agnosztikussa: nem kell tudnia a graph szerkezetet (ez
// egyben a 7.2 $('NodeName')-toredekenyseg lezarasa is).
//
// splitAxrInput(nodeOutput) -> { input, output }
//   input  : a node tenyleges bemenete (a marker erteke), vagy undefined ha
//            a node nem hagyott markert (pl. regi node, vagy hibas konfiguracio)
//   output : a node kimenete a marker NELKUL - ezt kell output_hash-elni, hogy
//            a marker jelenlete ne valtoztassa meg az output_hash-t
//
// Ez a fuggveny EGY helyen el, hogy a generator es a verifier garantaltan
// ugyanazt csinalja.
function splitAxrInput(nodeOutput) {
  // tomb-kimenet (n8n itemek): az elso item hordozza a markert
  if (Array.isArray(nodeOutput)) {
    if (nodeOutput.length === 0) return { input: undefined, output: nodeOutput };
    const first = nodeOutput[0];
    const restItems = nodeOutput.slice(1);
    if (first && typeof first === 'object' && !Array.isArray(first) && AXR_INPUT_KEY in first) {
      const { [AXR_INPUT_KEY]: input, ...cleanFirst } = first;
      return { input, output: [cleanFirst, ...restItems] };
    }
    return { input: undefined, output: nodeOutput };
  }
  // objektum-kimenet
  if (nodeOutput && typeof nodeOutput === 'object' && AXR_INPUT_KEY in nodeOutput) {
    const { [AXR_INPUT_KEY]: input, ...clean } = nodeOutput;
    return { input, output: clean };
  }
  return { input: undefined, output: nodeOutput };
}

// ── __axr_gen marker kezelese (0.3) ────────────────────────────────────────────
// Ugyanaz a minta, mint a splitAxrInput, de a generativ-lepes markerere. Egy
// generativ node MINDKET markert hordozza (__axr_input + __axr_gen); a generator
// eloszor a splitAxrInput-ot hivja, majd ezt a maradek kimeneten, hogy a tiszta
// output_hash egyik markert se tartalmazza.
//
// splitAxrGen(nodeOutput) -> { gen, output }
//   gen    : a generativ capture blokk (model/params/prompt/completion/...), vagy
//            undefined ha a node nem generativ (nincs marker)
//   output : a kimenet a __axr_gen marker NELKUL
function splitAxrGen(nodeOutput) {
  if (Array.isArray(nodeOutput)) {
    if (nodeOutput.length === 0) return { gen: undefined, output: nodeOutput };
    const first = nodeOutput[0];
    const restItems = nodeOutput.slice(1);
    if (first && typeof first === 'object' && !Array.isArray(first) && AXR_GEN_KEY in first) {
      const { [AXR_GEN_KEY]: gen, ...cleanFirst } = first;
      return { gen, output: [cleanFirst, ...restItems] };
    }
    return { gen: undefined, output: nodeOutput };
  }
  if (nodeOutput && typeof nodeOutput === 'object' && AXR_GEN_KEY in nodeOutput) {
    const { [AXR_GEN_KEY]: gen, ...clean } = nodeOutput;
    return { gen, output: clean };
  }
  return { gen: undefined, output: nodeOutput };
}

// ── Generation blokk epitese a markerbol (0.3, spec 5.3) ───────────────────────
// A node a nyers anyagot is csatolhatja (prompt/tools/completion) - ekkor itt
// szamoljuk a hash-eket -, vagy mar elore kiszamolt hash-eket. Egy helyen el,
// hogy a node es barmely ujraszamolo fel ugyanazt a hash-t kapja.
//   gen.prompt / gen.completion : nyers ordered message-lista / valasz -> hasheljuk
//   gen.tools                   : tool-definiciok (vagy null)
//   gen.*_hash                  : ha a node mar elore hashelt, azt hasznaljuk
function buildGeneration(gen) {
  if (!gen || typeof gen !== 'object') return null;
  const h = (v, pre) => (v !== undefined && v !== null) ? sha256(v) : (pre || null);
  return {
    params: gen.params || {},
    prompt_hash: gen.prompt !== undefined ? sha256(gen.prompt) : (gen.prompt_hash || null),
    tools_hash: (gen.tools !== undefined && gen.tools !== null) ? sha256(gen.tools) : (gen.tools_hash || null),
    completion_hash: gen.completion !== undefined ? sha256(gen.completion) : (gen.completion_hash || null),
    prompt_ref: gen.prompt_ref || null,
    completion_ref: gen.completion_ref || null,
    usage: gen.usage || null,
    finish_reason: gen.finish_reason || null,
    reproducibility: gen.reproducibility ||
      { level: 'best_effort', deterministic_settings: false, notes: '' }
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.3 - Merkle-fa es kulso horgonyzas (RFC 6962 / Certificate Transparency)
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.3 a receipt-hasheket egy RFC 6962 stilusu Merkle-faba kotegeli. A fa
// gyokeret idoszakosan alairjuk (Signed Tree Head) es egy fuggetlen, append-only
// szolgaltatasban (Rekor / RFC 3161 TSA / OpenTimestamps) horgonyozzuk le. Minden
// receipt kap egy inclusion proof-ot, az egymast koveto fa-fejek kozott pedig
// consistency proof bizonyitja, hogy az ujabb fa a regi append-only bovitese.
//
// A hashing PONTOSAN az RFC 6962 szabalyait koveti (domain separation: 0x00 a
// leveleknel, 0x01 a belso csomoknal; a split a legnagyobb 2-hatvany n alatt),
// igy a fa byte-kompatibilis a letezo CT/Rekor verifikalokkal.
// ═══════════════════════════════════════════════════════════════════════════════

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

// "sha256:hex" <-> Buffer konverziok. A receiptekben minden hash string-kent el.
function _sha256Bytes(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function _toHashStr(buf) { return 'sha256:' + buf.toString('hex'); }
function _fromHashStr(s) {
  if (Buffer.isBuffer(s)) return s;
  return Buffer.from(String(s).replace(/^sha256:/, ''), 'hex');
}

// ── Level- es csomo-hash (RFC 6962 domain separation) ──────────────────────────
// A level bemenete a TELJES alairt receipt kanonikus bajtjai, a volatilis mezok
// (anchor_ref, redactable detail) NELKUL - igy a horgonyzas es a kesobbi redakcio
// sem valtoztatja meg a level-hasht, tehat a mar kiadott inclusion proof tovabb el.
function leafInputBytes(receipt) {
  const clone = { ...receipt };
  delete clone.anchor_ref;
  delete clone.redactable;
  return Buffer.from(canonicalize(clone), 'utf8');
}
function leafHash(receipt) {
  return _toHashStr(_sha256Bytes(Buffer.concat([LEAF_PREFIX, leafInputBytes(receipt)])));
}
function nodeHash(left, right) {
  return _toHashStr(_sha256Bytes(Buffer.concat([NODE_PREFIX, _fromHashStr(left), _fromHashStr(right)])));
}

// A legnagyobb 2-hatvany, ami szigoruan kisebb n-nel (RFC 6962 split pont).
function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// ── Merkle Tree Hash (RFC 6962) egy level-hash tomb felett ─────────────────────
// Bemenet: level-hash string-ek tombje. n==1 -> a level-hash maga a gyoker.
//
// Implementacio: indextartomany-alapu rekurzio (NEM slice). A korabbi valtozat
// minden szinten uj tombot masolt (O(n log n) memoria-churn); ez a [lo,hi)
// felfele adott tomb felett dolgozik, igy O(log n) verem es nulla masolas mellett
// BYTE-AZONOS gyokeret ad (ugyanaz az RFC 6962 split: a legnagyobb 2-hatvany n
// alatt). A cross-impl byte-vektorok (axr-canonical/crossverify) ezt orzik.
function _mthRange(leaves, lo, hi) {
  const n = hi - lo;
  if (n === 0) return _toHashStr(_sha256Bytes(Buffer.alloc(0)));
  if (n === 1) return leaves[lo];
  const k = largestPowerOfTwoLessThan(n);
  return nodeHash(_mthRange(leaves, lo, lo + k), _mthRange(leaves, lo + k, hi));
}
function _mth(leafHashes) {
  return _mthRange(leafHashes, 0, leafHashes.length);
}

// Gyoker egy receipt-tomb felett (a leveleket maga szamolja).
function merkleRoot(receipts) {
  return _mth(receipts.map(leafHash));
}
// Gyoker mar kiszamolt level-hash-ek felett.
function merkleRootFromLeaves(leafHashes) {
  return _mthRange(leafHashes, 0, leafHashes.length);
}

// ── Inkrementalis Merkle (MMR / CT-stilus, RFC 6962-kompatibilis) ──────────────
// Az RFC 6962 fa balrol jobbra perfekt reszfakra ("peaks") bomlik, melyek meretei
// n binaris alakjat koevetik (legnagyobb balra). Egy uj level hozzaadasa egy
// binaris-szamlalo-szeru osszevonas: O(log n) muvelet es O(log n) tarolas - nem
// kell minden horgonyzaskor a teljes fat nullarol ujraszamolni.
//
// A gyoker (mmrRoot) a peakeket JOBBROL hajtja ossze, ami pontosan az RFC 6962
// MTH rekurzio (nodeHash(MTH(k), MTH(n-k)), k = legnagyobb 2-hatvany < n). Ezert
// mmrRoot BYTE-AZONOS a merkleRootFromLeaves-szel MINDEN n-re (nem csak 2-hatvany
// hatarokon). Ezt az axr-incremental-test.js n=1..40-ig bizonyitja.
//
// Egy peak: { hash, size }, ahol size mindig 2-hatvany. A peaks tomb balrol
// (legregebbi/legnagyobb) jobbra (legujabb/legkisebb) rendezett, JSON-szerializalhato.
function mmrAppend(peaks, leafHashStr) {
  const out = peaks.slice();
  let cur = { hash: leafHashStr, size: 1 };
  while (out.length && out[out.length - 1].size === cur.size) {
    const left = out.pop();
    cur = { hash: nodeHash(left.hash, cur.hash), size: left.size * 2 };
  }
  out.push(cur);
  return out;
}
function mmrRoot(peaks) {
  if (!peaks.length) return _toHashStr(_sha256Bytes(Buffer.alloc(0)));
  let acc = peaks[peaks.length - 1].hash;
  for (let i = peaks.length - 2; i >= 0; i--) acc = nodeHash(peaks[i].hash, acc);
  return acc;
}
// Egy peaks-allapot strukturalis ervenyessege egy adott levelszamhoz: a meretek
// 2-hatvanyok, szigoruan csokkenok, es osszeguk a deklaralt levelszam. Ezzel egy
// serult/hamis cache (pl. leaf_count=999, peaks=[]) olcson (O(log n)) kiszurheto,
// a teljes fa ujraszamolasa nelkul.
function mmrValid(peaks, leafCount) {
  if (!Array.isArray(peaks) || !Number.isInteger(leafCount) || leafCount < 0) return false;
  let sum = 0, prev = Infinity;
  for (const p of peaks) {
    if (!p || typeof p.hash !== 'string' || !Number.isInteger(p.size) || p.size < 1) return false;
    if ((p.size & (p.size - 1)) !== 0) return false; // 2-hatvany?
    if (p.size >= prev) return false;                // szigoruan csokkeno?
    prev = p.size; sum += p.size;
  }
  return sum === leafCount;
}

// ── Inclusion proof generalas (RFC 6962 PATH) ──────────────────────────────────
// Visszaadja a testver-hashek listajat a leveltol a gyokerig (string-tomb).
// Indextartomany-alapu (slice nelkul), a gyoker-szamolassal azonos split-logikaval.
function inclusionProof(index, leafHashes) {
  const out = [];
  function rec(i, lo, hi) {
    const n = hi - lo;
    if (n <= 1) return;
    const k = largestPowerOfTwoLessThan(n);
    if (i < k) { rec(i, lo, lo + k); out.push(_mthRange(leafHashes, lo + k, hi)); }
    else       { rec(i - k, lo + k, hi); out.push(_mthRange(leafHashes, lo, lo + k)); }
  }
  rec(index, 0, leafHashes.length);
  return out;
}

// ── Inclusion proof ellenorzes - gyoker visszaszamolasa (CT iterativ algoritmus)
// Ezt barmely auditor lefuttathatja: level-hash + index + fa-meret + proof -> gyoker.
function rootFromInclusionProof(leafHashStr, index, treeSize, proofStrs) {
  if (index < 0 || index >= treeSize) throw new Error('index a fa hatarain kivul');
  let fn = index, sn = treeSize - 1;
  let r = leafHashStr;
  for (const p of proofStrs) {
    if (sn === 0) throw new Error('inclusion proof tul hosszu');
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        do { fn >>= 1; sn >>= 1; } while ((fn & 1) === 0 && fn !== 0);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  if (sn !== 0) throw new Error('inclusion proof tul rovid');
  return r;
}
function verifyInclusion(leafHashStr, index, treeSize, proofStrs, expectedRootStr) {
  try {
    return rootFromInclusionProof(leafHashStr, index, treeSize, proofStrs) === expectedRootStr;
  } catch (e) { return false; }
}

// ── Consistency proof generalas (RFC 6962 SUBPROOF) ────────────────────────────
// Bizonyitja, hogy az elso m level egy korabbi fa, amit az n-meretu fa
// append-only modon bovit. Bemenet: level-hash tomb (n elem) + m.
function consistencyProof(m, leafHashes) {
  const n = leafHashes.length;
  if (m <= 0 || m > n) throw new Error('ervenytelen m a consistency proof-hoz');
  if (m === n) return [];
  const out = [];
  // [lo,hi) felfele, slice nelkul; a logika 1:1 az RFC 6962 SUBPROOF-jal.
  function sub(mm, lo, hi, onPath) {
    const nn = hi - lo;
    if (mm === nn) { if (!onPath) out.push(_mthRange(leafHashes, lo, hi)); return; }
    const k = largestPowerOfTwoLessThan(nn);
    if (mm <= k) { sub(mm, lo, lo + k, onPath); out.push(_mthRange(leafHashes, lo + k, hi)); }
    else         { sub(mm - k, lo + k, hi, false); out.push(_mthRange(leafHashes, lo, lo + k)); }
  }
  sub(m, 0, n, true);
  return out;
}

// ── Consistency proof ellenorzes (CT iterativ algoritmus) ──────────────────────
// Igaz, ha a regi (m-meretu, oldRoot) fa az uj (n-meretu, newRoot) fa prefixe.
function verifyConsistency(m, n, oldRootStr, newRootStr, proofStrs) {
  if (m < 0 || n < m) return false;
  if (m === n) return proofStrs.length === 0 && oldRootStr === newRootStr;
  if (m === 0) return proofStrs.length === 0;

  let node = m - 1, lastNode = n - 1;
  while (node & 1) { node >>= 1; lastNode >>= 1; }

  let p = 0, oldHash, newHash;
  if (node) {
    if (p >= proofStrs.length) return false;
    oldHash = newHash = proofStrs[p++];
  } else {
    oldHash = newHash = oldRootStr;
  }
  while (node) {
    if (node & 1) {
      if (p >= proofStrs.length) return false;
      const h = proofStrs[p++];
      oldHash = nodeHash(h, oldHash);
      newHash = nodeHash(h, newHash);
    } else if (node < lastNode) {
      if (p >= proofStrs.length) return false;
      newHash = nodeHash(newHash, proofStrs[p++]);
    }
    node >>= 1; lastNode >>= 1;
  }
  while (lastNode) {
    if (p >= proofStrs.length) return false;
    newHash = nodeHash(newHash, proofStrs[p++]);
    lastNode >>= 1;
  }
  return p === proofStrs.length && oldHash === oldRootStr && newHash === newRootStr;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.4 - Redactable mezok (GDPR Art. 17 torles vs append-only feloldasa)
// ═══════════════════════════════════════════════════════════════════════════════
// Az erzekeny (potencialisan szemelyes adatot tartalmazo) mezoket - tipikusan a
// generativ prompt/completion cleartext - NEM kozvetlenul irjuk ala, hanem egy
// mezo-szintu Merkle-fan keresztul commitoljuk. A receipt alairt resze csak a fa
// GYOKERET (redactable_root) tartalmazza; a cleartext reszlet (redactable.fields)
// kimarad az alairasbol, a lanc-hashbol es a level-hashbol (lasd _stripVolatile).
//
// Kovetkezmeny: egy mezo cleartextje KESOBB TOROLHETO (a value+salt eldobasaval,
// a leaf_hash megtartasaval) anelkul, hogy az alairas, a lanc vagy a mar
// lehorgonyzott inclusion proof eltorne. A commitment (leaf_hash a gyoker alatt)
// megmarad, de a tartalom valoban eltunik.
//
// Minden mezo SOZOTT: leaf = sha256({p:path, s:salt, v:value}). A so miatt egy
// torolt mezo leaf_hash-ebol NEM lehet brute-force-szal visszafejteni a rovid
// erteket - ez a kulcs elony a sima (sotlan) tartalom-hashhez kepest.
// ═══════════════════════════════════════════════════════════════════════════════

// Egy mezo sozott level-hash-e.
function redactableLeaf(fieldPath, salt, value) {
  return sha256({ p: fieldPath, s: salt, v: value });
}

// Redactable blokk epitese mezokbol. fields: [{ path, value }]
// -> { redactable_root, redactable: { fields: [{ path, salt, value, leaf_hash }] } }
function buildRedactable(fields) {
  const out = (fields || []).map(f => {
    const salt = crypto.randomBytes(16).toString('base64');
    return { path: f.path, salt, value: f.value, leaf_hash: redactableLeaf(f.path, salt, f.value) };
  });
  const root = out.length ? merkleRootFromLeaves(out.map(f => f.leaf_hash)) : sha256(null);
  return { redactable_root: root, redactable: { fields: out } };
}

// Egy mezo cleartextjenek torlese: value+salt eldobasa, leaf_hash megtartasa.
// A receipt alairasa/lanca/level-hashe valtozatlan marad (a detail kimarad ezekbol).
function redactField(receipt, fieldPath) {
  const clone = JSON.parse(JSON.stringify(receipt));
  if (!clone.redactable || !Array.isArray(clone.redactable.fields)) return clone;
  for (const f of clone.redactable.fields) {
    if (f.path === fieldPath) { delete f.value; delete f.salt; f.redacted = true; }
  }
  return clone;
}

// Redactable commitment ellenorzese.
//   - a mezok leaf_hash-eibol ujraszamolt gyoker == redactable_root (ez koti az
//     alairashoz, mert a redactable_root alairt)
//   - minden JELENLEVO (nem torolt) mezo erteke egyezik a sajat sozott leaf_hash-evel
//   - torolt mezonel a commitment all, cleartext nelkul
// -> { ok, problems, applicable }
function verifyRedactable(receipt) {
  const problems = [];
  if (!receipt || !('redactable_root' in receipt)) return { ok: true, problems, applicable: false };
  const block = receipt.redactable;
  if (!block || !Array.isArray(block.fields)) {
    return { ok: true, problems: ['redactable_root jelen van, de a detail hianyzik - a commitment lokalisan nem ellenorizheto'],
             applicable: true, detailAbsent: true };
  }
  const root = block.fields.length ? merkleRootFromLeaves(block.fields.map(f => f.leaf_hash)) : sha256(null);
  if (root !== receipt.redactable_root)
    problems.push('a mezok leaf_hash-eibol szamolt gyoker nem egyezik a redactable_root-tal');
  for (const f of block.fields) {
    if (f.redacted || f.value === undefined) continue;
    if (redactableLeaf(f.path, f.salt, f.value) !== f.leaf_hash)
      problems.push(`mezo "${f.path}": az ertek nem egyezik a commitolt (sozott) leaf_hash-evel`);
  }
  return { ok: problems.length === 0, problems, applicable: true };
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.4 - Side-effect attestation (N1 mitigacio: "az operator a sajatjat irja ala")
// ═══════════════════════════════════════════════════════════════════════════════
// Az anchoring idot/sorrendet bizonyit, igazsagot nem (N1). A side-effect
// attestation a receipt allitasat egy KULSO rendszer sajat rekordjahoz koti: a
// "Create Booking" lepes nem csak azt mondja "letrehoztam a foglalast", hanem
// rogziti a kulso rendszer sajat azonositojat (reference) es a valaszanak hashet
// (evidence_hash). Egy auditor ezt FUGGETLENUL ujra le tudja kerdezni es osszevetni.
//
// Ket szint:
//   - recheckable (attestation nelkul): a kulso referencia + valasz-hash alapjan
//     egy auditor ujra-ellenorizheti. NEM onmagat bizonyito, de fuggetlenul
//     ellenorizheto - ez az oszinte N1-mersekles.
//   - attested (provider co-sign): ha a kulso szolgaltato sajat kulccsal alairja a
//     side-effect bejegyzest, az KRIPTOGRAFIAILAG koti az esemenyt egy az operatortol
//     fuggetlen felhez. (A kulcs->provider azonossag bootstrapje kulon kerdes, lasd §8.)
//
// A side_effects mezo az ALAIRT receipt resze (a leaf/lanc/alairas fedi), ezert
// onmagaban tamper-evidens; az attestation ezen FELUL provider-szinten is verifikal.

// Egy side-effect bejegyzes provider-alairasa (co-sign). A providerPubPem belekerul
// az attestationbe, hogy az ellenorzes onellatu legyen.
function attestSideEffect(entry, providerPrivPem, providerPubPem) {
  const base = { ...entry };
  delete base.attestation;
  const sig = crypto.sign(null, Buffer.from(canonicalize(base), 'utf8'),
    crypto.createPrivateKey(providerPrivPem)).toString('base64');
  return { ...base, attestation: { algorithm: 'ed25519', public_key: providerPubPem, signature: sig } };
}

// Egy side-effect bejegyzes ellenorzese: strukturalis + (ha van) provider-alairas
// + (ha van trustRoot) a kulcs->provider azonossag kotese.
//
// trustRoot (opcionalis): egy MAR VERIFIKALT trust-root objektum (lasd
// verifyTrustRoot / loadTrustRoot). Ha at van adva:
//   - egy attestation csak akkor szamit "attested"-nek, ha a benne levo
//     public_key szerepel a trust-root providerhez (entry.provider) tartozo
//     kulcs-listajaban. Kulonben PROBLEMA ("a kulcs nincs a trust-rootban") -
//     ez zarja le az N1 lyukat: az operator nem nevezheti sajat kulcsat
//     'google-calendar'-nak, mert az nincs a fuggetlenul alairt allowlistben.
// Ha trustRoot NINCS atadva, a viselkedes valtozatlan (0.4 eredeti): az
// attestation strukturalis+alairas-szinten verifikal, de a kulcs->provider
// kotes nem ellenorzott (ezt a verifier notice-ban jelzi).
// -> { ok, problems, attested }
function verifySideEffect(entry, trustRoot) {
  const problems = [];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { ok: false, problems: ['a side-effect bejegyzes nem objektum'], attested: false };
  }
  for (const f of ['type', 'provider', 'reference']) {
    if (typeof entry[f] !== 'string' || !entry[f]) problems.push(`hianyzo/ures mezo: ${f}`);
  }
  const eh = entry.evidence_hash === undefined ? null : entry.evidence_hash;
  if (!(eh === null || (typeof eh === 'string' && /^sha256:[0-9a-f]{64}$/.test(eh)))) {
    problems.push('evidence_hash rossz formatumu (sha256:... vagy null)');
  }
  let attested = false;
  if (entry.attestation) {
    const a = entry.attestation;
    if (a.algorithm !== 'ed25519' || !a.public_key || !a.signature) {
      problems.push('attestation hianyos (algorithm/public_key/signature)');
    } else {
      const base = { ...entry }; delete base.attestation;
      try {
        const ok = crypto.verify(null, Buffer.from(canonicalize(base), 'utf8'),
          crypto.createPublicKey(a.public_key), Buffer.from(a.signature, 'base64'));
        if (!ok) problems.push('a provider-attestation alairasa ERVENYTELEN');
        else attested = true;
      } catch (e) { problems.push('attestation ellenorzes hiba: ' + e.message); }
    }
    // trust-root kotes: a kulcs valoban a providerhez tartozik-e
    if (attested && trustRoot) {
      if (!trustRootHasKey(trustRoot, entry.provider, a.public_key)) {
        problems.push(`az attestation kulcsa NINCS a trust-rootban a(z) "${entry.provider}" providerhez ` +
          `- az "attested" allitas nem megbizhato (lehet operator-onattesztacio)`);
        attested = false;
      }
    }
  }
  return { ok: problems.length === 0, problems, attested };
}

// Egy publikus kulcs (PEM) provider-tagsaganak ellenorzese egy verifikalt
// trust-rootban. A kulcsokat normalizaltan (whitespace-mentesen) hasonlitjuk,
// hogy a PEM sortores-kulonbsegek ne okozzanak false negative-et.
function _normalizePem(pem) {
  return String(pem).replace(/\s+/g, '');
}
function trustRootHasKey(trustRoot, provider, publicKeyPem) {
  if (!trustRoot || !Array.isArray(trustRoot.providers)) return false;
  const want = _normalizePem(publicKeyPem);
  const p = trustRoot.providers.find(x => x && x.provider === provider);
  if (!p || !Array.isArray(p.public_keys)) return false;
  return p.public_keys.some(k => _normalizePem(k) === want);
}

// ═══════════════════════════════════════════════════════════════════════════════
// 0.4 - Trust root (a side-effect attestation kulcs->provider azonossag bootstrap)
// ═══════════════════════════════════════════════════════════════════════════════
// A trust-root egy ONALLO, root-kulccsal alairt dokumentum, ami provider-nevekhez
// rendel megengedett provider-publikuskulcsokat. Az alairas megakadalyozza, hogy
// barki utolag bovitse vagy atirja. A root-kulcs az operatortol FUGGETLEN fel
// (pl. egy auditor, egy konzorcium, vagy egy publikalt allowlist) tulajdonaban
// all - ez teszi a kulcs->provider kotest megbizhatova (§8 lezarasa).
//
// Alak:
//   { axr_version, record_type: 'trust_root', issued_at, root_public_key,
//     providers: [ { provider, public_keys: [pem, ...] }, ... ], signature }
// Az alairas a 'signature' mezo NELKULI kanonikus format fedi.

function buildTrustRoot(providers, rootPrivPem, rootPubPem, now) {
  const body = {
    axr_version: '0.4',
    record_type: 'trust_root',
    issued_at: (now || (() => new Date().toISOString()))(),
    root_public_key: rootPubPem,
    providers: (providers || []).map(p => ({
      provider: p.provider,
      public_keys: (p.public_keys || []).slice()
    }))
  };
  const sig = crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'),
    crypto.createPrivateKey(rootPrivPem)).toString('base64');
  return { ...body, signature: sig };
}

// A trust-root onellenorzese: a sajat root_public_key-evel verifikal-e az alairas.
// (A root-kulcs hitelet a kulso vilag adja - publikalas, tanusitvany, stb.; itt a
// dokumentum INTEGRITASAT ellenorizzuk, hogy utolag ne lehessen bovitni.)
// -> { ok, problems }
function verifyTrustRoot(trustRoot) {
  const problems = [];
  if (!trustRoot || typeof trustRoot !== 'object') return { ok: false, problems: ['nem objektum'] };
  if (trustRoot.record_type !== 'trust_root') problems.push('record_type != trust_root');
  if (!trustRoot.root_public_key) problems.push('hianyzo root_public_key');
  if (!Array.isArray(trustRoot.providers)) problems.push('a providers nem tomb');
  if (!trustRoot.signature) problems.push('hianyzo signature');
  if (problems.length) return { ok: false, problems };
  const body = { ...trustRoot }; delete body.signature;
  try {
    const ok = crypto.verify(null, Buffer.from(canonicalize(body), 'utf8'),
      crypto.createPublicKey(trustRoot.root_public_key),
      Buffer.from(trustRoot.signature, 'base64'));
    if (!ok) problems.push('a trust-root alairasa ERVENYTELEN (a root-kulccsal nem verifikal)');
  } catch (e) { problems.push('trust-root alairas-ellenorzes hiba: ' + e.message); }
  return { ok: problems.length === 0, problems };
}

module.exports = {
  AXR_VERSION,
  AXR_INPUT_KEY,
  AXR_GEN_KEY,
  canonicalize,
  sha256,
  versionAtLeast,
  signablePart,
  chainHash,
  signReceipt,
  verifyReceipt,
  uuid,
  customerRef,
  splitAxrInput,
  splitAxrGen,
  buildGeneration,
  // 0.3 Merkle / anchoring
  leafHash,
  nodeHash,
  largestPowerOfTwoLessThan,
  merkleRoot,
  merkleRootFromLeaves,
  mmrAppend,
  mmrRoot,
  mmrValid,
  inclusionProof,
  rootFromInclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
  // 0.4 redactable mezok
  redactableLeaf,
  buildRedactable,
  redactField,
  verifyRedactable,
  // 0.4 side-effect attestation
  attestSideEffect,
  verifySideEffect,
  // 0.4 trust root (kulcs->provider azonossag)
  buildTrustRoot,
  verifyTrustRoot,
  trustRootHasKey
};
