#!/usr/bin/env node
// sbom-lite: a CycloneDX SBOM from a package-lock.json, with nothing to install.
// Plain Node 22, built-in modules only. See README.md for the exact rules.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { resolve } from 'node:path';

const TOOL = { author: 'Tick Group', name: 'sbom-lite', version: '0.1.0' };

const USAGE =
  'usage: sbom-lite [lockfile] [--include-dev] [--now <time>] [--out <file>] [--spec 1.5|1.4] [--random-serial]';

const LICENSE_IDS = new Set([
  '0BSD', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-2.0', 'Artistic-2.0',
  'BlueOak-1.0.0', 'BSD-2-Clause', 'BSD-3-Clause', 'CC-BY-3.0', 'CC-BY-4.0',
  'CC0-1.0', 'EPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only',
  'GPL-3.0-or-later', 'ISC', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0-only', 'LGPL-3.0-or-later', 'MIT', 'MIT-0', 'MPL-2.0', 'Python-2.0',
  'Unlicense', 'WTFPL', 'Zlib',
]);

const HASH_ALGS = {
  sha512: { name: 'SHA-512', bytes: 64 },
  sha384: { name: 'SHA-384', bytes: 48 },
  sha256: { name: 'SHA-256', bytes: 32 },
  sha1: { name: 'SHA-1', bytes: 20 },
};

class UsageError extends Error {}
class InputError extends Error {}

// ---------------------------------------------------------------- arguments

function parseTime(text) {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|[+-]\d{2}:\d{2})?)?$/.exec(text);
  if (!m) return null;
  const [, ys, mos, ds, hs, mis, ss, fs, zone] = m;
  const year = Number(ys), month = Number(mos), day = Number(ds);
  const hour = hs === undefined ? 0 : Number(hs);
  const minute = mis === undefined ? 0 : Number(mis);
  const second = ss === undefined ? 0 : Number(ss);
  const ms = fs === undefined ? 0 : Number(fs.padEnd(3, '0'));
  if (year < 1970 || year > 2999) return null;
  if (month < 1 || month > 12) return null;
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (day < 1 || day > dim) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  let offsetMinutes = 0;
  if (zone && zone !== 'Z') {
    const oh = Number(zone.slice(1, 3)), om = Number(zone.slice(4, 6));
    if (oh > 23 || om > 59) return null;
    offsetMinutes = (zone[0] === '-' ? -1 : 1) * (oh * 60 + om);
  }
  const t = Date.UTC(year, month - 1, day, hour, minute, second, ms) - offsetMinutes * 60000;
  return new Date(t).toISOString();
}

function parseArgs(argv) {
  const opts = {
    lockfile: null, includeDev: false, timestamp: null, out: null, spec: '1.5', randomSerial: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--include-dev': opts.includeDev = true; break;
      case '--random-serial': opts.randomSerial = true; break;
      case '--now':
      case '--out':
      case '--spec': {
        if (i + 1 >= argv.length) throw new UsageError(`option ${a} needs a value`);
        const v = argv[++i];
        if (a === '--out') opts.out = v;
        else if (a === '--spec') {
          if (v !== '1.5' && v !== '1.4') throw new UsageError(`--spec must be 1.5 or 1.4, not "${v}"`);
          opts.spec = v;
        } else {
          const ts = parseTime(v);
          if (ts === null) {
            throw new UsageError(`--now is not a valid time: "${v}" (use YYYY-MM-DD, YYYY-MM-DDTHH:MM[:SS[.fff]] with optional Z or +HH:MM)`);
          }
          opts.timestamp = ts;
        }
        break;
      }
      default:
        if (a.startsWith('-')) throw new UsageError(`unknown option: ${a}`);
        if (opts.lockfile !== null) throw new UsageError(`more than one lock file given: "${opts.lockfile}" and "${a}"`);
        opts.lockfile = a;
    }
  }
  return opts;
}

// ---------------------------------------------------------------- helpers

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const isNonEmptyString = (v) => typeof v === 'string' && v.length > 0;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function serialFromBytes(bytes) {
  const b = createHash('sha256').update(bytes).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x80;
  b[8] = (b[8] & 0x3f) | 0x80;
  return formatUuid(b);
}

function randomSerial() {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return formatUuid(b);
}

function formatUuid(b) {
  const h = Buffer.from(b).toString('hex');
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function percentEncode(text) {
  let out = '';
  for (const byte of Buffer.from(text, 'utf8')) {
    if ((byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || (byte >= 0x30 && byte <= 0x39) ||
        byte === 0x2e || byte === 0x2d || byte === 0x5f || byte === 0x7e) {
      out += String.fromCharCode(byte);
    } else {
      out += '%' + byte.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}

function splitName(full) {
  if (full.startsWith('@')) {
    const slash = full.indexOf('/');
    if (slash >= 1) return { group: full.slice(0, slash), name: full.slice(slash + 1) };
  }
  return { group: undefined, name: full };
}

function makePurl(group, name, version) {
  return 'pkg:npm/' + (group !== undefined ? percentEncode(group) + '/' : '') + percentEncode(name) +
    (version !== undefined ? '@' + percentEncode(version) : '');
}

// Index of the last "node_modules/" that starts a path segment of the key, or -1.
function lastModulesIndex(key) {
  let i = key.lastIndexOf('node_modules/');
  while (i > 0 && key[i - 1] !== '/') i = key.lastIndexOf('node_modules/', i - 1);
  return i;
}

function hashesOf(integrity) {
  if (typeof integrity !== 'string') return undefined;
  const hashes = [];
  const seen = new Set();
  for (const token of integrity.split(/\s+/)) {
    const m = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/]+={0,2})(?:\?[^]*)?$/.exec(token);
    if (!m) continue;
    const alg = HASH_ALGS[m[1]];
    const bytes = Buffer.from(m[2], 'base64');
    if (bytes.length !== alg.bytes || bytes.toString('base64') !== m[2]) continue;
    if (seen.has(m[1])) continue;
    seen.add(m[1]);
    hashes.push({ alg: alg.name, content: bytes.toString('hex') });
  }
  return hashes.length ? hashes : undefined;
}

function licensesOf(license) {
  if (typeof license !== 'string') return undefined;
  const text = license.trim();
  if (text === '') return undefined;
  return [{ license: LICENSE_IDS.has(text) ? { id: text } : { name: text } }];
}

// ---------------------------------------------------------------- the lock file

function readLock(file) {
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (e) {
    throw new InputError(`cannot read ${file}: ${e.code || e.message}`);
  }
  let lock;
  try {
    let text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    lock = JSON.parse(text);
  } catch (e) {
    throw new InputError(`${file} is not valid JSON: ${e.message}`);
  }
  if (!isObject(lock) || (lock.lockfileVersion !== 2 && lock.lockfileVersion !== 3) || !isObject(lock.packages)) {
    throw new InputError(`${file} is not supported: sbom-lite reads package-lock.json with lockfileVersion 2 or 3 and a "packages" object`);
  }
  return { bytes, lock };
}

function buildDocument(lock, bytes, opts) {
  const packages = new Map(Object.entries(lock.packages));

  const isCandidate = (key) => {
    const e = packages.get(key);
    if (!isObject(e) || e.link === true || !isNonEmptyString(e.version)) return false;
    const i = lastModulesIndex(key);
    return i >= 0 && key.length > i + 13;
  };

  // components
  const comps = [];
  for (const [key, e] of packages) {
    if (!isCandidate(key)) continue;
    if (e.dev === true && !opts.includeDev) continue;
    const i = lastModulesIndex(key);
    const full = isNonEmptyString(e.name) ? e.name : key.slice(i + 13);
    const { group, name } = splitName(full);
    comps.push({ key, e, full, group, name, version: e.version, purl: makePurl(group, name, e.version) });
  }
  comps.sort((a, b) => cmp(a.full, b.full) || cmp(a.version, b.version) || cmp(a.key, b.key));

  const purlCount = new Map();
  for (const c of comps) purlCount.set(c.purl, (purlCount.get(c.purl) || 0) + 1);
  const refByKey = new Map();
  for (const c of comps) {
    c.ref = purlCount.get(c.purl) > 1 ? `${c.purl}#${c.key}` : c.purl;
    refByKey.set(c.key, c.ref);
  }

  const resolveDep = (fromKey, name) => {
    let prefix = fromKey; // '' for the root package
    for (;;) {
      const k = (prefix === '' ? '' : prefix + '/') + 'node_modules/' + name;
      if (isCandidate(k)) return k;
      if (prefix === '') return null;
      const i = lastModulesIndex(prefix);
      if (i < 0) return null;
      prefix = i === 0 ? '' : prefix.slice(0, i - 1);
    }
  };

  const dependsOn = (fromKey, entry, extra) => {
    const names = [];
    for (const f of ['dependencies', 'optionalDependencies', 'peerDependencies', ...extra]) {
      if (isObject(entry[f])) names.push(...Object.keys(entry[f]));
    }
    const refs = new Set();
    for (const n of names) {
      const target = resolveDep(fromKey, n);
      if (target === null) continue;
      const ref = refByKey.get(target);
      if (ref === undefined || target === fromKey) continue;
      refs.add(ref);
    }
    return [...refs].sort(cmp);
  };

  // root
  const rootEntry = packages.has('') && isObject(packages.get('')) ? packages.get('') : {};
  const rootName = isNonEmptyString(rootEntry.name) ? rootEntry.name : isNonEmptyString(lock.name) ? lock.name : 'unnamed';
  const rootVersion = isNonEmptyString(rootEntry.version) ? rootEntry.version
    : isNonEmptyString(lock.version) ? lock.version : undefined;
  const rs = splitName(rootName);
  const rootComponent = { type: 'application', 'bom-ref': 'root' };
  if (rs.group !== undefined) rootComponent.group = rs.group;
  rootComponent.name = rs.name;
  if (rootVersion !== undefined) rootComponent.version = rootVersion;
  rootComponent.purl = makePurl(rs.group, rs.name, rootVersion);

  const components = comps.map((c) => {
    const o = { type: 'library', 'bom-ref': c.ref };
    if (c.group !== undefined) o.group = c.group;
    o.name = c.name;
    o.version = c.version;
    o.scope = c.e.dev === true || c.e.optional === true || c.e.devOptional === true ? 'optional' : 'required';
    const hashes = hashesOf(c.e.integrity);
    if (hashes) o.hashes = hashes;
    const licenses = licensesOf(c.e.license);
    if (licenses) o.licenses = licenses;
    o.purl = c.purl;
    if (typeof c.e.resolved === 'string' && /^https?:\/\//.test(c.e.resolved)) {
      o.externalReferences = [{ type: 'distribution', url: c.e.resolved }];
    }
    return o;
  });

  const dependencies = [{ ref: 'root', dependsOn: dependsOn('', rootEntry, opts.includeDev ? ['devDependencies'] : []) }];
  for (const c of comps) dependencies.push({ ref: c.ref, dependsOn: dependsOn(c.key, c.e, []) });

  const tools = opts.spec === '1.5'
    ? { components: [{ type: 'application', author: TOOL.author, name: TOOL.name, version: TOOL.version }] }
    : [{ vendor: TOOL.author, name: TOOL.name, version: TOOL.version }];

  return {
    bomFormat: 'CycloneDX',
    specVersion: opts.spec,
    serialNumber: opts.randomSerial ? randomSerial() : serialFromBytes(bytes),
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools,
      component: rootComponent,
    },
    components,
    dependencies,
  };
}

// ---------------------------------------------------------------- main

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    process.stderr.write(`sbom-lite: ${e.message}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  try {
    const { bytes, lock } = readLock(resolve(opts.lockfile ?? 'package-lock.json'));
    const text = JSON.stringify(buildDocument(lock, bytes, opts), null, 2) + '\n';
    if (opts.out !== null) {
      try {
        writeFileSync(resolve(opts.out), text);
      } catch (e) {
        throw new InputError(`cannot write ${opts.out}: ${e.code || e.message}`);
      }
    } else {
      process.stdout.write(text);
    }
  } catch (e) {
    if (!(e instanceof InputError)) throw e;
    process.stderr.write(`sbom-lite: ${e.message}\n`);
    process.exitCode = 1;
  }
}

main(process.argv.slice(2));
