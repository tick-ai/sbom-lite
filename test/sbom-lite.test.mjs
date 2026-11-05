import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const TOOL = fileURLToPath(new URL('../sbom-lite.mjs', import.meta.url));
const NOW = '2026-01-02T03:04:05Z';

function sandbox(files = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sbom-lite-'));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

function run(dir, args = []) {
  const r = spawnSync(process.execPath, [TOOL, ...args], { cwd: dir, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

// Runs the tool on `lock` (an object or string) in a fresh folder; removes the folder.
function gen(lock, args = [], extra = {}) {
  const text = typeof lock === 'string' ? lock : JSON.stringify(lock, null, 2);
  const dir = sandbox({ 'package-lock.json': text, ...extra });
  try {
    const r = run(dir, ['--now', NOW, ...args]);
    r.doc = r.code === 0 && r.out ? JSON.parse(r.out) : null;
    return r;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const lock3 = (packages, extra = {}) => ({ lockfileVersion: 3, packages, ...extra });
const names = (doc) => doc.components.map((c) => c['bom-ref']);

const EXAMPLE = `{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": { "@acme/core": "^2.0.0", "tiny": "^1.0.0" },
      "devDependencies": { "tester": "^3.0.0" }
    },
    "node_modules/@acme/core": {
      "version": "2.1.0",
      "resolved": "https://registry.npmjs.org/@acme/core/-/core-2.1.0.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
      "license": "MIT",
      "dependencies": { "tiny": "^1.2.0" }
    },
    "node_modules/@acme/core/node_modules/tiny": {
      "version": "1.2.0",
      "resolved": "https://registry.npmjs.org/tiny/-/tiny-1.2.0.tgz",
      "license": "ISC"
    },
    "node_modules/tiny": {
      "version": "1.0.1",
      "resolved": "https://registry.npmjs.org/tiny/-/tiny-1.0.1.tgz",
      "integrity": "sha1-AAECAwQFBgcICQoLDA0ODxAREhM=",
      "license": "Apache 2.0"
    },
    "node_modules/tester": {
      "version": "3.0.0",
      "dev": true,
      "license": "MIT"
    }
  }
}
`;

const TOOLS15 = { components: [{ type: 'application', author: 'Tick Group', name: 'sbom-lite', version: '0.1.0' }] };

const EXPECTED = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: 'urn:uuid:826911eb-c961-8c81-96da-0ad8da4fe168',
  version: 1,
  metadata: {
    timestamp: '2026-01-02T03:04:05.000Z',
    tools: TOOLS15,
    component: { type: 'application', 'bom-ref': 'root', name: 'demo', version: '1.0.0', purl: 'pkg:npm/demo@1.0.0' },
  },
  components: [
    {
      type: 'library', 'bom-ref': 'pkg:npm/%40acme/core@2.1.0', group: '@acme', name: 'core', version: '2.1.0',
      scope: 'required',
      hashes: [{ alg: 'SHA-512', content: 'bf690311ee7b95e713ba568322e3533f2dd1cb880b189e99d4edef13592b81764daec43e2c54c61d5c558dc5cfb35ecb85b65519e74026ff17675b6f8f916f4a' }],
      licenses: [{ license: { id: 'MIT' } }],
      purl: 'pkg:npm/%40acme/core@2.1.0',
      externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/@acme/core/-/core-2.1.0.tgz' }],
    },
    {
      type: 'library', 'bom-ref': 'pkg:npm/tiny@1.0.1', name: 'tiny', version: '1.0.1', scope: 'required',
      hashes: [{ alg: 'SHA-1', content: '000102030405060708090a0b0c0d0e0f10111213' }],
      licenses: [{ license: { name: 'Apache 2.0' } }],
      purl: 'pkg:npm/tiny@1.0.1',
      externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/tiny/-/tiny-1.0.1.tgz' }],
    },
    {
      type: 'library', 'bom-ref': 'pkg:npm/tiny@1.2.0', name: 'tiny', version: '1.2.0', scope: 'required',
      licenses: [{ license: { id: 'ISC' } }],
      purl: 'pkg:npm/tiny@1.2.0',
      externalReferences: [{ type: 'distribution', url: 'https://registry.npmjs.org/tiny/-/tiny-1.2.0.tgz' }],
    },
  ],
  dependencies: [
    { ref: 'root', dependsOn: ['pkg:npm/%40acme/core@2.1.0', 'pkg:npm/tiny@1.0.1'] },
    { ref: 'pkg:npm/%40acme/core@2.1.0', dependsOn: ['pkg:npm/tiny@1.2.0'] },
    { ref: 'pkg:npm/tiny@1.0.1', dependsOn: [] },
    { ref: 'pkg:npm/tiny@1.2.0', dependsOn: [] },
  ],
};

// ------------------------------------------------------------ the example

test('the job example prints exactly the documented bytes', () => {
  const r = gen(EXAMPLE);
  assert.equal(r.code, 0);
  assert.equal(r.err, '');
  assert.equal(r.out, JSON.stringify(EXPECTED, null, 2) + '\n');
});

test('the default lock file is package-lock.json in the current directory', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE });
  try {
    const r = run(dir, ['--now', NOW]);
    assert.equal(r.code, 0);
    assert.deepEqual(JSON.parse(r.out), EXPECTED);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the lock file can be named, relative or absolute; nothing is written beside it', () => {
  const dir = sandbox({ 'sub/other.json': EXAMPLE });
  try {
    const before = readdirSync(dir, { recursive: true }).sort();
    const a = run(dir, ['sub/other.json', '--now', NOW]);
    const b = run(dir, [join(dir, 'sub', 'other.json'), '--now', NOW]);
    assert.equal(a.code, 0);
    assert.equal(a.out, b.out);
    assert.deepEqual(readdirSync(dir, { recursive: true }).sort(), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('same input, same bytes; the order of the options does not matter', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE });
  try {
    const a = run(dir, ['--now', NOW, '--include-dev']);
    const b = run(dir, ['--include-dev', '--now', NOW]);
    assert.equal(a.out, b.out);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------ serial number

function expectedSerial(bytes) {
  const b = createHash('sha256').update(bytes).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x80;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

test('serial number is derived from the file bytes, whatever the options', () => {
  const text = JSON.stringify(lock3({}));
  const want = expectedSerial(Buffer.from(text));
  for (const args of [[], ['--include-dev'], ['--spec', '1.4']]) {
    assert.equal(gen(text, args).doc.serialNumber, want);
  }
  assert.match(want, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('the serial number is taken from the bytes before the BOM is removed', () => {
  const body = Buffer.from(JSON.stringify(lock3({})));
  const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), body]);
  const dir = sandbox();
  try {
    writeFileSync(join(dir, 'package-lock.json'), withBom);
    const r = run(dir, ['--now', NOW]);
    assert.equal(r.code, 0);
    assert.equal(JSON.parse(r.out).serialNumber, expectedSerial(withBom));
    assert.notEqual(expectedSerial(withBom), expectedSerial(body));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('--random-serial gives a version 4 UUID that differs between runs', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE });
  try {
    const seen = new Set();
    for (let i = 0; i < 3; i++) {
      const s = JSON.parse(run(dir, ['--random-serial']).out).serialNumber;
      assert.match(s, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      seen.add(s);
    }
    assert.equal(seen.size, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------ time

test('--now forms', () => {
  const cases = {
    '2026-03-04': '2026-03-04T00:00:00.000Z',
    '2026-03-04T05:06': '2026-03-04T05:06:00.000Z',
    '2026-03-04T05:06:07': '2026-03-04T05:06:07.000Z',
    '2026-03-04T05:06:07.5': '2026-03-04T05:06:07.500Z',
    '2026-03-04T05:06:07.12': '2026-03-04T05:06:07.120Z',
    '2026-03-04T05:06:07.123': '2026-03-04T05:06:07.123Z',
    '2026-03-04T05:06Z': '2026-03-04T05:06:00.000Z',
    '2026-03-04T05:06:07.5Z': '2026-03-04T05:06:07.500Z',
    '2026-03-04T05:06:07+02:30': '2026-03-04T02:36:07.000Z',
    '2026-03-04T01:00:00-03:00': '2026-03-04T04:00:00.000Z',
    '2026-01-01T00:30+01:00': '2025-12-31T23:30:00.000Z',
    '2024-02-29': '2024-02-29T00:00:00.000Z',
    '1970-01-01': '1970-01-01T00:00:00.000Z',
    '2999-12-31T23:59:59.999Z': '2999-12-31T23:59:59.999Z',
  };
  const dir = sandbox({ 'package-lock.json': JSON.stringify(lock3({})) });
  try {
    for (const [input, want] of Object.entries(cases)) {
      const r = run(dir, ['--now', input]);
      assert.equal(r.code, 0, input);
      assert.equal(JSON.parse(r.out).metadata.timestamp, want, input);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('invalid --now values are usage errors', () => {
  const bad = ['', 'now', '2026-02-30', '2025-02-29', '2026-13-01', '2026-00-10', '2026-01-00', '1969-12-31',
    '3000-01-01', '2026-01-01T24:00', '2026-01-01T12:60', '2026-01-01T12:00:60', '2026-01-01T12',
    '2026-01-01 12:00', '2026-01-01T12:00:00.', '2026-01-01T12:00:00.1234', '2026-01-01T12:00+24:00',
    '2026-01-01T12:00+01:60', '2026-01-01T12:00+0100', '2026-01-01Z', '2026-01-01+01:00', '2026-1-1',
    '2026-01-01T12:00:00z', ' 2026-01-01', '2026-01-01\n', '+002026-01-01'];
  const dir = sandbox({ 'package-lock.json': JSON.stringify(lock3({})) });
  try {
    for (const b of bad) {
      const r = run(dir, ['--now', b]);
      assert.equal(r.code, 2, JSON.stringify(b));
      assert.equal(r.out, '');
      assert.notEqual(r.err, '');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('without --now the clock is used', () => {
  const dir = sandbox({ 'package-lock.json': JSON.stringify(lock3({})) });
  try {
    const t0 = Date.now();
    const doc = JSON.parse(run(dir, []).out);
    const t = Date.parse(doc.metadata.timestamp);
    assert.match(doc.metadata.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    assert.ok(t >= t0 - 1000 && t <= Date.now() + 1000);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------ spec

test('--spec 1.4 changes specVersion and the tools form only', () => {
  const a = gen(EXAMPLE).doc;
  const b = gen(EXAMPLE, ['--spec', '1.4']).doc;
  assert.equal(b.specVersion, '1.4');
  assert.deepEqual(b.metadata.tools, [{ vendor: 'Tick Group', name: 'sbom-lite', version: '0.1.0' }]);
  assert.deepEqual(Object.keys(b.metadata.tools[0]), ['vendor', 'name', 'version']);
  a.specVersion = '1.4';
  a.metadata.tools = b.metadata.tools;
  assert.deepEqual(a, b);
  assert.deepEqual(gen(EXAMPLE, ['--spec', '1.5']).doc, EXPECTED);
});

test('other --spec values are usage errors', () => {
  for (const v of ['1.6', '1.3', '1', '1.50', '', 'x', '1.5 ']) {
    const r = gen(EXAMPLE, ['--spec', v]);
    assert.equal(r.code, 2, JSON.stringify(v));
    assert.equal(r.out, '');
  }
});

// ------------------------------------------------------------ usage errors

test('usage errors: message on stderr, nothing on stdout, status 2, no file', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE, 'b.json': EXAMPLE });
  try {
    const cases = [
      ['--bogus'], ['-x'], ['-'], ['--now=2026-01-01'], ['--help'], ['--out'], ['--now'], ['--spec'],
      ['--out', 'o.json', '--spec'], ['a.json', 'b.json'], ['package-lock.json', 'b.json'],
      ['--spec', '9'], ['--now', 'bad', '--out', 'o.json'], ['--out', 'o.json', '--bogus'],
    ];
    for (const args of cases) {
      const r = run(dir, args);
      assert.equal(r.code, 2, args.join(' '));
      assert.equal(r.out, '', args.join(' '));
      assert.notEqual(r.err, '', args.join(' '));
      assert.equal(existsSync(join(dir, 'o.json')), false, args.join(' '));
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('arguments are checked before any file is read (missing file + usage error is 2)', () => {
  const dir = sandbox();
  try {
    assert.equal(run(dir, ['missing.json', '--bogus']).code, 2);
    assert.equal(run(dir, ['missing.json', '--spec', '2']).code, 2);
    assert.equal(run(dir, ['missing.json']).code, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an option takes the next argument, whatever it looks like', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE });
  try {
    const r = run(dir, ['--out', '--include-dev', '--now', NOW]);
    assert.equal(r.code, 0);
    assert.equal(r.out, '');
    const doc = JSON.parse(readFileSync(join(dir, '--include-dev'), 'utf8'));
    assert.equal(doc.components.length, 3, 'dev stays out: --include-dev was a value');
    const bad = run(dir, ['--now', '--include-dev']);
    assert.equal(bad.code, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------ --out and exit 1

test('--out writes the same bytes to a file and prints nothing', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE });
  try {
    const stdout = run(dir, ['--now', NOW]).out;
    const r = run(dir, ['--now', NOW, '--out', 'bom.json']);
    assert.equal(r.code, 0);
    assert.equal(r.out, '');
    assert.equal(r.err, '');
    assert.equal(readFileSync(join(dir, 'bom.json'), 'utf8'), stdout);
    // replaced, absolute path
    writeFileSync(join(dir, 'bom.json'), 'old');
    const abs = join(dir, 'bom.json');
    assert.equal(run(dir, ['--now', NOW, '--out', abs]).code, 0);
    assert.equal(readFileSync(abs, 'utf8'), stdout);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('--out into a missing folder or onto a folder exits 1, nothing on stdout', () => {
  const dir = sandbox({ 'package-lock.json': EXAMPLE });
  try {
    mkdirSync(join(dir, 'adir'));
    for (const out of ['nope/bom.json', 'adir']) {
      const r = run(dir, ['--out', out]);
      assert.equal(r.code, 1);
      assert.equal(r.out, '');
      assert.notEqual(r.err, '');
    }
    assert.equal(existsSync(join(dir, 'nope')), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('unreadable, unparsable and unsupported lock files exit 1 with nothing on stdout or in --out', () => {
  const bad = {
    'not json': '{ nope',
    empty: '',
    'array top level': '[]',
    'null': 'null',
    'version 1': JSON.stringify({ lockfileVersion: 1, dependencies: {} }),
    'version 4': JSON.stringify({ lockfileVersion: 4, packages: {} }),
    'version as string': JSON.stringify({ lockfileVersion: '3', packages: {} }),
    'no version': JSON.stringify({ packages: {} }),
    'no packages': JSON.stringify({ lockfileVersion: 3 }),
    'packages null': JSON.stringify({ lockfileVersion: 3, packages: null }),
    'packages array': JSON.stringify({ lockfileVersion: 2, packages: [] }),
  };
  for (const [what, text] of Object.entries(bad)) {
    const dir = sandbox({ 'package-lock.json': text });
    try {
      const r = run(dir, ['--out', 'o.json']);
      assert.equal(r.code, 1, what);
      assert.equal(r.out, '', what);
      assert.notEqual(r.err, '', what);
      assert.equal(existsSync(join(dir, 'o.json')), false, what);
      assert.equal(run(dir, []).code, 1, what);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  const dir = sandbox();
  try {
    mkdirSync(join(dir, 'folder'));
    for (const name of ['package-lock.json', 'missing.json', 'folder']) {
      const r = run(dir, [name]);
      assert.equal(r.code, 1, name);
      assert.equal(r.out, '', name);
      assert.notEqual(r.err, '', name);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('lockfileVersion 2 is read from packages only; a BOM is ignored', () => {
  const lock = { lockfileVersion: 2, packages: { 'node_modules/a': { version: '1.0.0' } },
    dependencies: { b: { version: '9.9.9' } } };
  const r = gen(lock);
  assert.deepEqual(names(r.doc), ['pkg:npm/a@1.0.0']);
  const dir = sandbox();
  try {
    writeFileSync(join(dir, 'package-lock.json'), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(lock))]));
    const b = run(dir, ['--now', NOW]);
    assert.equal(b.code, 0);
    assert.deepEqual(names(JSON.parse(b.out)), ['pkg:npm/a@1.0.0']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('success prints nothing on stderr, and output ends with exactly one newline', () => {
  const r = gen(EXAMPLE);
  assert.equal(r.err, '');
  assert.ok(r.out.endsWith('}\n') && !r.out.endsWith('\n\n'));
  assert.equal(r.out, JSON.stringify(JSON.parse(r.out), null, 2) + '\n');
});

test('non-ASCII text is not escaped', () => {
  const r = gen(lock3({ 'node_modules/é': { version: '1.0.0', license: 'Ünï' } }));
  assert.match(r.out, /"name": "é"/);
  assert.match(r.out, /"name": "Ünï"/);
  assert.equal(r.doc.components[0]['bom-ref'], 'pkg:npm/%C3%A9@1.0.0');
});

// ------------------------------------------------------------ root component

test('root component fallbacks', () => {
  const root = (lock) => gen(lock).doc.metadata.component;
  assert.deepEqual(root(lock3({ '': { name: 'p', version: '1.0.0' } }, { name: 't', version: '2.0.0' })),
    { type: 'application', 'bom-ref': 'root', name: 'p', version: '1.0.0', purl: 'pkg:npm/p@1.0.0' });
  assert.deepEqual(root(lock3({ '': {} }, { name: 't', version: '2.0.0' })),
    { type: 'application', 'bom-ref': 'root', name: 't', version: '2.0.0', purl: 'pkg:npm/t@2.0.0' });
  assert.deepEqual(root(lock3({}, { name: 't' })),
    { type: 'application', 'bom-ref': 'root', name: 't', purl: 'pkg:npm/t' });
  assert.deepEqual(root(lock3({})),
    { type: 'application', 'bom-ref': 'root', name: 'unnamed', purl: 'pkg:npm/unnamed' });
  assert.deepEqual(root(lock3({ '': { name: '', version: '' } }, { name: '', version: 5 })),
    { type: 'application', 'bom-ref': 'root', name: 'unnamed', purl: 'pkg:npm/unnamed' });
  assert.deepEqual(root(lock3({ '': { name: '@acme/app', version: '1.0.0+b' } })),
    { type: 'application', 'bom-ref': 'root', group: '@acme', name: 'app', version: '1.0.0+b',
      purl: 'pkg:npm/%40acme/app@1.0.0%2Bb' });
});

// ------------------------------------------------------------ components

test('which entries are components', () => {
  const r = gen(lock3({
    '': { name: 'x' },
    'node_modules/ok': { version: '1.0.0' },
    'node_modules/a/node_modules/@s/deep': { version: '1.0.0' },
    'packages/app': { version: '1.0.0' },
    'node_modules/linked': { version: '1.0.0', link: true },
    'node_modules/noversion': {},
    'node_modules/emptyversion': { version: '' },
    'node_modules/numversion': { version: 1 },
    'node_modules/notobject': 'str',
    'node_modules/nullval': null,
    'node_modules/': { version: '1.0.0' },
    'xnode_modules/nope': { version: '1.0.0' },
    'node_modules/linkfalse': { version: '2.0.0', link: false },
  }));
  assert.deepEqual(names(r.doc), [
    'pkg:npm/%40s/deep@1.0.0', 'pkg:npm/linkfalse@2.0.0', 'pkg:npm/ok@1.0.0']);
});

test('dev entries are left out unless --include-dev; scope rules', () => {
  const packages = {
    'node_modules/req': { version: '1.0.0' },
    'node_modules/dev': { version: '1.0.0', dev: true },
    'node_modules/opt': { version: '1.0.0', optional: true },
    'node_modules/devopt': { version: '1.0.0', devOptional: true },
    'node_modules/devfalse': { version: '1.0.0', dev: false },
    'node_modules/peer': { version: '1.0.0', peer: true },
  };
  const a = gen(lock3(packages)).doc;
  assert.deepEqual(a.components.map((c) => [c.name, c.scope]), [
    ['devfalse', 'required'], ['devopt', 'optional'], ['opt', 'optional'], ['peer', 'required'], ['req', 'required']]);
  const b = gen(lock3(packages), ['--include-dev']).doc;
  assert.deepEqual(b.components.map((c) => [c.name, c.scope]), [
    ['dev', 'optional'], ['devfalse', 'required'], ['devopt', 'optional'], ['opt', 'optional'],
    ['peer', 'required'], ['req', 'required']]);
});

test('npm aliases use the name field as the full name', () => {
  const r = gen(lock3({
    '': { dependencies: { foo: '1' } },
    'node_modules/foo': { name: 'bar', version: '1.0.0' },
    'node_modules/sc': { name: '@acme/real', version: '1.0.0' },
    'node_modules/emptyname': { name: '', version: '1.0.0' },
  }));
  assert.deepEqual(r.doc.components.map((c) => [c['bom-ref'], c.group, c.name]), [
    ['pkg:npm/%40acme/real@1.0.0', '@acme', 'real'],
    ['pkg:npm/bar@1.0.0', undefined, 'bar'],
    ['pkg:npm/emptyname@1.0.0', undefined, 'emptyname'],
  ]);
  // dependencies are found by path name
  assert.deepEqual(r.doc.dependencies[0].dependsOn, ['pkg:npm/bar@1.0.0']);
});

test('component keys come in the stated order, absent keys are absent', () => {
  const r = gen(lock3({
    'node_modules/@s/full': { version: '1.0.0', resolved: 'https://x/y.tgz',
      integrity: 'sha1-AAECAwQFBgcICQoLDA0ODxAREhM=', license: 'MIT' },
    'node_modules/bare': { version: '1.0.0' },
  }));
  assert.deepEqual(Object.keys(r.doc.components[0]),
    ['type', 'bom-ref', 'group', 'name', 'version', 'scope', 'hashes', 'licenses', 'purl', 'externalReferences']);
  assert.deepEqual(Object.keys(r.doc.components[1]), ['type', 'bom-ref', 'name', 'version', 'scope', 'purl']);
  assert.deepEqual(Object.keys(r.doc), ['bomFormat', 'specVersion', 'serialNumber', 'version', 'metadata', 'components', 'dependencies']);
  assert.deepEqual(Object.keys(r.doc.metadata), ['timestamp', 'tools', 'component']);
});

test('scoped names are split; group and name edge cases', () => {
  const r = gen(lock3({
    'node_modules/@a/b/c': { version: '1.0.0' },
    'node_modules/plain': { version: '1.0.0' },
    'node_modules/@lonely': { version: '1.0.0' },
  }));
  const c = r.doc.components.find((x) => x.group === '@a');
  assert.equal(c.name, 'b/c');
  const lonely = r.doc.components.find((x) => x.purl.includes('lonely'));
  assert.equal(lonely.group, undefined);
  assert.equal(lonely.name, '@lonely');
  assert.equal(lonely.purl, 'pkg:npm/%40lonely@1.0.0');
});

test('sorting is by full name, version, lock key in code-unit order', () => {
  const r = gen(lock3({
    'node_modules/a': { version: '9.0.0' },
    'node_modules/B': { version: '1.0.0' },
    'node_modules/@s/x': { version: '1.0.0' },
    'node_modules/z/node_modules/a': { version: '10.0.0' },
    'node_modules/a2': { name: 'a', version: '9.0.0' },
    'node_modules/_u': { version: '1.0.0' },
  }));
  assert.deepEqual(r.doc.components.map((c) => [c.group ? c.group + '/' + c.name : c.name, c.version, c['bom-ref']]), [
    ['@s/x', '1.0.0', 'pkg:npm/%40s/x@1.0.0'],
    ['B', '1.0.0', 'pkg:npm/B@1.0.0'],
    ['_u', '1.0.0', 'pkg:npm/_u@1.0.0'],
    ['a', '10.0.0', 'pkg:npm/a@10.0.0'],
    ['a', '9.0.0', 'pkg:npm/a@9.0.0#node_modules/a'],
    ['a', '9.0.0', 'pkg:npm/a@9.0.0#node_modules/a2'],
  ]);
  assert.deepEqual(r.doc.dependencies.map((d) => d.ref), ['root', ...names(r.doc)]);
});

// ------------------------------------------------------------ purl

test('purl percent-encoding: upper-case hex, unreserved kept, case kept', () => {
  const r = gen(lock3({
    'node_modules/@Acme/Core': { version: '1.0.0+build.5' },
    'node_modules/we ird~name_x.y-z': { version: '1.0.0-rc.1' },
    'node_modules/ü': { version: '1.0.0' },
  }));
  assert.deepEqual(names(r.doc).sort(), [
    'pkg:npm/%40Acme/Core@1.0.0%2Bbuild.5',
    'pkg:npm/%C3%BC@1.0.0',
    'pkg:npm/we%20ird~name_x.y-z@1.0.0-rc.1',
  ].sort());
});

// ------------------------------------------------------------ bom-ref

test('duplicate purls get the lock key; dev copies only count when listed', () => {
  const packages = {
    'node_modules/a': { version: '1.0.0', dependencies: { tiny: '1' } },
    'node_modules/tiny': { version: '1.0.1' },
    'node_modules/a/node_modules/tiny': { version: '1.0.1' },
    'node_modules/d': { version: '1.0.0', dev: true, dependencies: { solo: '1' } },
    'node_modules/solo': { version: '1.0.0' },
    'node_modules/d/node_modules/solo': { version: '1.0.0', dev: true },
  };
  const a = gen(lock3(packages)).doc;
  assert.deepEqual(names(a), ['pkg:npm/a@1.0.0', 'pkg:npm/solo@1.0.0',
    'pkg:npm/tiny@1.0.1#node_modules/a/node_modules/tiny', 'pkg:npm/tiny@1.0.1#node_modules/tiny']);
  assert.equal(a.components[2].purl, 'pkg:npm/tiny@1.0.1');
  const b = gen(lock3(packages), ['--include-dev']).doc;
  assert.ok(names(b).includes('pkg:npm/solo@1.0.0#node_modules/d/node_modules/solo'));
  assert.ok(names(b).includes('pkg:npm/solo@1.0.0#node_modules/solo'));
  const dep = Object.fromEntries(b.dependencies.map((d) => [d.ref, d.dependsOn]));
  assert.deepEqual(dep['pkg:npm/a@1.0.0'], ['pkg:npm/tiny@1.0.1#node_modules/a/node_modules/tiny']);
  assert.deepEqual(dep['pkg:npm/d@1.0.0'], ['pkg:npm/solo@1.0.0#node_modules/d/node_modules/solo']);
});

// ------------------------------------------------------------ hashes

const b64 = (n, fill = 1) => Buffer.alloc(n, fill).toString('base64');
const hex = (n, fill = 1) => Buffer.alloc(n, fill).toString('hex');
const hashesFor = (integrity) => gen(lock3({ 'node_modules/p': { version: '1.0.0', integrity } })).doc.components[0].hashes;

test('hashes from integrity', () => {
  assert.deepEqual(hashesFor(`sha512-${b64(64)}`), [{ alg: 'SHA-512', content: hex(64) }]);
  assert.deepEqual(hashesFor(`sha384-${b64(48, 2)}`), [{ alg: 'SHA-384', content: hex(48, 2) }]);
  assert.deepEqual(hashesFor(`sha256-${b64(32, 255)}`), [{ alg: 'SHA-256', content: hex(32, 255) }]);
  assert.deepEqual(hashesFor(`sha1-${b64(20)}`), [{ alg: 'SHA-1', content: hex(20) }]);
  // in the order of the tokens, extra whitespace, ?options ignored
  assert.deepEqual(hashesFor(`  sha1-${b64(20, 3)}\t sha512-${b64(64, 4)}?foo=bar \n`),
    [{ alg: 'SHA-1', content: hex(20, 3) }, { alg: 'SHA-512', content: hex(64, 4) }]);
  // the first used token of an algorithm counts; an ignored token does not
  assert.deepEqual(hashesFor(`sha1-${b64(20, 5)} sha1-${b64(20, 6)}`), [{ alg: 'SHA-1', content: hex(20, 5) }]);
  assert.deepEqual(hashesFor(`sha1-AAAA sha1-${b64(20, 6)}`), [{ alg: 'SHA-1', content: hex(20, 6) }]);
});

test('malformed integrity tokens are ignored; no usable token means no hashes', () => {
  const bad = [
    undefined, 5, null, {}, ['sha1-' + b64(20)], '', '   ',
    'md5-' + b64(16), 'SHA1-' + b64(20), 'sha1:' + b64(20), 'sha1-', `sha1-${b64(19)}`, `sha1-${b64(21)}`,
    `sha512-${b64(63)}`, `sha256-${b64(20)}`, `sha1-${b64(20).slice(0, -1)}`, `sha1-${b64(20)}=`,
    'sha1-AAECAwQFBgcICQoLDA0ODxAREhN=', // padding ok but not canonical re-encoding? (non-zero trailing bits)
    `sha1-${b64(20).replace('=', '')}`, 'sha1-@@@@', `sha1_${b64(20)}`, `sha1-${b64(20)}x?y`,
    `sha1-${Buffer.alloc(20, 251).toString('base64url')}`,
  ];
  for (const integrity of bad) {
    const h = hashesFor(integrity);
    // the only value in this list that may produce hashes is the base64url one if it has no - or _
    if (integrity === `sha1-${Buffer.alloc(20, 251).toString('base64url')}`) continue;
    assert.equal(h, undefined, JSON.stringify(integrity));
  }
  const r = gen(lock3({ 'node_modules/p': { version: '1.0.0', integrity: 'junk' } }));
  assert.equal('hashes' in r.doc.components[0], false);
});

// ------------------------------------------------------------ licences

const licFor = (license) => gen(lock3({ 'node_modules/p': { version: '1.0.0', license } })).doc.components[0].licenses;

test('licences: id for the listed ids, name otherwise, none for other shapes', () => {
  const ids = ['0BSD', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-2.0', 'Artistic-2.0', 'BlueOak-1.0.0',
    'BSD-2-Clause', 'BSD-3-Clause', 'CC-BY-3.0', 'CC-BY-4.0', 'CC0-1.0', 'EPL-2.0', 'GPL-2.0-only',
    'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'ISC', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
    'LGPL-3.0-only', 'LGPL-3.0-or-later', 'MIT', 'MIT-0', 'MPL-2.0', 'Python-2.0', 'Unlicense', 'WTFPL', 'Zlib'];
  assert.equal(ids.length, 28);
  for (const id of ids) assert.deepEqual(licFor(id), [{ license: { id } }], id);
  assert.deepEqual(licFor('  MIT\n'), [{ license: { id: 'MIT' } }]);
  for (const name of ['(MIT OR Apache-2.0)', 'Apache 2.0', 'GPL-3.0', 'mit', 'SEE LICENSE IN LICENSE', 'Apache-2.0 ']) {
    const want = name.trim();
    assert.deepEqual(licFor(name), [{ license: want === 'Apache-2.0' ? { id: want } : { name: want } }], name);
  }
  assert.deepEqual(licFor(' (ISC) '), [{ license: { name: '(ISC)' } }]);
  for (const other of [undefined, '', '   \n', null, 5, {}, { type: 'MIT' }, ['MIT'], true]) {
    assert.equal(licFor(other), undefined, JSON.stringify(other));
  }
});

// ------------------------------------------------------------ external references

test('distribution references are kept only for http and https URLs', () => {
  const refFor = (resolved) => gen(lock3({ 'node_modules/p': { version: '1.0.0', resolved } })).doc.components[0].externalReferences;
  assert.deepEqual(refFor('https://r.example/p.tgz'), [{ type: 'distribution', url: 'https://r.example/p.tgz' }]);
  assert.deepEqual(refFor('http://r.example/p.tgz?x=1 y'), [{ type: 'distribution', url: 'http://r.example/p.tgz?x=1 y' }]);
  for (const v of ['file:../p', 'git+ssh://git@github.com/a/b.git', 'git+https://github.com/a/b.git', 'ftp://x', '',
    'HTTPS://x', ' https://x', undefined, null, 7, { url: 'https://x' }]) {
    assert.equal(refFor(v), undefined, JSON.stringify(v));
  }
});

// ------------------------------------------------------------ dependencies

test('dependencies resolve nearest node_modules first', () => {
  const r = gen(lock3({
    '': { dependencies: { x: '1' } },
    'node_modules/x': { version: '1.0.0', dependencies: { y: '1', z: '1' } },
    'node_modules/x/node_modules/y': { version: '2.0.0', dependencies: { z: '1', x: '1' } },
    'node_modules/y': { version: '1.0.0' },
    'node_modules/z': { version: '1.0.0' },
    'node_modules/x/node_modules/y/node_modules/z': { version: '3.0.0' },
  })).doc;
  const dep = Object.fromEntries(r.dependencies.map((d) => [d.ref, d.dependsOn]));
  assert.deepEqual(dep.root, ['pkg:npm/x@1.0.0']);
  assert.deepEqual(dep['pkg:npm/x@1.0.0'], ['pkg:npm/y@2.0.0', 'pkg:npm/z@1.0.0']);
  assert.deepEqual(dep['pkg:npm/y@2.0.0'], ['pkg:npm/x@1.0.0', 'pkg:npm/z@3.0.0']);
});

test('dependencies come from dependencies, optionalDependencies, peerDependencies; sorted, no repeats, no self', () => {
  const r = gen(lock3({
    '': { dependencies: { b: '1' }, optionalDependencies: { a: '1' }, peerDependencies: { c: '1', b: '1' },
      devDependencies: { dd: '1' } },
    'node_modules/a': { version: '1.0.0', dependencies: { a: '1', c: '1' }, devDependencies: { dd: '1' } },
    'node_modules/b': { version: '1.0.0', peerDependencies: { a: '*' }, optionalDependencies: { a: '*', b: '*' } },
    'node_modules/c': { version: '1.0.0', dependencies: [ 'a' ], optionalDependencies: 'a', peerDependencies: null },
    'node_modules/dd': { version: '1.0.0' },
  })).doc;
  const dep = Object.fromEntries(r.dependencies.map((d) => [d.ref, d.dependsOn]));
  assert.deepEqual(dep.root, ['pkg:npm/a@1.0.0', 'pkg:npm/b@1.0.0', 'pkg:npm/c@1.0.0']);
  assert.deepEqual(dep['pkg:npm/a@1.0.0'], ['pkg:npm/c@1.0.0']);
  assert.deepEqual(dep['pkg:npm/b@1.0.0'], ['pkg:npm/a@1.0.0']);
  assert.deepEqual(dep['pkg:npm/c@1.0.0'], []);
  assert.deepEqual(Object.keys(r.dependencies[0]), ['ref', 'dependsOn']);
});

test('root devDependencies count only with --include-dev; dev targets are left out without it', () => {
  const lock = lock3({
    '': { dependencies: { a: '1' }, devDependencies: { t: '1' } },
    'node_modules/a': { version: '1.0.0', dependencies: { t: '1' } },
    'node_modules/t': { version: '1.0.0', dev: true },
  });
  const a = gen(lock).doc;
  assert.deepEqual(a.dependencies.map((d) => [d.ref, d.dependsOn]), [['root', ['pkg:npm/a@1.0.0']], ['pkg:npm/a@1.0.0', []]]);
  const b = gen(lock, ['--include-dev']).doc;
  assert.deepEqual(b.dependencies.map((d) => [d.ref, d.dependsOn]), [
    ['root', ['pkg:npm/a@1.0.0', 'pkg:npm/t@1.0.0']], ['pkg:npm/a@1.0.0', ['pkg:npm/t@1.0.0']], ['pkg:npm/t@1.0.0', []]]);
});

test('unresolved names, links and non-candidates are skipped while resolving', () => {
  const r = gen(lock3({
    '': { dependencies: { missing: '1', lnk: '1', nov: '1', ws: '1' } },
    'node_modules/lnk': { resolved: 'packages/lnk', link: true },
    'packages/lnk': { version: '1.0.0' },
    'node_modules/nov': {},
    'node_modules/a': { version: '1.0.0', dependencies: { lnk: '1', nov: '1' } },
    'node_modules/a/node_modules/nov': { version: '5.0.0' },
  })).doc;
  const dep = Object.fromEntries(r.dependencies.map((d) => [d.ref, d.dependsOn]));
  assert.deepEqual(names(r), ['pkg:npm/a@1.0.0', 'pkg:npm/nov@5.0.0']);
  assert.deepEqual(dep.root, []);
  assert.deepEqual(dep['pkg:npm/a@1.0.0'], ['pkg:npm/nov@5.0.0']);
});

test('a link (not a candidate) lets resolution go on to the parent', () => {
  const r = gen(lock3({
    'node_modules/a': { version: '1.0.0', dependencies: { l: '1' } },
    'node_modules/a/node_modules/l': { link: true, version: '1.0.0' },
    'node_modules/l': { version: '2.0.0' },
  })).doc;
  assert.deepEqual(r.dependencies[1].dependsOn, ['pkg:npm/l@2.0.0']);
});

test('no root entry: the root package is empty and has no dependencies', () => {
  const r = gen(lock3({ 'node_modules/a': { version: '1.0.0' } }, { name: 'top', version: '0.0.1' })).doc;
  assert.equal(r.metadata.component.name, 'top');
  assert.deepEqual(r.dependencies[0], { ref: 'root', dependsOn: [] });
});

test('keys such as __proto__ are plain data', () => {
  const text = '{"lockfileVersion":3,"packages":{"__proto__":{"version":"1.0.0"},"node_modules/__proto__":{"version":"1.0.0"},"node_modules/constructor":{"version":"1.0.0"}}}';
  const r = gen(text);
  assert.equal(r.code, 0);
  assert.deepEqual(names(r.doc), ['pkg:npm/__proto__@1.0.0', 'pkg:npm/constructor@1.0.0']);
});

// ------------------------------------------------------------ a larger lock file

test('a larger generated lock file: unique refs, closed dependencies, nothing written', () => {
  const packages = { '': { name: 'big', version: '1.0.0', dependencies: {}, devDependencies: {} } };
  const N = 1500;
  for (let i = 0; i < N; i++) {
    const nm = i % 7 === 0 ? `@scope${i % 5}/p${i}` : `p${i}`;
    const dev = i % 4 === 0;
    const deps = {};
    for (const j of [i + 1, i + 2, (i * 7) % N, i]) deps[j % 7 === 0 ? `@scope${j % 5}/p${j}` : `p${j}`] = '*';
    packages[`node_modules/${nm}`] = { version: `1.${i % 3}.0`, dev, dependencies: deps, license: 'MIT' };
    if (i % 10 === 0) packages[`node_modules/${nm}/node_modules/shared`] = { version: '1.0.0', dev };
    if (i % 10 === 3) packages[`node_modules/${nm}/node_modules/shared`] = { version: '1.0.0', dependencies: { p0: '*' } };
    if (i < 20) (dev ? packages[''].devDependencies : packages[''].dependencies)[nm] = '*';
  }
  const dir = sandbox({ 'package-lock.json': JSON.stringify(packages && { lockfileVersion: 3, packages }, null, 2) });
  try {
    const before = readdirSync(dir).sort();
    for (const args of [[], ['--include-dev']]) {
      const r = run(dir, ['--now', NOW, ...args]);
      assert.equal(r.code, 0);
      const doc = JSON.parse(r.out);
      const refs = names(doc);
      assert.equal(new Set(refs).size, refs.length);
      const known = new Set(['root', ...refs]);
      assert.equal(doc.dependencies.length, refs.length + 1);
      for (const d of doc.dependencies) {
        assert.ok(known.has(d.ref));
        assert.deepEqual(d.dependsOn, [...new Set(d.dependsOn)].sort());
        for (const x of d.dependsOn) assert.ok(known.has(x) && x !== d.ref);
      }
      if (args.length) assert.ok(refs.length > N);
    }
    assert.deepEqual(readdirSync(dir).sort(), before);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
