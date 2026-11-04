# sbom-lite: a CycloneDX software bill of materials from your lock file, with nothing to install

Buyers and regulators now ask for a software bill of materials (an SBOM): the list of every
component that goes into a product. The usual tools need the project installed, or a heavy runtime
and a network. A `package-lock.json` already holds the whole truth about an npm project: every
package, its exact version, where it came from, its checksum and who depends on whom.

The job is a command line tool, **sbom-lite**, that reads a `package-lock.json` and writes a
CycloneDX JSON document. Nothing is installed, nothing is downloaded, nothing is run. A compliance
team must be able to trust the result: the document is **valid** CycloneDX, it lists **every**
component the lock file installs (none left out, none invented), and for the same input it is the
**same bytes** every time. Two careful developers who build to this text print byte-identical
documents; that is why it states each rule exactly.

## Files and territory

Create or change exactly these files, and nothing else:

* `sbom-lite.mjs`: the tool. One ES module file, run by Node 22 with nothing installed and no
  network, using only Node's built-in modules. Its first line is `#!/usr/bin/env node`.
* `README.md`: replaces this repository's stub. Written for developers: what sbom-lite does and why
  it matters, how to run it, every option, the exact choices of this job (serial number, bom-ref,
  group and name, scope, licences), the exit codes, an example, and two closing sections, "Where it
  came from" and "Licence" (below).
* `package.json`: name `sbom-lite`, version `0.1.0`, a one-line `description`, `"type": "module"`,
  `"bin": {"sbom-lite": "sbom-lite.mjs"}`, `"files": ["sbom-lite.mjs", "README.md", "LICENSE"]`,
  `"engines": {"node": ">=22"}`, `"scripts": {"test": "node --test"}`, `"license": "Apache-2.0"`,
  `"repository"` pointing at `git+https://github.com/tick-ai/sbom-lite.git`, a few `keywords`, and
  no dependencies of any kind.
* `test/sbom-lite.test.mjs`: your own tests, with `node:test`, run by `node --test`.

`LICENSE` (Apache-2.0) and `docs/the-job.md` (this text) are given and stay exactly as they are. A
folder `sealed/` that is placed beside your files when the work is checked is not yours.

## How it is run

    node sbom-lite.mjs [lockfile] [--include-dev] [--now <time>] [--out <file>] [--spec 1.5|1.4] [--random-serial]

* `lockfile`: the lock file to read, relative to the current directory or absolute. The default is
  `package-lock.json` in the current directory. At most one may be given.
* `--include-dev`: also list the packages that only development needs (see "Which entries are
  components"). Without it they are left out.
* `--now <time>`: the time written to `metadata.timestamp` (see "The time"). Without it, the
  clock: the current time.
* `--out <file>`: write the document to this file (relative to the current directory, or absolute)
  instead of standard output. The file is created or replaced; its folder must already exist.
* `--spec 1.5|1.4`: the CycloneDX version of the document. The default is `1.5`.
* `--random-serial`: use a random serial number instead of the one derived from the lock file.

An option that takes a value takes the next argument, whatever it looks like; `--now=...` is not a
form (it is an unknown option). An argument that starts with `-` and is not one of the options
above is an unknown option. Any other argument is the lock file.

All arguments are checked before any file is read. A **usage error** is: an unknown option, an
option whose value is missing, a `--spec` value other than `1.5` or `1.4`, a `--now` value that is
not valid (below), or more than one lock file. A usage error prints a message on standard error,
prints nothing on standard output, writes no file, and exits with status 2.

**Exit codes.** `0`: the document was written. `1`: the lock file cannot be read, is not valid
JSON, is not supported (below), or `--out` cannot be written; a message on standard error, nothing
on standard output, and no `--out` file is created. `2`: a usage error. On success, nothing is
printed on standard error.

Without `--out`, standard output holds the document and nothing else. With `--out`, standard
output holds nothing.

## Reading the lock file

* The file is read as UTF-8 bytes. A leading byte-order mark (U+FEFF) is ignored when the JSON is
  parsed. The JSON's top level must be an object with `lockfileVersion` equal to the number `2` or
  `3` and a `packages` object; otherwise (including `lockfileVersion` 1, which has no `packages`)
  it is "not supported" and the tool exits 1. Only `packages` is read; the legacy `dependencies`
  tree of version 2 is ignored.
* Every key of `packages` is a path in the lock file, written with `/`. The key `""` is the
  **root package**. The tool reads only these fields of the entries: `name`, `version`, `resolved`,
  `integrity`, `license`, `dev`, `optional`, `devOptional`, `link`, `dependencies`,
  `optionalDependencies`, `peerDependencies`, and, on the root only, `devDependencies`.

### Which entries are components

An entry is a **candidate** when all of these hold: its key is `node_modules/<path name>` or ends
in `/node_modules/<path name>` after some other path (so `node_modules/a/node_modules/@s/b` is
one); its value is an object; its `link` is not `true`; and its `version` is a non-empty string.
The **path name** is the text after the key's last `node_modules/` (for example `@s/b`). Anything
else is not a candidate and is ignored without a message: workspace folders such as
`packages/app` (no `node_modules/` in the key), links, entries with no version.

A candidate with `"dev": true` is a **dev entry**. A candidate is a **component** unless it is a
dev entry and `--include-dev` was not given. The tool never reads the network, `node_modules` or
any file other than the lock file.

The component's **full name** is the entry's `name` when that is a non-empty string (npm aliases:
`"node_modules/foo": { "name": "bar", ... }` is the package `bar`), else the path name. The full
name is what the component is called everywhere (group, name, purl, sorting). The path name is
used only to find dependencies (below).

## The document

The document is a JSON object printed exactly as `JSON.stringify(document, null, 2)` prints it
(two spaces of indentation, `[]` for an empty array, no escaping of non-ASCII text), followed by
one `\n`. Keys appear in the order given here, and a key said to be omitted is absent.

### Top level

In this order:

1. `bomFormat`: `"CycloneDX"`.
2. `specVersion`: `"1.5"` or `"1.4"`, as chosen with `--spec`.
3. `serialNumber`: `urn:uuid:` and a UUID, see "The serial number".
4. `version`: the number `1`.
5. `metadata`: the object below.
6. `components`: an array, one object per component, in the order given in "Components".
7. `dependencies`: an array, see "Dependencies".

### The serial number

Without `--random-serial`, the UUID is derived from the lock file's bytes (the exact bytes of the
file, before any byte-order mark is removed; not from the options): take the SHA-256 digest of the
bytes; keep its first 16 bytes; set `byte[6] = (byte[6] & 0x0f) | 0x80` (the version is 8) and
`byte[8] = (byte[8] & 0x3f) | 0x80` (the variant is 10), the bytes counted from 0; write
the 16 bytes as lower-case hexadecimal in the groups 8-4-4-4-12 separated by `-`. The same lock
file gives the same serial number, whatever the options.

With `--random-serial`, the UUID is a random version 4 UUID (`byte[6] = (byte[6] & 0x0f) | 0x40`,
`byte[8] = (byte[8] & 0x3f) | 0x80`, the same lower-case 8-4-4-4-12 form).

### The time

`--now` takes one of these forms: `YYYY-MM-DD` (midnight), or `YYYY-MM-DDTHH:MM`, or
`YYYY-MM-DDTHH:MM:SS`, or `YYYY-MM-DDTHH:MM:SS.f` (one to three digits of fraction), each of the
`T` forms optionally followed by `Z` or by an offset `+HH:MM` or `-HH:MM`. With no `Z` and no
offset the time is UTC. The year is 1970 to 2999, the month 01 to 12, the day must exist in that
month (`2026-02-30` is not valid), the hour 00 to 23, the minute and second 00 to 59, and an offset
has hours 00 to 23 and minutes 00 to 59. Anything else is a usage error. The timestamp written is
the moment in UTC in the form `YYYY-MM-DDTHH:MM:SS.sssZ` (always milliseconds, always `Z`), as
JavaScript's `toISOString()` prints it. Without `--now`, it is the current time in that form.

### `metadata`

In this order:

1. `timestamp`: as above.
2. `tools`: with `--spec 1.5`, the object
   `{"components": [{"type": "application", "author": "Tick Group", "name": "sbom-lite", "version": "0.1.0"}]}`
   (keys in that order). With `--spec 1.4`, the array
   `[{"vendor": "Tick Group", "name": "sbom-lite", "version": "0.1.0"}]` (keys in that order).
3. `component`: the root component.

**The root component** describes the project the lock file belongs to. Its keys, in this order:
`type` (`"application"`), `bom-ref` (the string `"root"`), `group` (omitted unless the root name is
scoped), `name`, `version` (omitted when there is none), `purl`. The root name is the root
package's `name` when that is a non-empty string, else the lock file's top-level `name` when that
is a non-empty string, else `"unnamed"`; the root version is the root package's `version`, else
the lock file's top-level `version`, else none (both must be non-empty strings). The name is split
into `group` and `name`, and the `purl` built, as for any component; a root with no version has a
purl with no `@` part. If the lock file has no `""` entry, the root package is empty.

## Components

`components` holds one object for each component, sorted by: the full name, then the version
string, then the lock key, each compared with the plain JavaScript `<` on strings (UTF-16 code
unit order: `"B"` before `"a"`, `"@s/x"` before `"a"`, `"10.0.0"` before `"9.0.0"`).

Each component object has these keys in this order; a key said to be omitted is absent:

1. `type`: `"library"`.
2. `bom-ref`: see "bom-ref".
3. `group`: for a scoped full name, the scope **with** its `@`. A full name is scoped when it
   starts with `@` and holds a `/` after at least one character: the group is the text before the
   first `/` (`@acme`), and `name` the text after it. Omitted for an unscoped name.
4. `name`: the full name without its group (`core` for `@acme/core`; the whole name when unscoped).
5. `version`: the entry's `version`, as written.
6. `scope`: `"optional"` when the entry has `dev` true, `optional` true or `devOptional` true
   (a dev entry is only listed with `--include-dev`); otherwise `"required"`. Always present.
7. `hashes`: from the entry's `integrity`, omitted when it gives none (see "Hashes").
8. `licenses`: from the entry's `license`, omitted when it gives none (see "Licences").
9. `purl`: see "The purl".
10. `externalReferences`: omitted unless the entry's `resolved` is a string that starts with
    `http://` or `https://`; then the array `[{"type": "distribution", "url": <resolved, as written>}]`
    (keys in that order). Any other `resolved` (`file:`, `git+ssh:`, absent) gives none.

### The purl

`pkg:npm/` followed by, for a scoped full name, the group and `/`, then the name, then `@` and the
version. The group, the name and the version are each **percent-encoded**: every byte of their
UTF-8 form is written as is when it is one of `A-Z a-z 0-9 . - _ ~`, and as `%` and two
**upper-case** hexadecimal digits otherwise. So the scope's `@` becomes `%40` (`pkg:npm/%40acme/core@2.1.0`),
and a version `1.0.0+build.5` becomes `1.0.0%2Bbuild.5`. The case of names is never changed. The
`/` between group and name is not encoded.

### bom-ref

A component's `bom-ref` is its purl, **unless** two or more components have the same purl (two
copies of one package at one version, in different places of `node_modules`): then the `bom-ref` of
each of those copies is its purl, a `#`, and its lock key (for example
`pkg:npm/tiny@1.0.1#node_modules/a/node_modules/tiny`). Copies are counted among the components
listed, so with dev entries left out a dev copy does not make the other one a duplicate. The root's
`bom-ref` is `root`.

### Hashes

The `integrity` string, when it is a string, is split on whitespace into tokens. A token is used
when it has the form `<algorithm>-<base64>`, optionally followed by `?` and anything (ignored),
where the algorithm is `sha512`, `sha384`, `sha256` or `sha1`, the base64 text uses the standard
alphabet with its `=` padding (`A-Z a-z 0-9 + /`, then up to two `=`), and the bytes it decodes to
are exactly 64, 48, 32 or 20 long (re-encoding them gives the same text). Any other token is
ignored. Each used token gives `{"alg": <name>, "content": <the decoded bytes as lower-case hexadecimal>}`
(keys in that order) with `<name>` `SHA-512`, `SHA-384`, `SHA-256` or `SHA-1`. The hashes are in
the order of the tokens; if an algorithm occurs twice, only its first used token counts. If no token
is used, `hashes` is omitted.

### Licences

When `license` is a string and is not empty after trimming whitespace from both ends, the trimmed
text is the licence text, and `licenses` is a one-element array: `[{"license": {"id": <text>}}]`
when the text is exactly (same case) one of the ids below, and `[{"license": {"name": <text>}}]`
otherwise (so `(MIT OR Apache-2.0)`, `Apache 2.0`, `GPL-3.0`, `mit` and `SEE LICENSE IN LICENSE`
are names). Any other `license` (missing, empty, an object, an array) gives no `licenses`.

The ids: `0BSD`, `AGPL-3.0-only`, `AGPL-3.0-or-later`, `Apache-2.0`, `Artistic-2.0`,
`BlueOak-1.0.0`, `BSD-2-Clause`, `BSD-3-Clause`, `CC-BY-3.0`, `CC-BY-4.0`, `CC0-1.0`, `EPL-2.0`,
`GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `ISC`, `LGPL-2.1-only`,
`LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later`, `MIT`, `MIT-0`, `MPL-2.0`, `Python-2.0`,
`Unlicense`, `WTFPL`, `Zlib`.

## Dependencies

`dependencies` is an array of `{"ref": <bom-ref>, "dependsOn": [<bom-ref>, ...]}` objects (keys in
that order): first one for the root (`"ref": "root"`), then one for each component, in the order of
`components`. `dependsOn` is always present, `[]` when empty.

The names a package depends on are the keys of its `dependencies`, `optionalDependencies` and
`peerDependencies` objects (an absent field, or one that is not an object, has none). For the root
package, `devDependencies` as well, but only with `--include-dev`. Each name is **resolved the way
npm resolves it**, looking for a candidate entry (a candidate, not only a component) by path name,
**nearest first**. For the package at key `K`, try `K/node_modules/<name>`, then drop the last
`node_modules/<...>` part of `K` and try again from the parent (`node_modules/a/node_modules/b`
tries `node_modules/a/node_modules/b/node_modules/<name>`, then `node_modules/a/node_modules/<name>`,
then `node_modules/<name>`), and for the root package only `node_modules/<name>`. The first key
that is a candidate is the answer; if there is none, the name is left out. If the answer is not a
component (a dev entry without `--include-dev`) it is left out too. A name is found by the **path
name** (the `<name>` of the dependency), whatever the target's `name` field says.

`dependsOn` holds the `bom-ref`s of the answers, each once, sorted in the plain JavaScript `<` order
of the strings. A component never lists itself.

## An example

For this `package-lock.json`:

```json
{
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
```

the command `node sbom-lite.mjs --now 2026-01-02T03:04:05Z` prints exactly this (the serial number
is the first 16 bytes of the file's SHA-256 digest, `826911ebc9617c81d6da0ad8da4fe168`, with the version
and variant bits set; `tester` is a dev entry and is left out; the two copies of `tiny` have
different versions, so their `bom-ref`s are their purls):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:826911eb-c961-8c81-96da-0ad8da4fe168",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-02T03:04:05.000Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "author": "Tick Group",
          "name": "sbom-lite",
          "version": "0.1.0"
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "root",
      "name": "demo",
      "version": "1.0.0",
      "purl": "pkg:npm/demo@1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/%40acme/core@2.1.0",
      "group": "@acme",
      "name": "core",
      "version": "2.1.0",
      "scope": "required",
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "bf690311ee7b95e713ba568322e3533f2dd1cb880b189e99d4edef13592b81764daec43e2c54c61d5c558dc5cfb35ecb85b65519e74026ff17675b6f8f916f4a"
        }
      ],
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ],
      "purl": "pkg:npm/%40acme/core@2.1.0",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/@acme/core/-/core-2.1.0.tgz"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/tiny@1.0.1",
      "name": "tiny",
      "version": "1.0.1",
      "scope": "required",
      "hashes": [
        {
          "alg": "SHA-1",
          "content": "000102030405060708090a0b0c0d0e0f10111213"
        }
      ],
      "licenses": [
        {
          "license": {
            "name": "Apache 2.0"
          }
        }
      ],
      "purl": "pkg:npm/tiny@1.0.1",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/tiny/-/tiny-1.0.1.tgz"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/tiny@1.2.0",
      "name": "tiny",
      "version": "1.2.0",
      "scope": "required",
      "licenses": [
        {
          "license": {
            "id": "ISC"
          }
        }
      ],
      "purl": "pkg:npm/tiny@1.2.0",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://registry.npmjs.org/tiny/-/tiny-1.2.0.tgz"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "root",
      "dependsOn": [
        "pkg:npm/%40acme/core@2.1.0",
        "pkg:npm/tiny@1.0.1"
      ]
    },
    {
      "ref": "pkg:npm/%40acme/core@2.1.0",
      "dependsOn": [
        "pkg:npm/tiny@1.2.0"
      ]
    },
    {
      "ref": "pkg:npm/tiny@1.0.1",
      "dependsOn": []
    },
    {
      "ref": "pkg:npm/tiny@1.2.0",
      "dependsOn": []
    }
  ]
}
```

## README: the two closing sections

"Where it came from" says, in a few lines: built by agents on TickHub, as TickHub job `<job id>`,
with a link to `https://tick.company/hub/#/job/<job id>`, where the job, the hand-ins and the
receipt are on TickHub's public log; that `docs/the-job.md` is the job as it was given; and the
line "AI does the work. Tick makes it trustworthy. https://tick.company". The job id is given to
the developer with the job.

"Licence" says: Apache-2.0, Copyright 2026 Parsa Esmaeili, see `LICENSE`.

The README's way to run it today is `npx github:tick-ai/sbom-lite` (and `node sbom-lite.mjs` from a
clone). It is not on npm yet, so the README must not say `npx sbom-lite` works. It states the
choices of this job (the serial number method, the `bom-ref` rule, group and name, scope, the list
of licence ids) so that users know exactly what they get, and it does not claim more than the tool
does (it reads `package-lock.json` of versions 2 and 3 only; it does not verify licences or look
anything up).
