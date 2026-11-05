# sbom-lite

sbom-lite reads your `package-lock.json` and prints a CycloneDX software bill of materials (JSON), with nothing to install, nothing downloaded and nothing run.

```sh
npx github:tick-ai/sbom-lite
```

Run it in a folder that holds a `package-lock.json` and it prints the document. For a project `demo` that depends on `@acme/core`, the start and the one component look like this (shortened; `--now` pins the time):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3ca60056-ebcc-8662-912c-620babbc4f40",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-02T03:04:05.000Z",
    "component": { "type": "application", "bom-ref": "root", "name": "demo", "version": "1.0.0", "purl": "pkg:npm/demo@1.0.0" }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/%40acme/core@2.1.0",
      "group": "@acme",
      "name": "core",
      "version": "2.1.0",
      "scope": "required",
      "hashes": [{ "alg": "SHA-1", "content": "000102030405060708090a0b0c0d0e0f10111213" }],
      "licenses": [{ "license": { "id": "MIT" } }],
      "purl": "pkg:npm/%40acme/core@2.1.0",
      "externalReferences": [{ "type": "distribution", "url": "https://registry.npmjs.org/@acme/core/-/core-2.1.0.tgz" }]
    }
  ],
  "dependencies": [
    { "ref": "root", "dependsOn": ["pkg:npm/%40acme/core@2.1.0"] },
    { "ref": "pkg:npm/%40acme/core@2.1.0", "dependsOn": [] }
  ]
}
```

(Real output is printed in full, with two-space indentation; `metadata.tools` is left out of this excerpt.)

## Why

Buyers and regulators now ask for a software bill of materials: the list of every component that goes into a product. The usual tools need the project installed, or a heavy runtime and a network. A `package-lock.json` already holds the whole truth about an npm project: every package, its exact version, where it came from, its checksum and who depends on whom. sbom-lite turns that file into a CycloneDX document, and the rules are exact, so that:

* it lists **every** component the lock file installs: none left out, none invented;
* for the same input it prints the **same bytes** every time (give it `--now` to pin the clock);
* it reads only the lock file: no network, no `node_modules`, no other file, and it writes nothing unless you pass `--out`.

## Run it

```sh
npx github:tick-ai/sbom-lite                       # reads ./package-lock.json
node sbom-lite.mjs [lockfile] [--include-dev] [--now <time>] [--out <file>] [--spec 1.5|1.4] [--random-serial]
```

`node sbom-lite.mjs` is how you run it from a clone. It needs Node 22 or later and nothing else. It is not on npm yet, so there is no `npx sbom-lite`.

| Option | Meaning |
| --- | --- |
| `lockfile` | The lock file to read, relative to the current directory or absolute. Default: `package-lock.json` in the current directory. At most one. |
| `--include-dev` | Also list the packages that only development needs. Without it they are left out. |
| `--now <time>` | The time written to `metadata.timestamp`. Without it, the current time. |
| `--out <file>` | Write the document to this file (created or replaced; its folder must exist) instead of standard output. Standard output then holds nothing. |
| `--spec 1.5\|1.4` | The CycloneDX version of the document. Default `1.5`. Only `specVersion` and the form of `metadata.tools` change. |
| `--random-serial` | Use a random serial number instead of the one derived from the lock file. |

An option that takes a value takes the next argument, whatever it looks like. `--now=...` is not a form: it is an unknown option. An argument that starts with `-` and is not one of the options is an unknown option; any other argument is the lock file. All arguments are checked before any file is read.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The document was written. Nothing is printed on standard error. |
| `1` | The lock file cannot be read, is not valid JSON, is not supported, or `--out` cannot be written. A message on standard error, nothing on standard output, no `--out` file created. |
| `2` | A usage error: an unknown option, an option whose value is missing, a `--spec` other than `1.5` or `1.4`, an invalid `--now`, or more than one lock file. A message on standard error, nothing on standard output, no file written. |

### The time

`--now` takes `YYYY-MM-DD` (midnight), or `YYYY-MM-DDTHH:MM`, `YYYY-MM-DDTHH:MM:SS` or `YYYY-MM-DDTHH:MM:SS.f` (one to three digits of fraction), each `T` form optionally followed by `Z` or an offset `+HH:MM` / `-HH:MM`. With no `Z` and no offset the time is UTC. The year is 1970 to 2999, the day must exist in its month (`2026-02-30` is not valid), hours are 00 to 23, minutes and seconds 00 to 59. The timestamp written is the moment in UTC as `YYYY-MM-DDTHH:MM:SS.sssZ`.

## What it reads

Only `package-lock.json` files with `lockfileVersion` 2 or 3 and a `packages` object. Version 1 files, and anything else, exit 1. Only `packages` is read; the legacy `dependencies` tree of version 2 is ignored. A leading byte-order mark is ignored. sbom-lite does not verify licences and does not look anything up.

An entry of `packages` is a **candidate** when its key is `node_modules/<name>` or ends in `/node_modules/<name>`, its value is an object, its `link` is not `true`, and its `version` is a non-empty string. Workspace folders, links and entries without a version are ignored. A candidate with `"dev": true` is a dev entry; it is a **component** unless it is a dev entry and `--include-dev` was not given.

The **full name** of a component is the entry's `name` when that is a non-empty string (npm aliases: `node_modules/foo` with `"name": "bar"` is the package `bar`), else the name in the key.

## The exact choices

**Serial number.** Without `--random-serial`: the SHA-256 digest of the lock file's exact bytes (before any byte-order mark is removed), its first 16 bytes, with `byte[6] = (byte[6] & 0x0f) | 0x80` and `byte[8] = (byte[8] & 0x3f) | 0x80`, written as lower-case hexadecimal in groups 8-4-4-4-12 after `urn:uuid:`. The same lock file gives the same serial number whatever the options. With `--random-serial`, a random version 4 UUID.

**Root component.** `type` `application`, `bom-ref` `root`. Its name is the root package's `name` (the `""` entry), else the lock file's top-level `name`, else `unnamed`; its version is the root package's `version`, else the top-level `version`, else none (and then the purl has no `@` part).

**Group and name.** A full name is scoped when it starts with `@` and holds a `/`: `group` is the text before the first `/` with its `@` (`@acme`), `name` the text after it (`core`). Unscoped names have no `group`.

**purl.** `pkg:npm/` + (group + `/`) + name + `@` + version. The group, name and version are percent-encoded: every UTF-8 byte is written as is when it is one of `A-Z a-z 0-9 . - _ ~` and as `%` plus two upper-case hexadecimal digits otherwise. So `@acme` becomes `%40acme` and `1.0.0+build.5` becomes `1.0.0%2Bbuild.5`. The case of names is never changed.

**bom-ref.** The purl, unless two or more listed components have the same purl (two copies of one version in different places of `node_modules`): then each copy's `bom-ref` is its purl, `#`, and its lock key, for example `pkg:npm/tiny@1.0.1#node_modules/a/node_modules/tiny`. Copies are counted among the components listed, so a left-out dev copy does not make another one a duplicate.

**Scope.** `optional` when the entry has `dev`, `optional` or `devOptional` true; `required` otherwise.

**Hashes.** From `integrity`: each whitespace-separated token of the form `<algorithm>-<base64>` (optionally `?` and anything) with algorithm `sha512`, `sha384`, `sha256` or `sha1`, standard padded base64, and exactly 64, 48, 32 or 20 decoded bytes, gives `{"alg": "SHA-512" | "SHA-384" | "SHA-256" | "SHA-1", "content": <lower-case hex>}`. In the order of the tokens; a repeated algorithm counts once (the first). Other tokens are ignored; no usable token, no `hashes`.

**Licences.** When `license` is a non-empty string (after trimming), the trimmed text is a `license.id` if it is exactly one of the ids below (same case), and a `license.name` otherwise: `(MIT OR Apache-2.0)`, `Apache 2.0`, `GPL-3.0`, `mit` and `SEE LICENSE IN LICENSE` are names. Any other `license` (missing, empty, an object, an array) gives no `licenses`.

`0BSD`, `AGPL-3.0-only`, `AGPL-3.0-or-later`, `Apache-2.0`, `Artistic-2.0`, `BlueOak-1.0.0`, `BSD-2-Clause`, `BSD-3-Clause`, `CC-BY-3.0`, `CC-BY-4.0`, `CC0-1.0`, `EPL-2.0`, `GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `ISC`, `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later`, `MIT`, `MIT-0`, `MPL-2.0`, `Python-2.0`, `Unlicense`, `WTFPL`, `Zlib`.

**External references.** A `distribution` reference with the entry's `resolved` as written, only when it starts with `http://` or `https://`.

**Order.** `components` are sorted by full name, then version, then lock key, each with JavaScript's `<` on strings (UTF-16 code unit order: `"B"` before `"a"`, `"10.0.0"` before `"9.0.0"`).

**Dependencies.** The names a package depends on are the keys of its `dependencies`, `optionalDependencies` and `peerDependencies` (for the root package also `devDependencies`, with `--include-dev`). Each name is resolved as npm does, nearest `node_modules` first: for the package at key `K`, `K/node_modules/<name>`, then the same under each parent, up to `node_modules/<name>`. The first key that is a candidate wins; a name with no answer, or whose answer is a left-out dev entry, is dropped. `dependsOn` holds the `bom-ref`s, each once, sorted, never the component itself. The list starts with the root, then one entry per component in the order of `components`.

## Tests

```sh
node --test
```

## Where it came from

Built by agents on TickHub, as TickHub job `ee04b135-bcf3-40df-b815-9b941352aa78`. The job, the hand-ins and the receipt are on TickHub's public log: https://tick.company/hub/#/job/ee04b135-bcf3-40df-b815-9b941352aa78

`docs/the-job.md` is the job as it was given.

AI does the work. Tick makes it trustworthy. https://tick.company

## Licence

Apache-2.0, Copyright 2026 Parsa Esmaeili, see `LICENSE`.
