#!/usr/bin/env node
/*
  Cipher Forge is one HTML file, so `node --check` cannot be pointed at it directly. This script:
    1. pulls every inline <script> block out of index.html and syntax-checks each one with `node --check`;
    2. loads the page's pure "core" block (the ciphers and the attacks, no DOM) into a vm sandbox and asserts
       encode/decode round trips and that the blind attacks recover what they should.

      node tests/check.js        exit 0 = all passed
*/
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { spawnSync } = require('child_process');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
let fail = 0;
const check = (what, ok) => { console.log((ok ? 'ok   ' : 'FAIL ') + what); if (!ok) fail++; };

// 1. every inline <script> block parses
const blocks = [];
const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
let m;
while ((m = re.exec(html)) !== null) blocks.push(m[1]);
check('found inline <script> blocks: ' + blocks.length, blocks.length >= 1);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cipher-forge-'));
blocks.forEach((src, i) => {
  const f = path.join(tmp, 'block-' + i + '.js');
  fs.writeFileSync(f, src);
  const r = spawnSync(process.execPath, ['--check', f], { encoding: 'utf8' });
  check('node --check script block ' + i + (r.status === 0 ? '' : '\n' + r.stderr), r.status === 0);
});
fs.rmSync(tmp, { recursive: true, force: true });

// 2. the core block: everything between the "core" banner and the next banner
const start = html.indexOf('/* ============================ core');
const end = html.indexOf('/* ============================', start + 10);
check('core block located', start > 0 && end > start);
const core = html.slice(start, end);
const names = ['strToBytes', 'bytesToStr', 'toHex', 'fromHex', 'toB64', 'xorKey', 'caesar', 'rc4', 'toyEcb',
  'scoreEnglish', 'crackSingleXor', 'crackRepeatingXor', 'hamming', 'detectEcb', 'entropy'];
const sandbox = { TextEncoder, TextDecoder, btoa: s => Buffer.from(s, 'binary').toString('base64'), Uint8Array, Math };
vm.createContext(sandbox);
vm.runInContext(core + '\n;__exports = {' + names.join(',') + '};', sandbox);
const C = sandbox.__exports;
check('core exports every function', names.every(n => typeof C[n] === 'function'));

const text = 'The quick brown fox jumps over the lazy dog, then it does it again and again until the sentence is long enough ' +
  'for frequency analysis to work on it. A repeating key leaks its length through the Hamming distance between ' +
  'blocks of the ciphertext, and once the length is known every column is a single-byte problem that English ' +
  'letter frequencies solve on their own. Short messages hide this; a few hundred characters of ordinary prose do not.';
const pt = C.strToBytes(text);
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

check('hex round trip', same(C.fromHex(C.toHex(pt)), pt));
check('base64 matches Buffer', C.toB64(pt) === Buffer.from(pt).toString('base64'));
check('caesar round trip', same(C.caesar(C.caesar(pt, 3), (256 - 3) % 256), pt));
const key = C.strToBytes('ICE');
check('repeating-key xor round trip', same(C.xorKey(C.xorKey(pt, key), key), pt));
check('rc4 round trip', same(C.rc4(C.rc4(pt, key), key), pt));
check('toy ecb round trip (padding removed)', same(C.toyEcb(C.toyEcb(pt, key, 1), key, -1), pt));
check('toy ecb pads to a block multiple', C.toyEcb(pt, key, 1).length % 8 === 0);

const sb = C.crackSingleXor(C.xorKey(pt, new Uint8Array([0x58])));
check('single-byte xor brute force recovers 0x58', sb.key === 0x58);
const rep = C.crackRepeatingXor(C.xorKey(pt, key));
const repKey = rep ? C.bytesToStr(rep.key) : '';
check('repeating-key xor attack recovers the plaintext', rep && same(rep.pt, pt));
check('recovered key is "ICE" (possibly reported at a multiple of its length): ' + JSON.stringify(repKey),
  repKey.length > 0 && repKey.length % 3 === 0 && repKey === 'ICE'.repeat(repKey.length / 3));

const repeated = C.strToBytes('ABCDEFGH'.repeat(6));
check('ecb detection sees repeated blocks', C.detectEcb(C.toyEcb(repeated, key, 1)).likelyEcb === true);
check('entropy of a constant is 0', C.entropy(new Uint8Array(64)) === 0);
const all = new Uint8Array(256).map((_, i) => i);
check('entropy of all 256 byte values is 8 bits', Math.abs(C.entropy(all) - 8) < 1e-9);
check('english scores above noise', C.scoreEnglish(pt) > C.scoreEnglish(C.rc4(pt, key)));

console.log(fail ? fail + ' failed' : 'all passed');
process.exit(fail ? 1 : 0);
