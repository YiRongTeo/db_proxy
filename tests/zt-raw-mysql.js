// Raw MySQL wire client for Task 8.14 gate evidence (tests/harness only).
// Usage: node zt-raw-mysql.js <token> < host-port-commands.jsonl
// stdin: one JSON object per line: {"at": <ms after connect>, "sql": "..."}
// stdout: @<ms> lines: CONNECTED / SEND <sql> / RESP OK [info] / RESP ROWS [...] /
//         RESP ERR <code> <msg> / RESP EOF-COUNT <n> / CLOSED / state lines.
// Exit 0 on clean close; 2 on wire error.
const net = require('net');
const token = process.argv[2];
if (!token) { console.error('usage: node zt-raw-mysql.js <token>'); process.exit(2); }

const t0 = Date.now();
const at = () => Date.now() - t0;

// --- tiny MySQL packet framing -------------------------------------------
let buf = Buffer.alloc(0);
function readPacket(sock, cb) {
  const need = 4;
  if (buf.length < need) return;
  const len = buf.readUIntLE(0, 3);
  const total = 4 + len;
  if (buf.length < total) return;
  const seqByte = buf[3];
  const pkt = buf.subarray(4, total);
  buf = buf.subarray(total);
  if (process.env.DEBUG) console.error(`PKT len=${len} seq=${seqByte} hex=${pkt.subarray(0, 120).toString('hex')}`);
  cb(pkt);
}
function sendPacket(sock, seq, payload) {
  const hdr = Buffer.alloc(4);
  hdr.writeUIntLE(payload.length, 0, 3);
  hdr[3] = seq;
  sock.write(Buffer.concat([hdr, payload]));
}
function lenenc(s) {
  const b = Buffer.from(s, 'utf8');
  if (b.length < 251) return Buffer.concat([Buffer.from([b.length]), b]);
  if (b.length < 65536) { const h = Buffer.alloc(3); h.writeUIntLE(b.length, 0, 3); return Buffer.concat([Buffer.from([0xfc]), h, b]); }
  const h = Buffer.alloc(4); h.writeUIntLE(b.length, 0, 4);
  return Buffer.concat([Buffer.from([0xfd]), h, b]);
}
function readLenenc(p, off) {
  const first = p[off];
  if (first < 251) return [p.subarray(off + 1, off + 1 + first), off + 1 + first];
  if (first === 0xfc) { const n = p.readUIntLE(off + 1, 2); return [p.subarray(off + 3, off + 3 + n), off + 3 + n]; }
  if (first === 0xfd) { const n = p.readUIntLE(off + 1, 3); return [p.subarray(off + 4, off + 4 + n), off + 4 + n]; }
  if (first === 0xfb) return [null, off + 1]; // NULL
  throw new Error('lenenc 0xfe/0xff in unexpected position');
}

// --- client state ----------------------------------------------------------
let phase = 'handshake'; // handshake | authed | resultset(cols expected) | done
let capFlags = 0;
let seq = 0;
let colCount = 0;
let colDefs = [];
let rows = [];
let resultStarted = false;
let readingRows = false;
let authDone = false;     // set on the auth OK packet; only later OK/ERR count as command responses
let sentCount = 0;      // commands sent to the server
let respCount = 0;      // commands answered (ERR/OK/result set)
let scheduledCount = 0; // commands parsed from stdin (scheduled or sent)
let stdinClosed = false;
let exitTimer = null;
const sock = net.connect(3306, '127.0.0.1');

// Exit once stdin is closed AND every scheduled command has been sent AND
// answered (or 20 s after the last send as a safety net).
function maybeExit() {
  if (!stdinClosed) return;
  if (scheduledCount === sentCount && sentCount === respCount) { sock.end(); setTimeout(() => process.exit(0), 300); }
}
function armExitWatchdog() {
  if (exitTimer) clearTimeout(exitTimer);
  exitTimer = setTimeout(() => { console.error(`@${at()} WATCHDOG: no response within 20s of last send (sent=${sentCount} resp=${respCount})`); process.exit(3); }, 20000);
}

function parseColumns(p) {
  // ColumnDefinition41: NO type marker — the packet starts directly with the
  // lenenc catalog (usually 0x03 "def"), schema, table, org_table, name,
  // org_name, then 0x0c + charset(2) + colLen(4) + type(1) + flags(2) +
  // decimals(1) + filler(2).
  let off = 0;
  const [catalog, o1] = readLenenc(p, off); off = o1;
  const [schema, o2] = readLenenc(p, off); off = o2;
  const [table, o3] = readLenenc(p, off); off = o3;
  const [orgTable, o4] = readLenenc(p, off); off = o4;
  const [name, o5] = readLenenc(p, off); off = o5;
  const [orgName, o6] = readLenenc(p, off); off = o6;
  void catalog; void schema; void table; void orgTable; void orgName;
  const type = p[off + 7]; // fixed-len byte + charset(2) + colLen(4)
  return { name: name ? name.toString() : '', type };
}

function onPacket(pkt) {
  if (phase === 'handshake') {
    const proto = pkt[0];
    if (proto !== 0x0a) { console.error(`@${at()} FATAL: not a MySQL handshake (first byte ${proto})`); sock.destroy(); process.exit(2); }
    let off = 1;
    while (pkt[off] !== 0) off++; off++; // server version
    off += 4; // thread id
    const auth1 = pkt.subarray(off, off + 8); off += 8;
    off += 1; // filler
    capFlags = pkt.readUInt16LE(off); off += 2;
    const charset = pkt[off]; off += 1;
    off += 2; // status
    const capHigh = pkt.readUInt16LE(off); off += 2;
    capFlags |= capHigh << 16;
    const authLen = pkt[off]; off += 1;
    off += 10; // reserved
    let auth2 = Buffer.alloc(0);
    if (capFlags & 0x00080000) { // CLIENT_PLUGIN_AUTH
      auth2 = pkt.subarray(off, off + Math.max(13, authLen - 8)); off += Math.max(13, authLen - 8);
      while (pkt[off] !== 0) off++; off++;
    } else {
      auth2 = pkt.subarray(off, off + 12); off += 12;
    }
    void charset;
    // HandshakeResponse41
    const caps = 0x00000201 | 0x00008000 | 0x00080000; // LONG_PASSWORD | PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH
    const h = Buffer.alloc(4);
    h.writeUInt32LE(caps, 0);
    const maxpkt = Buffer.alloc(4); maxpkt.writeUInt32LE(0x40000000, 0);
    const chrs = Buffer.from([0x21]); // utf8
    const filler23 = Buffer.alloc(23);
    const user = Buffer.concat([Buffer.from(token, 'utf8'), Buffer.from([0])]);
    const authResp = Buffer.from([0]); // empty password, 1-byte length
    const plugin = Buffer.concat([Buffer.from('mysql_native_password'), Buffer.from([0])]);
    sendPacket(sock, 1, Buffer.concat([h, maxpkt, chrs, filler23, user, authResp, plugin]));
    phase = 'authed';
    console.log(`@${at()} CONNECTED (cap=0x${caps.toString(16)})`);
    return;
  }
  if (phase === 'authed' || phase === 'resultset') {
    const first = pkt[0];
    if (first === 0xff) { // ERR
      const code = pkt.readUInt16LE(1);
      let msg = '';
      let off = 3;
      if (pkt[off] === 0x23) { off += 6; } // #sqlstate
      msg = pkt.subarray(off).toString();
      console.log(`@${at()} RESP ERR ${code} ${msg}`);
      phase = 'authed'; colCount = 0; colDefs = []; rows = []; resultStarted = false; readingRows = false;
      if (authDone) { respCount++; maybeExit(); }
      return;
    }
    if (first === 0x00) { // OK — the first one is the auth OK (not a command response)
      console.log(`@${at()} RESP OK`);
      phase = 'authed'; colCount = 0; colDefs = []; rows = []; resultStarted = false; readingRows = false;
      if (authDone) { respCount++; maybeExit(); } else { authDone = true; }
      return;
    }
    if (first === 0xfb) { console.log(`@${at()} RESP LOCAL INFILE (unexpected)`); phase = 'authed'; return; }
    // result set: column count (lenenc — a byte < 0xfb IS the value)
    if (!resultStarted) {
      colCount = pkt[0];
      resultStarted = true;
      colDefs = [];
      console.log(`@${at()} RESP COLUMNS ${colCount}`);
      return;
    }
    if (colDefs.length < colCount) {
      colDefs.push(parseColumns(pkt));
      return;
    }
    if (first === 0xfe && pkt.length < 9) { // EOF
      if (!readingRows) { readingRows = true; return; } // EOF after coldefs → rows follow
      console.log(`@${at()} RESP ROWS ${JSON.stringify(rows)}`);
      phase = 'authed'; colCount = 0; colDefs = []; rows = []; resultStarted = false; readingRows = false;
      respCount++; maybeExit();
      return;
    }
    // row packet
    let off = 0; const r = [];
    for (let i = 0; i < colCount; i++) {
      const [v, o] = readLenenc(pkt, off); off = o;
      r.push(v === null ? null : v.toString());
    }
    rows.push(r);
    return;
  }
}

sock.on('data', (d) => {
  buf = Buffer.concat([buf, d]);
  while (true) {
    const before = buf.length;
    readPacket(sock, (pkt) => {
      seq = (pkt[3] || 0); // not used; response seq tracked implicitly
      onPacket(pkt);
    });
    if (buf.length === before) break;
  }
});
sock.on('error', (e) => { console.error(`@${at()} SOCK_ERR ${e.message}`); process.exit(2); });
sock.on('close', () => { console.log(`@${at()} CLOSED`); process.exit(0); });

// --- stdin command schedule -------------------------------------------------
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  line = line.trim();
  if (!line) return;
  const cmd = JSON.parse(line);
  scheduledCount++;
  setTimeout(() => {
    if (sock.destroyed) { console.error(`@${at()} SEND SKIPPED (closed): ${cmd.sql}`); return; }
    const payload = Buffer.concat([Buffer.from([0x03]), Buffer.from(cmd.sql, 'utf8')]); // COM_QUERY
    console.log(`@${at()} SEND ${cmd.sql}`);
    sentCount++;
    armExitWatchdog();
    sendPacket(sock, 0, payload);
  }, cmd.at);
});
rl.on('close', () => { stdinClosed = true; maybeExit(); /* keep socket open until commands answered */ });
