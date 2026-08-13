// WS listener for Task 8.14 gate. Usage: node zt-ws-listen.js <channel> <cookie> <timeoutMs>
// Prints each event as EVENT: <json> and exits 0 after timeoutMs. Exit 2 on error.
const channel = process.argv[2];
const cookie = process.argv[3];
const timeoutMs = parseInt(process.argv[4] || "15000", 10);
const ws = new WebSocket(`ws://127.0.0.1:8080/ws/checker?channel=${channel}`, {
  headers: { Cookie: `zt_session=${cookie}` },
});
const t0 = Date.now();
ws.onmessage = (e) => { console.log(`EVENT@${Date.now() - t0}ms:`, e.data); };
ws.onerror = (e) => { console.error("WS_ERR:", e.message || e.error || "no msg"); };
ws.onclose = (e) => { console.error(`CLOSE code=${e.code} reason=${e.reason}`); process.exit(e.code === 1000 ? 0 : 1); };
setTimeout(() => { ws.close(); }, timeoutMs);
