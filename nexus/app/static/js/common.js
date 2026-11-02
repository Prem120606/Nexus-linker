const $ = id => document.getElementById(id);

const fmtSize = n => n < 1024 ? n + " B"
  : n < 1048576 ? (n / 1024).toFixed(1) + " KB"
  : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB"
  : (n / 1073741824).toFixed(2) + " GB";

async function api(path, method = "GET", body) {
  const opt = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

const errText = d => typeof d.detail === "string" ? d.detail : "Please check what you entered";

function toast(msg, bad) {
  const t = document.createElement("div");
  t.className = "toast" + (bad ? " bad" : "");
  t.textContent = msg;               // never innerHTML with dynamic text
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

function setPill(el, text, kind) {   // kind: "ok" | "bad" | ""
  el.textContent = text;
  el.className = "pill" + (kind ? " " + kind : "");
}

// Pages always live inside the shell (/), so transfers survive switching tabs
const VIEWS = ["/home", "/chat", "/files", "/pairing"];
const framed = window.top !== window;
if (!framed && VIEWS.includes(location.pathname)) location.replace("/#" + location.pathname);
if (framed) document.documentElement.classList.add("framed");
document.querySelectorAll("#tabs").forEach(n => n.remove());   // the shell has its own dock

// Live connection: fast retries, stuck-handshake watchdog, wakes up on network return
function live(handlers) {
  let ws, delay = 500, pinger, watchdog, retryTimer, stopped = false;

  function connect() {
    if (stopped) return;
    clearTimeout(retryTimer);
    ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");

    // If it isn't open within 4s (flaky hotspot), drop it and retry
    watchdog = setTimeout(() => { if (ws.readyState !== 1) ws.close(); }, 4000);

    ws.onopen = () => {
      clearTimeout(watchdog);
      delay = 500;
      pinger = setInterval(() => ws.readyState === 1 && ws.send("ping"), 15000);
      handlers.open && handlers.open();
    };
    ws.onmessage = e => {
      let ev; try { ev = JSON.parse(e.data); } catch { return; }
      handlers[ev.type] && handlers[ev.type](ev);
    };
    ws.onerror = () => {};                       // onclose always follows
    ws.onclose = e => {
      clearTimeout(watchdog); clearInterval(pinger);
      if (e.code === 4401 || e.code === 4403) {  // not allowed: stop retrying
        stopped = true;
        handlers.denied ? handlers.denied() : toast("Disconnected. Pair again.", true);
        return;
      }
      handlers.close && handlers.close();
      retryTimer = setTimeout(connect, delay);
      delay = Math.min(delay * 2, 5000);         // 0.5s, 1s, 2s, 4s, then every 5s
    };
  }

  const wake = () => { if (!stopped && (!ws || ws.readyState > 1)) { delay = 500; connect(); } };
  document.addEventListener("visibilitychange", () => { if (!document.hidden) wake(); });
  window.addEventListener("online", wake);       // Wi-Fi came back: reconnect immediately
  connect();
}
