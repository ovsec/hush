'use strict';

// hush web UI. All values are inserted as text nodes, never as HTML.

const root = document.getElementById('app');
const S = {
  status: null, info: {}, code: '', safety: '',
  items: [], q: '', sel: null, open: null, showPass: false,
  editing: null, confirm: null, raw: null,
  tab: 'secrets', members: [], adding: null,
  events: [], seen: new Set(), activity: true,
  started: 0, busy: false, clipGen: 0,
};

// ── tiny DOM helper ─────────────────────────────────────

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

async function api(method, path, body) {
  const opts = { method, headers: { 'X-Hush': '1' }, credentials: 'same-origin' };
  if (body instanceof Blob) {
    opts.body = body;
    opts.headers['Content-Type'] = 'application/octet-stream';
  } else if (body !== undefined) {
    opts.body = JSON.stringify(body);
    opts.headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, opts);
  const data = (res.headers.get('content-type') || '').includes('json') ? await res.json() : null;
  if (!res.ok) {
    if (res.status === 423 || res.status === 401) setTimeout(refresh, 0);
    throw new Error((data && data.error) || res.statusText);
  }
  return data;
}

function toast(msg, bad) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.className = ''; }, 3400);
}

const fail = (e) => toast(e.message, true);

function ago(iso) {
  const t = Date.parse(iso);
  if (!t || t < 0) return 'never';
  const s = (Date.now() - t) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  if (s < 2592000) return Math.floor(s / 86400) + 'd ago';
  return new Date(t).toLocaleDateString();
}

const clock = (iso) => new Date(iso).toTimeString().slice(0, 8);

// ── state ───────────────────────────────────────────────

async function refresh() {
  try {
    const st = await api('GET', '/api/state');
    Object.assign(S, { status: st.status, info: st.info, code: st.code || '', safety: st.safety || '', net: st });
    if (S.info.unlocked) {
      S.items = await api('GET', '/api/items');
      if (S.tab === 'members') S.members = await api('GET', '/api/members');
      if (S.sel && !S.items.some((i) => i.id === S.sel)) S.sel = null;
    } else {
      Object.assign(S, { items: [], sel: null, open: null, editing: null, confirm: null, raw: null, busy: false });
    }
  } catch (e) {
    fail(e);
  }
  render();
}

// refreshSoon coalesces bursts of sync events into one refresh.
function refreshSoon() {
  clearTimeout(refreshSoon.t);
  refreshSoon.t = setTimeout(refresh, 250);
}

function connectEvents() {
  const es = new EventSource('/api/events');
  es.onmessage = (msg) => {
    const ev = JSON.parse(msg.data);
    const key = ev.at + ev.kind + ev.msg;
    if (S.seen.has(key)) return;
    S.seen.add(key);
    S.events.push(ev);
    if (S.events.length > 300) S.events.shift();
    renderActivity();
    renderSteps();
    if (ev.kind === 'lock' && S.info.unlocked) refresh();
    if (['merge', 'online', 'offline'].includes(ev.kind) && S.info.unlocked && !S.editing && !S.adding) refreshSoon();
  };
}

// ── layout ──────────────────────────────────────────────

function render() {
  const unlocked = S.info.unlocked;
  let body;
  if (!unlocked) body = gate();
  else if (S.tab === 'members') body = membersView();
  else body = secretsView();
  root.replaceChildren(topbar(), body, activityPanel(), S.raw ? rawModal() : '');
  if (unlocked && S.tab === 'secrets') { renderList(); renderDetail(); }
  renderActivity();
  renderSteps();
  const focus = root.querySelector('[data-autofocus]');
  if (focus) focus.focus();
}

function topbar() {
  const unlocked = S.info.unlocked;
  const name = S.status === 'pending' ? 'joining a team' : (S.info.vault || 'hush');
  const tab = (id, label) => h('button', {
    class: 'tab', role: 'tab', 'aria-selected': String(S.tab === id),
    onclick: async () => { S.tab = id; S.adding = null; S.confirm = null; await refresh(); },
  }, label);
  return h('header', { class: 'top' },
    h('span', { class: 'brand' }, 'hush'),
    h('span', { class: 'crumb' }, '/'),
    h('span', null, name),
    unlocked && h('nav', { class: 'tabs', role: 'tablist' }, tab('secrets', 'Secrets'), tab('members', 'Members')),
    h('span', { class: 'spacer' }),
    unlocked
      ? h('span', { class: 'pill' }, `● unlocked · ${S.items.length} secrets` + (S.net && S.net.syncing ? ` · ${S.net.online}/${S.net.others} online` : ''))
      : h('span', { class: 'pill locked' }, '○ locked'),
    unlocked && h('button', { class: 'btn small', onclick: () => api('POST', '/api/lock').then(refresh, fail) }, 'Lock'),
  );
}

function activityPanel() {
  const always = !S.info.unlocked;
  const open = always || S.activity;
  return h('section', { class: 'activity' + (open ? '' : ' closed'), 'aria-label': 'activity' },
    h('header', null,
      h('span', { class: 'dot' }),
      h('span', { class: 'label' }, 'activity'),
      h('span', { class: 'tiny' }, 'what hush is doing, as it happens'),
      h('span', { class: 'spacer' }),
      !always && h('button', { class: 'btn ghost small', onclick: () => { S.activity = !S.activity; render(); } }, open ? 'hide' : 'show'),
    ),
    open && h('div', { class: 'log', id: 'log' }),
  );
}

function renderActivity() {
  const log = document.getElementById('log');
  if (!log) return;
  const stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 24;
  log.replaceChildren(...S.events.slice(-150).map((e) =>
    h('div', { class: 'ev' + (e.kind === 'deny' ? ' deny' : '') },
      h('time', null, clock(e.at)), h('span', { class: 'k' }, e.kind), h('span', { class: 'm' }, e.msg))));
  if (stick) log.scrollTop = log.scrollHeight;
}

// ── gate: no vault, pending, unlock, removed ────────────

const UNLOCK_STEPS = [
  ['kdf', 'stretch your passphrase with argon2id into a 256-bit key'],
  ['open', 'decrypt your private keys from identity.json'],
  ['verify', 'check every signature and hash link in ops.jsonl'],
  ['unwrap', 'open the vault key that was sealed to you'],
  ['index', 'decrypt titles to build the list; passwords stay sealed'],
];

function gate() {
  let card;
  if (S.status === 'none') {
    card = [
      h('h2', null, 'No vault here yet'),
      h('p', { class: 'sub' }, 'Create or join one in the terminal by running hush, then come back.'),
      h('p', { class: 'tiny' }, S.info.dir || ''),
    ];
  } else if (S.status === 'pending') {
    card = pendingCard();
  } else if (S.status === 'removed') {
    card = [
      h('h2', null, 'You were removed'),
      h('p', { class: 'sub' }, 'The admin removed this identity from the vault. Its key is no longer accepted, and newer secrets are sealed with a key you do not have.'),
    ];
  } else {
    card = unlockCard();
  }
  return h('main', { class: 'gate' }, h('div', { class: 'card' }, card));
}

function unlockCard() {
  const pass = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'passphrase', 'data-autofocus': true, 'aria-label': 'passphrase' });
  const err = h('p', { class: 'err', id: 'unlock-err' });
  const submit = async (ev) => {
    ev.preventDefault();
    S.started = Date.now() - 200;
    S.busy = true;
    err.textContent = '';
    renderSteps();
    const value = pass.value;
    pass.value = '';
    try {
      await api('POST', '/api/unlock', { passphrase: value });
      S.busy = false;
      await refresh();
    } catch (e) {
      S.busy = false;
      err.textContent = e.message;
      renderSteps();
      pass.focus();
    }
  };
  const info = S.info;
  return [
    h('h2', null, info.vault),
    h('p', { class: 'sub' }, `${info.me} · safety number `, h('span', { class: 'value' }, info.safety)),
    h('p', { class: 'tiny' }, `${info.secrets} secrets · ${info.ops} ops · key epoch ${info.epoch} · ${info.members} member(s)`),
    info.admin && !info.is_admin && h('p', { class: 'tiny' }, `admin ${info.admin} · ${info.admin_safety} · check it with them`),
    h('form', { class: 'form', onsubmit: submit },
      h('div', { class: 'inline' }, pass, h('button', { class: 'btn primary', type: 'submit' }, 'Unlock'))),
    err,
    h('ul', { class: 'steps', id: 'steps', 'data-steps': 'unlock' }),
  ];
}

function renderSteps() {
  const ul = document.getElementById('steps');
  if (!ul) return;
  const seen = new Set();
  let failed = false;
  if (S.started) {
    for (const e of S.events) {
      if (Date.parse(e.at) >= S.started) {
        seen.add(e.kind);
        failed = failed || e.kind === 'deny';
      }
    }
  }
  let current = true;
  ul.replaceChildren(
    h('li', { class: 'title' }, h('span', { class: 'eyebrow' }, 'what happens when you unlock')),
    ...UNLOCK_STEPS.map(([kind, text], i) => {
      let cls = '', mark = String(i + 1).padStart(2, '0');
      if (seen.has(kind)) { cls = 'done'; mark = '✓'; }
      else if (current && S.busy) { cls = 'cur'; mark = '•'; current = false; }
      else if (current && failed) { cls = 'fail'; mark = '✕'; current = false; }
      return h('li', { class: cls }, h('span', { class: 'n' }, mark), h('span', null, text));
    }));
}

function pendingCard() {
  return [
    h('h2', null, 'Waiting to be added'),
    h('p', { class: 'sub' }, 'Send this join code to your vault admin. It holds only your name and public keys.'),
    h('div', { class: 'code' }, S.code),
    h('button', { class: 'btn small', onclick: () => copyText(S.code, 'code', 'join code') }, 'Copy join code'),
    h('p', { class: 'sub' }, 'safety number'),
    h('div', { class: 'safety' }, S.safety),
    h('p', { class: 'tiny' }, 'Your admin sees this same number when adding you. Read it to each other on a call or in person.'),
    h('div', { class: 'actions' }, importButton('Import the bundle they send')),
  ];
}

function importButton(label) {
  const input = h('input', {
    type: 'file', 'aria-label': label,
    onchange: async () => {
      const file = input.files[0];
      if (!file) return;
      try {
        const res = await api('POST', '/api/import', file);
        toast(`${res.added} new ops verified and merged · ${res.known} already known`);
        if (res.rejected && res.rejected.length) toast(`${res.rejected.length} op(s) rejected: ${res.rejected[0]}`, true);
      } catch (e) {
        fail(e);
      }
      await refresh();
    },
  });
  return h('label', { class: 'btn file' }, label, input);
}

// ── secrets ─────────────────────────────────────────────

function secretsView() {
  const search = h('input', {
    type: 'search', placeholder: 'Search', value: S.q, id: 'search', 'aria-label': 'search secrets',
    oninput: (e) => { S.q = e.target.value; renderList(); },
  });
  return h('main', { class: 'main' + (S.sel || S.editing ? ' showing' : ''), id: 'main' },
    h('aside', { class: 'side' },
      h('div', { class: 'search' }, search, h('button', { class: 'btn', onclick: () => edit(null) }, 'New')),
      h('nav', { class: 'list', id: 'list', 'aria-label': 'secrets' })),
    h('section', { class: 'detail', id: 'detail' }));
}

function visible() {
  const q = S.q.trim().toLowerCase();
  return S.items.filter((i) => !q || `${i.title} ${i.username} ${i.url}`.toLowerCase().includes(q));
}

function renderList() {
  const list = document.getElementById('list');
  if (!list) return;
  const items = visible();
  if (!items.length) {
    list.replaceChildren(h('p', { class: 'none' }, S.q ? 'No matches' : 'Empty'));
    return;
  }
  list.replaceChildren(...items.map((it) =>
    h('button', { class: 'row' + (it.id === S.sel ? ' sel' : ''), 'aria-label': it.title, 'aria-current': it.id === S.sel ? 'true' : null, onclick: () => select(it.id) },
      h('span', { class: 't' }, it.title),
      it.exposed?.length > 0 && h('span', { class: 'flag', title: 'a removed member could read this' }, '!'),
      h('span', { class: 'u' }, it.username))));
}

function select(id) {
  Object.assign(S, { sel: id, open: null, showPass: false, editing: null, confirm: null });
  document.getElementById('main').classList.add('showing');
  renderList();
  renderDetail();
}

function back() {
  Object.assign(S, { sel: null, open: null, editing: null, confirm: null });
  document.getElementById('main').classList.remove('showing');
  renderList();
  renderDetail();
}

const current = () => S.items.find((i) => i.id === S.sel);

async function decrypt() {
  if (S.open && S.open.id === S.sel) return S.open;
  const id = S.sel;
  const entry = await api('GET', `/api/items/${encodeURIComponent(id)}`);
  S.open = Object.assign(entry, { id });
  return S.open;
}

function renderDetail() {
  const pane = document.getElementById('detail');
  if (!pane) return;
  if (S.editing) return pane.replaceChildren(editor());
  const it = current();
  if (!it) {
    return pane.replaceChildren(h('div', { class: 'empty' },
      h('h1', null, S.items.length ? 'Pick a secret' : 'Nothing here yet'),
      h('p', null, S.items.length ? 'Choose one on the left to see it.' : 'Press New to add your first secret.'),
      h('p', { class: 'tiny' }, 'Secrets are encrypted with xchacha20-poly1305 before anything is written to disk.')));
  }
  const open = S.open && S.open.id === it.id ? S.open : null;
  const sealed = (label) => h('span', { class: 'sealed' }, label || 'sealed');
  const btn = (label, fn) => h('button', { class: 'btn small', onclick: () => fn().catch(fail) }, label);

  const pw = open
    ? h('span', { class: 'value' + (S.showPass ? ' secret' : '') }, S.showPass ? open.password : '•'.repeat(Math.min(16, [...open.password].length)))
    : sealed('sealed · decrypt to see');
  const url = /^https?:\/\//i.test(it.url)
    ? h('a', { class: 'value', href: it.url, target: '_blank', rel: 'noopener noreferrer' }, it.url)
    : h('span', { class: 'value' }, it.url);

  pane.replaceChildren(...visibleKids(
    h('button', { class: 'btn ghost small back', onclick: back }, '← All secrets'),
    h('h1', null, it.title),
    h('div', { class: 'meta' }, `v${it.version} · updated ${ago(it.updated)} by ${it.author}`),
    it.exposed?.length > 0 && h('div', { class: 'warn' },
      `${it.exposed.join(', ')} could read this value before being removed. Change it at the source, then edit and save it here.`),
    h('div', { class: 'fields' },
      h('span', { class: 'label' }, 'username'), h('span', { class: 'value' }, it.username),
      h('span', { class: 'acts' }, it.username && btn('Copy', () => copyField('username'))),
      h('span', { class: 'label' }, 'password'), pw,
      h('span', { class: 'acts' },
        open
          ? [btn(S.showPass ? 'Hide' : 'Show', async () => { S.showPass = !S.showPass; renderDetail(); }), btn('Copy', () => copyField('password'))]
          : btn('Decrypt', async () => { await decrypt(); renderDetail(); })),
      h('span', { class: 'label' }, 'url'), url, h('span'),
      h('span', { class: 'label' }, 'notes'),
      open ? h('span', { class: 'value plain' }, open.notes) : sealed(), h('span')),
    S.confirm === 'delete'
      ? h('div', { class: 'confirm' },
        h('p', null, `Delete “${it.title}”?`),
        h('ul', null, h('li', null, 'It disappears for everyone who imports this log.'), h('li', null, 'Older encrypted versions stay in the log.')),
        h('div', { class: 'actions' },
          h('button', { class: 'btn danger', onclick: () => remove(it).catch(fail) }, 'Delete'),
          h('button', { class: 'btn ghost', onclick: () => { S.confirm = null; renderDetail(); } }, 'Cancel')))
      : h('div', { class: 'actions' },
        btn('Edit', async () => { await decrypt(); edit(S.open); }),
        btn('On disk', async () => { S.raw = { title: it.title, text: (await api('GET', `/api/items/${encodeURIComponent(it.id)}/raw`)).raw }; render(); }),
        h('button', { class: 'btn ghost danger small', onclick: () => { S.confirm = 'delete'; renderDetail(); } }, 'Delete')),
    h('div', { class: 'hood' },
      h('h3', null, 'under the hood'),
      h('dl', null,
        h('dt', null, 'stored as'), h('dd', null, `secret.put op ${it.op}`),
        h('dt', null, 'cipher'), h('dd', null, `xchacha20-poly1305 · epoch ${it.epoch} key`),
        h('dt', null, 'size'), h('dd', null, `${it.size} B ciphertext`),
        h('dt', null, 'in memory'), h('dd', null, open ? 'decrypted until you pick another secret' : 'only title, username and url'))),
  ));
}

// visibleKids drops the false/null that conditional children leave behind.
const visibleKids = (...kids) => kids.filter((k) => k != null && k !== false && k !== '');

async function remove(it) {
  await api('DELETE', `/api/items/${encodeURIComponent(it.id)}`);
  toast(`Deleted “${it.title}”`);
  S.sel = null;
  await refresh();
}

// ── clipboard ───────────────────────────────────────────

async function copyField(field) {
  const e = await decrypt();
  await copyText(e[field], field, e.title);
}

async function copyText(text, field, title) {
  if (!text) return toast(`No ${field} to copy`);
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return toast('The browser blocked clipboard access', true);
  }
  const gen = ++S.clipGen;
  api('POST', '/api/clip', { action: 'copied', field, title }).catch(() => {});
  toast(field === 'code' ? 'Join code copied' : `${field[0].toUpperCase() + field.slice(1)} copied · clears in 30s`);
  if (field === 'code') return;
  setTimeout(async () => {
    if (gen !== S.clipGen) return;
    if (document.hasFocus()) {
      await navigator.clipboard.writeText('').catch(() => {});
      api('POST', '/api/clip', { action: 'cleared' }).catch(() => {});
    } else {
      api('POST', '/api/clip', { action: 'kept' }).catch(() => {});
    }
  }, 30000);
}

// ── editor ──────────────────────────────────────────────

function edit(entry) {
  S.editing = { id: entry ? entry.id : '', entry: entry || {} };
  S.confirm = null;
  const main = document.getElementById('main');
  if (main) main.classList.add('showing');
  renderDetail();
  const first = document.querySelector('#detail input');
  if (first) first.focus();
}

function editor() {
  const e = S.editing.entry;
  const field = (label, input) => h('label', null, label, input);
  const title = h('input', { value: e.title || '', placeholder: 'github, aws root, prod db…', required: true });
  const username = h('input', { value: e.username || '', placeholder: 'optional', autocomplete: 'off' });
  const password = h('input', { type: 'password', value: e.password || '', autocomplete: 'new-password' });
  const url = h('input', { value: e.url || '', placeholder: 'optional', autocomplete: 'off' });
  const notes = h('textarea', { placeholder: 'optional' });
  notes.value = e.notes || '';
  const err = h('p', { class: 'err' });

  const save = async (ev) => {
    ev.preventDefault();
    try {
      const entry = { title: title.value, username: username.value.trim(), password: password.value, url: url.value.trim(), notes: notes.value };
      const res = await api('POST', '/api/items', { id: S.editing.id, entry });
      Object.assign(S, { editing: null, open: null, sel: res.id });
      toast('Saved · encrypted, signed and written');
      await refresh();
    } catch (x) {
      err.textContent = x.message;
    }
  };
  const generate = async () => {
    password.value = (await api('POST', '/api/generate')).password;
    password.type = 'text';
  };

  return h('div', null,
    h('h1', null, S.editing.id ? 'Edit secret' : 'New secret'),
    h('div', { class: 'meta' }, 'Nothing is written until you save.'),
    h('form', { class: 'form', onsubmit: save },
      field('title', title),
      field('username', username),
      field('password', h('div', { class: 'inline' }, password,
        h('button', { class: 'btn', type: 'button', onclick: () => generate().catch(fail) }, 'Generate'),
        h('button', { class: 'btn', type: 'button', onclick: () => { password.type = password.type === 'password' ? 'text' : 'password'; } }, 'Show'))),
      field('url', url),
      field('notes', notes),
      err,
      h('div', { class: 'actions' },
        h('button', { class: 'btn primary', type: 'submit' }, 'Save'),
        h('button', { class: 'btn ghost', type: 'button', onclick: () => { S.editing = null; if (!S.sel) back(); else renderDetail(); } }, 'Cancel'))),
    h('p', { class: 'eyebrow', style: null }, 'what happens when you save'),
    h('ol', { class: 'how' },
      h('li', null, 'your fields become json, in memory only'),
      h('li', null, `encrypted with the epoch ${S.info.epoch} vault key · xchacha20-poly1305 · fresh nonce`),
      h('li', null, 'wrapped in a secret.put op and signed with your ed25519 key'),
      h('li', null, 'appended to ops.jsonl and fsynced; plaintext never touches disk')));
}

// ── on-disk view ────────────────────────────────────────

function rawModal() {
  const close = () => { S.raw = null; render(); };
  const lines = S.raw.text.split('\n').map((line) => {
    const m = line.match(/^(\s*)("[^"]+")(:.*)$/);
    return m ? [m[1], h('span', { class: 'key' }, m[2]), m[3], '\n'] : [line, '\n'];
  });
  return h('div', { class: 'backdrop', onclick: (e) => { if (e.target === e.currentTarget) close(); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'stored op' },
      h('header', null,
        h('strong', null, 'On disk'),
        h('span', { class: 'meta' }, `the exact op ops.jsonl holds for “${S.raw.title}”`),
        h('span', { class: 'spacer' }),
        h('button', { class: 'btn small', onclick: close, 'data-autofocus': true }, 'Close')),
      h('p', { class: 'tiny' }, 'Only ct is secret, and it is ciphertext. id is the sha-256 of the op; sig is an ed25519 signature by its author.'),
      h('pre', { class: 'raw' }, lines)));
}

// ── members ─────────────────────────────────────────────

function membersView() {
  const info = S.info;
  const admin = info.is_admin;
  const people = S.members.map((m) => {
    const canRemove = admin && !m.you && !m.removed && m.role !== 'admin';
    const row = h('div', { class: 'person' + (m.removed ? ' gone' : '') },
      h('span', { class: 'name' }, m.name, m.sso && h('span', { class: 'sso', title: `verified by ${m.sso.iss}` }, m.sso.email || 'company login')),
      h('span', { class: 'role' }, m.removed ? 'removed' : m.role),
      h('span', { class: 'sn' }, m.safety),
      presence(m),
      h('span', null, canRemove && h('button', { class: 'btn ghost danger small', onclick: () => { S.confirm = { remove: m }; render(); } }, 'Remove')));
    if (!(S.confirm && S.confirm.remove && S.confirm.remove.id === m.id)) return row;
    return [row, h('div', { class: 'confirm' },
      h('p', null, `Remove ${m.name}?`),
      h('ul', null,
        h('li', null, 'Their key stops being accepted wherever this log goes.'),
        h('li', null, `A new vault key (epoch ${info.epoch + 1}) is sealed to the other ${info.members - 1} member(s).`),
        h('li', null, `All ${info.secrets} secrets are re-encrypted with it.`),
        h('li', null, 'They may have copied old values. Those get marked ! so you can change them.')),
      h('div', { class: 'actions' },
        h('button', { class: 'btn danger', onclick: () => removeMember(m).catch(fail) }, `Remove ${m.name}`),
        h('button', { class: 'btn ghost', onclick: () => { S.confirm = null; render(); } }, 'Cancel')))];
  });

  return h('main', { class: 'members' },
    h('h1', null, 'Members'),
    h('div', { class: 'meta' }, `${info.members} member(s) · key epoch ${info.epoch}`),
    h('p', { class: 'sub' }, admin ? 'You are the admin: you add and remove people.' : `Only ${info.admin} can add or remove people.`),
    h('div', { class: 'people' }, people),
    h('div', { class: 'actions' },
      admin && h('button', { class: 'btn primary', onclick: () => { S.adding = { step: 'paste' }; render(); } }, 'Add member'),
      h('a', { class: 'btn', href: '/api/bundle', download: '' }, 'Download bundle'),
      importButton('Import bundle')),
    S.adding && addPanel(),
    h('div', { class: 'hood' },
      h('h3', null, 'under the hood'),
      h('p', null, 'People are named by their ed25519 key. The safety number covers both of their public keys.'),
      h('p', null, 'Adding seals every vault key to the newcomer’s x25519 key. Removing seals a new key to everyone else and re-encrypts every secret.'),
      h('p', null, 'Bundles carry signed ops only; every one is verified before it is merged. Send them any way you like.'),
      h('p', null, 'While unlocked, hush syncs directly with other members: on the LAN, through NAT hole punching, or via a member acting as relay. Presence is live; “seen” is gossiped between peers.')));
}

function presence(m) {
  const when = (iso, verb) => (iso && Date.parse(iso) > 0 ? `${verb} ${ago(iso)}` : `never ${verb}`);
  let text = `○ ${when(m.last_active, 'active')}`, on = false;
  if (m.removed) text = '';
  else if (m.you) { text = '● you'; on = true; }
  else if (m.presence === 'direct') { text = '● online · direct'; on = true; }
  else if (m.presence === 'relay') { text = '◐ online · via relay'; on = true; }
  else if (m.presence === 'offline') text = `○ offline · ${when(m.last_seen, 'seen')}`;
  return h('span', { class: 'seen' + (on ? ' you' : '') }, text);
}

function addPanel() {
  const cancel = () => { S.adding = null; render(); };
  if (S.adding.step === 'paste') {
    const code = h('textarea', { placeholder: 'paste the hush1:… code they sent you', 'data-autofocus': true, 'aria-label': 'join code' });
    const err = h('p', { class: 'err' });
    const check = async () => {
      try {
        const r = await api('POST', '/api/members/check', { code: code.value });
        S.adding = { step: 'confirm', code: code.value, name: r.name, safety: r.safety, sso: r.sso, note: r.note };
        render();
      } catch (e) {
        err.textContent = e.message;
      }
    };
    return h('div', { class: 'panel' },
      h('p', { class: 'eyebrow' }, 'add a member'),
      code, err,
      h('div', { class: 'actions' },
        h('button', { class: 'btn primary', onclick: check }, 'Check code'),
        h('button', { class: 'btn ghost', onclick: cancel }, 'Cancel')));
  }
  const a = S.adding;
  const add = async () => {
    try {
      await api('POST', '/api/members', { code: a.code });
      S.adding = null;
      toast(`${a.name} added · download a bundle and send it to them`);
    } catch (e) {
      fail(e);
    }
    await refresh();
  };
  return h('div', { class: 'panel' },
    h('p', { class: 'eyebrow' }, `add ${a.name}?`),
    h('div', { class: 'safety' }, a.safety),
    a.sso ? h('p', { class: 'sub you' }, `✓ company login ${a.sso.email} · verified by ${new URL(a.sso.iss).host}`) : a.note && h('p', { class: 'tiny' }, a.note),
    h('p', { class: 'sub' }, `Ask ${a.name} to read the safety number on their screen. Add them only if every digit matches.`),
    h('div', { class: 'actions' },
      h('button', { class: 'btn primary', onclick: add }, 'Numbers match · add'),
      h('button', { class: 'btn ghost', onclick: cancel }, 'Cancel')));
}

async function removeMember(m) {
  const res = await api('DELETE', `/api/members/${encodeURIComponent(m.id)}`);
  S.confirm = null;
  toast(`${m.name} removed · ${res.rekeyed} secrets re-encrypted · change the ones marked !`);
  await refresh();
}

// ── keyboard ────────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName);
  if (e.key === 'Escape') {
    if (S.raw) { S.raw = null; render(); }
    else if (S.editing) { S.editing = null; renderDetail(); }
    return;
  }
  if (typing || !S.info.unlocked || S.tab !== 'secrets') return;
  if (e.key === '/') { e.preventDefault(); document.getElementById('search').focus(); }
  if (e.key === 'n') { e.preventDefault(); edit(null); }
});

connectEvents();
refresh();
