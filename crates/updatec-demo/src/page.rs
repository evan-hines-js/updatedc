pub(crate) const PAGE: &str = r#"<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>updated — operator demo</title>
<style>
  :root {
    color-scheme: dark;
    --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", "Cascadia Mono", Menlo, Consolas, monospace;
    --bg: #0b1220; --surface: #121c30; --surface-2: #0f1829;
    --line: #22304b; --line-2: #33456a;
    --ink: #eaf0f9; --muted: #9aa8c0; --faint: #6d7d99;
    --brand: #e7b24d; --brand-2: #f4c76e; --brand-deep: #c48f2c; --brand-ink: #1a1206;
    --ok: #5bb389; --ok-line: #275c46; --ok-bg: #10251c;
    --warn: #dda63f; --warn-line: #5c4418; --warn-bg: #241c0b;
    --bad: #d5675c; --bad-line: #5f2c27; --bad-bg: #271310;
    --info: #66a9cd; --info-line: #244d61; --info-bg: #0c2531;
    --teal: #46b8a0; --teal-line: #1f5147; --teal-bg: #0c2822;
    --gone: #9a7bc8; --gone-line: #3d2f57; --gone-bg: #1c1630;
    --steel: #7f9cd6;
    font: 15px/1.5 var(--sans);
  }
  * { box-sizing: border-box; }
  body { margin: 0; color: var(--ink); -webkit-font-smoothing: antialiased;
    background: radial-gradient(1100px 560px at 82% -8%, #13233f 0%, rgba(19,35,63,0) 62%), var(--bg); }
  main { max-width: 1400px; margin: 0 auto; padding: 4px 28px 64px; }
  p { color: var(--muted); max-width: 76ch; }
  code { font-family: var(--mono); font-size: .92em; color: #cdd8ec; }
  ::selection { background: rgba(231,178,77,.26); }

  /* Masthead */
  .masthead { position: sticky; top: 0; z-index: 20; padding: 14px 0;
    background: rgba(11,18,32,.82); backdrop-filter: blur(10px); border-bottom: 1px solid var(--line); }
  .masthead-inner { max-width: 1400px; margin: 0 auto; padding: 0 28px;
    display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brandmark { width: 24px; height: 24px; flex: none; border-radius: 6px; transform: rotate(45deg);
    background: linear-gradient(135deg, var(--brand-2), var(--brand-deep));
    box-shadow: 0 0 0 1px rgba(231,178,77,.35), 0 6px 16px -6px rgba(231,178,77,.55); }
  .wordmark { font-weight: 800; letter-spacing: .3em; font-size: 17px; padding-left: 4px; }
  .brand-sub { color: var(--faint); font-size: 12px; letter-spacing: .16em; text-transform: uppercase;
    padding-left: 12px; margin-left: 2px; border-left: 1px solid var(--line-2); }
  .status-strip { display: flex; align-items: center; gap: 14px; font-family: var(--mono); }
  .env-pill { font-size: 11px; font-weight: 700; letter-spacing: .14em; padding: 5px 11px; border-radius: 999px;
    color: var(--brand-2); border: 1px solid var(--brand-deep); background: rgba(231,178,77,.07); }
  .clock { font-size: 13px; color: var(--muted); font-variant-numeric: tabular-nums; }

  h1 { font-size: 30px; line-height: 1.14; letter-spacing: -.012em; font-weight: 750; margin: 22px 0 8px; }
  .lead { font-size: 15px; }

  /* Section headers — the eyebrow names each section's role in the release path */
  .sec { display: flex; flex-direction: column; gap: 3px; margin: 40px 0 14px;
    padding-bottom: 10px; border-bottom: 1px solid var(--line); }
  .sec .eyebrow { font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .18em;
    text-transform: uppercase; color: var(--brand); }
  .sec .title { font-size: 19px; font-weight: 650; letter-spacing: -.006em; color: var(--ink); }

  /* Controls */
  button { font: 600 14px var(--sans); border: 1px solid var(--brand-deep); border-radius: 9px;
    padding: 11px 18px; cursor: pointer; color: var(--brand-ink);
    background: linear-gradient(180deg, var(--brand-2), var(--brand)); }
  button:hover { filter: brightness(1.05); }
  button.ghost { background: transparent; color: var(--ink); border-color: var(--line-2); }
  button.ghost:hover { border-color: var(--brand); color: var(--brand-2); }
  button:disabled { opacity: .5; cursor: wait; filter: none; }
  :focus-visible { outline: 2px solid var(--brand); outline-offset: 2px; }
  input[type=date] { font: 14px var(--mono); padding: 10px 12px; border-radius: 9px;
    border: 1px solid var(--line-2); background: var(--surface-2); color: var(--ink); color-scheme: dark; }
  pre { font-family: var(--mono); font-size: 12.5px; padding: 18px 20px; background: var(--surface-2);
    border: 1px solid var(--line); border-radius: 12px; overflow: auto; color: #c6d2e8; }
  .muted { color: var(--faint); }
  .chaos { margin: 14px 0; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  #chaosStatus { font-family: var(--mono); font-size: 13px; color: var(--muted); }

  /* Rollout progress */
  .progress { height: 8px; background: var(--surface-2); border: 1px solid var(--line);
    border-radius: 999px; overflow: hidden; margin: 12px 0 8px; }
  #progressFill { height: 100%; width: 0; transition: width .5s ease;
    background: linear-gradient(90deg, var(--brand-deep), var(--brand-2)); }

  /* Service-level metrics */
  .sla { display: grid; grid-template-columns: 1.4fr repeat(4, 1fr); gap: 12px; margin: 14px 0 8px; }
  .metric { padding: 14px 16px; background: var(--surface); border: 1px solid var(--line); border-radius: 12px; }
  .metric .k { color: var(--faint); font-family: var(--mono); font-size: 10.5px;
    text-transform: uppercase; letter-spacing: .12em; }
  .metric .v { font-family: var(--mono); font-size: 27px; font-weight: 600; margin-top: 6px;
    font-variant-numeric: tabular-nums; letter-spacing: -.01em; }
  .metric .sub { color: var(--muted); font-size: 11.5px; margin-top: 3px; }
  .metric.availability.met { border-color: var(--ok-line); background: linear-gradient(180deg, var(--ok-bg), var(--surface)); }
  .metric.availability.met .v { color: var(--ok); }
  .metric.availability.breached { border-color: var(--bad-line); background: linear-gradient(180deg, var(--bad-bg), var(--surface)); }
  .metric.availability.breached .v { color: var(--bad); }
  .gauge { height: 8px; margin-top: 12px; background: var(--surface-2); border-radius: 999px;
    overflow: hidden; position: relative; }
  .gauge > span { display: block; height: 100%; background: var(--ok); transition: width .4s ease; }
  .gauge.breached > span { background: var(--bad); }
  .gauge > .line { position: absolute; top: -3px; bottom: -3px; width: 2px; background: var(--ink); opacity: .8; }
  .budget > span { background: var(--steel); }

  /* Fleet groups */
  #groups { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 10px; margin: 12px 0 8px; }
  .set-box { border: 1px solid var(--line); border-radius: 12px; padding: 10px; background: var(--surface); }
  .set-box.met { border-color: var(--ok-line); }
  .set-box.breached { border-color: var(--bad-line); }
  .set-label { font-family: var(--mono); font-size: 11px; font-weight: 600; letter-spacing: .08em;
    color: var(--faint); text-transform: uppercase; margin: 0 2px 8px; }
  .set-load { display: flex; flex-wrap: wrap; gap: 4px 12px; margin: 0 2px 9px; font-family: var(--mono);
    font-size: 10.5px; font-weight: 500; color: var(--muted); font-variant-numeric: tabular-nums; }
  .set-load.met span:first-child { color: var(--ok); }
  .set-load.breached span:first-child { color: var(--bad); }
  .set-members { display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap: 8px; }
  .members { display: grid; grid-template-columns: repeat(auto-fit,minmax(20px,1fr)); gap: 4px; margin-top: 8px; }
  .group > .node { min-height: 0; }
  .node { padding: 11px; background: var(--surface-2); border: 1px solid var(--line);
    border-radius: 9px; transition: border-color .3s, background .3s; }
  .node h3 { margin: 0 0 3px; font-size: 15px; font-weight: 600; }
  .node p { margin: 3px 0 2px; color: var(--muted); font-size: 12.5px; }
  .healthy { color: var(--ok); } .unhealthy { color: var(--bad); }
  #events { min-height: 90px; max-height: 240px; color: #b9c6dc; }
  .group { min-height: 96px; }
  .group code { overflow-wrap: anywhere; }
  .group.failure { border-color: var(--bad-line); background: var(--bad-bg); }
  .group.recovered { border-color: var(--teal-line); background: var(--teal-bg); }
  .group.good { border-color: var(--ok-line); background: var(--ok-bg); }
  .group.rolling { border-color: var(--warn-line); background: var(--warn-bg); }
  .group.default { border-color: var(--line-2); }
  .node.failing { border-color: var(--bad-line); background: var(--bad-bg); }
  .node.activating { border-color: var(--warn-line); background: var(--warn-bg); }
  .node.activating .phase { color: var(--warn); }
  .node.pending { border-color: var(--info-line); background: var(--info-bg); }
  .node.pending .phase { color: var(--info); }
  .node.rolledback { border-color: var(--teal-line); background: var(--teal-bg); }
  .node.rolledback .phase { color: var(--teal); }
  .node.converged { border-color: var(--ok-line); background: var(--ok-bg); }
  .node.converged .phase { color: var(--ok); }
  .node.baseline { border-color: var(--line-2); background: var(--surface-2); }
  .node.baseline .phase { color: var(--muted); }
  .node.unreachable { border-color: var(--gone-line); background: var(--gone-bg); }
  .service-cell { aspect-ratio: 1; min-width: 0; padding: 0; border-radius: 6px; border-width: 1px;
    cursor: default; display: grid; place-items: center; font-family: var(--mono);
    font-size: 9px; font-weight: 700; letter-spacing: .04em; }
  .service-cell .pool { display: inline; color: var(--ink); }
  .service-cell h3, .service-cell p, .service-cell .phase { display: none; }
  .phase { font-family: var(--mono); font-size: 10.5px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; }

  /* Provider lifecycle — a real ordered sequence, so numbering carries meaning */
  .pipeline { display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; margin: 14px 0; }
  .step { padding: 13px 14px; border: 1px solid var(--line); background: var(--surface);
    border-radius: 10px; font-size: 12.5px; color: var(--muted); }
  .step b { display: block; font-family: var(--mono); font-size: 12px; letter-spacing: .02em;
    color: var(--brand); margin-bottom: 4px; }
  .tree { color: #a9c6e8; min-height: 150px; }

  /* Rollout calendar */
  .calendar-panel { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 10px 0 8px; min-height: 34px; }
  .cal-badge { font-family: var(--mono); font-size: 11.5px; font-weight: 700; letter-spacing: .08em;
    padding: 7px 13px; border-radius: 8px; text-transform: uppercase; }
  .cal-badge.open { background: var(--ok-bg); color: var(--ok); border: 1px solid var(--ok-line); }
  .cal-badge.frozen { background: var(--bad-bg); color: var(--bad); border: 1px solid var(--bad-line); }
  .cal-badge.pending { background: var(--info-bg); color: var(--info); border: 1px solid var(--info-line); }
  .cal-chip { font-family: var(--mono); font-size: 12px; font-weight: 500; padding: 6px 11px; border-radius: 8px;
    background: var(--surface); border: 1px solid var(--line); color: var(--muted); font-variant-numeric: tabular-nums; }
  .cal-chip.today { border-color: var(--brand-deep); color: var(--brand-2); background: rgba(231,178,77,.08); }
  .cal-empty { color: var(--faint); font-size: 13px; }
  #calStatus { font-family: var(--mono); font-size: 12.5px; color: var(--muted); }

  @media (max-width: 1100px) { #groups { grid-template-columns: repeat(2,1fr); } }
  @media (max-width: 900px) { .sla { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 700px) {
    main { padding: 4px 16px 48px; }
    .masthead-inner { padding: 0 16px; }
    .brand-sub { display: none; }
    #groups { grid-template-columns: 1fr; }
    .pipeline { grid-template-columns: repeat(2,1fr); }
  }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
<header class="masthead">
  <div class="masthead-inner">
    <div class="brand">
      <span class="brandmark" aria-hidden="true"></span>
      <span class="wordmark">updatec</span>
      <span class="brand-sub">Release Operations</span>
    </div>
    <div class="status-strip">
      <span class="env-pill">PRODUCTION FLEET</span>
      <span class="clock" id="utcClock">--:--:-- UTC</span>
    </div>
  </div>
</header>
<main>
  <h1>Fleet release control, live</h1>
  <p class="lead">The fleet running end to end, for real, with a console on top. Each epoch
     diverges the sixteen fixed five-service groups a generation at a time — three groups per
     generation, some taking a signed broken release and some a valid one, all under random
     pod-kill chaos. Broken groups hold below the bad release (killed, stateless pods recover by
     descending versions through signed ordered fallback); valid groups advance. Once every group
     has been exercised, the whole fleet converges onto a single new version, and the next epoch
     begins one hundred above the last.</p>
  <div class="chaos"><span id="chaosStatus"></span></div>
  <div class="progress"><div id="progressFill"></div></div>
  <h2 class="sec"><span class="eyebrow">Service level</span><span class="title">Golden signals, live</span></h2>
  <p>A synthetic client acts as a readiness-respecting load balancer, continuously routing
     real requests to whichever fleet endpoints are in the pool. Because a correct drain
     withdraws readiness before shutdown, availability holds the SLA line through pod-kill
     chaos and rollouts — a failed drain would burn the error budget on screen.</p>
  <section class="sla">
    <div class="metric availability" id="availabilityCard">
      <div class="k">Availability</div>
      <div class="v" id="availabilityValue">—</div>
      <div class="sub" id="availabilitySub">SLA <span id="slaTarget"></span></div>
      <div class="gauge" id="availabilityGauge"><span></span><i class="line"></i></div>
    </div>
    <div class="metric"><div class="k">Request rate</div><div class="v" id="rateValue">—</div><div class="sub">req/s over <span id="windowSecs"></span>s</div></div>
    <div class="metric"><div class="k">Error rate</div><div class="v" id="errorValue">—</div><div class="sub" id="errorSub">of served traffic</div></div>
    <div class="metric"><div class="k">Latency p50 / p95</div><div class="v" id="latencyValue">—</div><div class="sub">milliseconds</div></div>
    <div class="metric budget"><div class="k">Error budget</div><div class="v" id="budgetValue">—</div><div class="sub" id="budgetSub">remaining this window</div><div class="gauge budget" id="budgetGauge"><span></span></div></div>
  </section>
  <h2 class="sec"><span class="eyebrow">Fleet</span><span class="title">Control-plane groups and managed agents</span></h2><section id="groups"></section>
  <h2 class="sec"><span class="eyebrow">Release gate</span><span class="title">Rollout calendar</span></h2>
  <p>The fleet-wide <code>UpdateGroupSet</code> carries a list of one-off UTC dates. The fleet
     may admit new rollouts only on a listed day; once every date is in the past the calendar
     "runs out" and rollouts resume automatically. Add <b>today</b> and the fleet keeps rolling;
     add only a <b>future</b> date and watch the whole fleet freeze until then. The operator
     re-reads this off the CRD every reconcile — <b>Add date</b> patches
     <code>spec.calendar</code> live.</p>
  <div class="chaos calendar-controls">
    <input type="date" id="calDate">
    <button id="calAdd">Add date</button>
    <button id="calClear" class="ghost">Clear</button>
    <span id="calStatus"></span>
  </div>
  <section id="calPanel" class="calendar-panel"></section>
  <h2 class="sec"><span class="eyebrow">Provider lifecycle</span><span class="title">Provider-owned deployment filesystem</span></h2>
  <p>Every valid assignment runs this downloaded Rust provider state machine. The
     E2E independently reads its durable audit and receipt; these are real files in
     each agent volume, not UI state.</p>
  <div class="pipeline">
    <div class="step"><b>1 · preflight</b>validate app + release config</div>
    <div class="step"><b>2 · prepare</b>backup WAR, repository, server.xml</div>
    <div class="step"><b>3 · drain</b>remove from pool + drain requests</div>
    <div class="step"><b>4 · stop</b>record managed child PID</div>
    <div class="step"><b>5 · activate</b>stage WAR + migration plan</div>
    <div class="step"><b>6 · start</b>warm caches + launch candidate</div>
    <div class="step"><b>7 · verify</b>prove live candidate identity</div>
    <div class="step"><b>8 · finalize</b>migrate + write change receipt</div>
  </div>
  <pre class="tree">/var/lib/updated/providers/state/demo-enterprise-lifecycle/
├── attempts/&lt;signed-attempt-id&gt;/
│   ├── preflight.done
│   ├── prepare.done
│   ├── drain.done
│   ├── stop.done
│   ├── activate.done
│   ├── start.done
│   ├── verify.done
│   ├── finalize.done
│   ├── generated-install.properties
│   └── stopped-process.pid
├── backups/&lt;signed-attempt-id&gt;/
│   ├── application.war
│   ├── content.repository
│   └── server.xml
├── legacy-java-home/
│   ├── application.war
│   ├── content.repository
│   ├── install.properties
│   └── change-ticket.receipt
└── audit/lifecycle.tsv</pre>
  <h2 class="sec"><span class="eyebrow">Audit log</span><span class="title">Scenario events</span></h2><pre id="events">not started</pre>
</main>
<script>
const groups = document.querySelector('#groups');
const chaosStatus = document.querySelector('#chaosStatus');
const events = document.querySelector('#events');
const progressFill = document.querySelector('#progressFill');
// Live UTC clock in the masthead — the release calendar is UTC, so the console reads in UTC too.
const utcClock = document.querySelector('#utcClock');
const tickClock = () => { if (utcClock) utcClock.textContent = new Date().toISOString().slice(11, 19) + ' UTC'; };
tickClock(); setInterval(tickClock, 1000);
// Fetch JSON with a hard timeout, so a single slow endpoint can never stall the refresh
// loop (which is what silently froze the SLA panel before).
async function getJson(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 4000);
  try { return await fetch(url, {cache: 'no-store', signal: ctrl.signal}).then(r => r.json()); }
  finally { clearTimeout(timer); }
}
async function refreshFleet() {
  try {
    // The fleet snapshot probes every agent server-side, so it is the slow endpoint. Fetch
    // only what the boxes need here; the SLA panel and per-set load come from /golden on its
    // own fast loop (below), so a slow /fleet can never starve or freeze them.
    const [nodesR, valuesR, chaosR] = await Promise.allSettled([
      getJson('/fleet'), getJson('/groups'), getJson('/chaos')
    ]);
    const nodes = nodesR.status === 'fulfilled' ? nodesR.value : [];
    const values = valuesR.status === 'fulfilled' ? valuesR.value : [];
    const chaos = chaosR.status === 'fulfilled' ? chaosR.value : {};
    const byName = new Map(nodes.map(node => [node.node, node]));
    // Authoritative cohort roles from the backend. The UI never infers broken-vs-valid
    // from version numbers — the control plane is the single source of truth.
    const activeBroken = new Set(chaos.activeBroken || []);
    const activeValid = new Set(chaos.activeValid || []);
    const updatedGroups = new Set(chaos.updatedGroups || []);
    const rolledBackGroups = new Set(chaos.rolledBackGroups || []);
    const converging = !!chaos.converging;
    const badMajor = Number((chaos.badVersion || '0').split('.')[0]);
    const major = version => Number((version || '0').split('.')[0]);
    const cohorts = values
      .filter(group => group.name.startsWith('demo-'))
      .sort((a, b) => a.name.localeCompare(b.name));
    // The authoritative rollout state + label for a group (broken/valid/rolled-back/etc).
    const stateFor = group => {
      const members = group.selectedNodes.map(name => byName.get(name)).filter(Boolean);
      const draining = members.some(node => !node.inLoadBalancer);
      const onDesired = members.length > 0 && members.every(node =>
        node.version === group.desiredVersion && node.inLoadBalancer && node.healthy);
      const brokenActive = activeBroken.has(group.name);
      const validActive = activeValid.has(group.name);
      const rolledBack = rolledBackGroups.has(group.name);
      const updated = updatedGroups.has(group.name);
      let state, label;
      if (converging) {
        state = onDesired ? 'good' : 'rolling';
        label = onDesired ? `converged · ${group.desiredVersion}` : `converging → ${group.desiredVersion}`;
      } else if (brokenActive) {
        state = draining ? 'failure' : 'rolling';
        label = draining ? 'broken release · rolling back' : 'broken release · queued';
      } else if (validActive) {
        state = 'rolling';
        label = `rolling forward → ${group.desiredVersion}`;
      } else if (rolledBack) {
        state = 'recovered';
        label = 'rollback complete · healthy';
      } else if (updated) {
        state = 'good';
        label = `updated → ${group.desiredVersion}`;
      } else {
        state = 'default';
        label = 'baseline · not exercised';
      }
      return { members, state, label, brokenActive, validActive, rolledBack, updated };
    };
    const renderGroup = group => {
      const { members, state, label, brokenActive, validActive, rolledBack, updated } = stateFor(group);
      const cards = members.map(node => {
        const atDesired = node.version === group.desiredVersion;
        const cell = !node.inLoadBalancer ? (brokenActive ? 'failing' : 'activating')
          : rolledBack ? 'rolledback'
          : (updated || (converging && atDesired)) ? 'converged'
          : (brokenActive || validActive || converging) ? 'pending'
          : 'baseline';
        const pool = node.inLoadBalancer ? 'IN' : 'OUT';
        const probe = `readyz ${node.readyzProbeMillis}ms${node.probeNote ? ' · ' + node.probeNote : ''}`;
        return `<article class="node service-cell ${cell}" title="${label} · ${pool === 'IN' ? 'in load balancer' : 'out of load balancer'} · version ${node.version ?? 'unreachable'} · ${node.selectedGroup ?? 'pending'} · ${probe}"><span class="pool">${pool}</span></article>`;
      }).join('');
      return `<article class="node group ${state}">
      <h3>${group.name}</h3>
      <p title="selector ${group.selector || '(default)'}">${members.length} services · desired ${group.desiredVersion}<br>${label}</p>
      <section class="members">${cards}</section>
    </article>`;
    };
    // One box per display set, each group in its set.
    const bySet = new Map();
    for (const group of cohorts) {
      const key = group.set || group.name;
      if (!bySet.has(key)) bySet.set(key, []);
      bySet.get(key).push(group);
    }
    groups.innerHTML = [...bySet.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([set, members]) => {
        // Each set has its own load balancer: show its live availability, rate, tail
        // latency, and remaining error budget.
        const g = goldenBySet.get(set);
        const loadClass = g && g.requests > 0 ? (g.slaMet ? 'met' : 'breached') : '';
        const load = g ? `<div class="set-load ${loadClass}">
          <span>${g.requests ? pct(g.availability) : '—'} avail</span>
          <span>${g.requestRate.toFixed(g.requestRate < 10 ? 1 : 0)} rps</span>
          <span>p95 ${g.latencyP95Ms}ms</span>
          <span>budget ${g.requests ? g.errorBudgetRemaining.toFixed(0) + '%' : '—'}</span>
        </div>` : '';
        return `<section class="set-box ${loadClass}">
          <header class="set-label">${set} · ${members.length} groups${g ? ` · ${g.readyEndpoints} in pool` : ''}</header>
          ${load}
          <div class="set-members">${members.map(renderGroup).join('')}</div>
        </section>`;
      })
      .join('');
  } catch (_) { groups.textContent = 'Reading operator groups…'; }
}
async function refreshChaos() {
  try {
    const state = await fetch('/chaos', {cache: 'no-store'}).then(r => r.json());
    chaosStatus.textContent = state.error ? `failed: ${state.error}`
      : state.complete ? `PASS — fleet converged onto ${state.goodVersion}`
      : state.running ? `epoch ${state.epoch} · loop ${state.loopNumber} · seed ${state.seed} · ${state.completedNodes}/${16} cohorts exercised`
      : `ready · next run chooses a random seed`;
    progressFill.style.width = `${Math.min(100, state.completedNodes / 16 * 100)}%`;
    events.textContent = state.events.length ? state.events.join('\n') : 'not started';
    events.scrollTop = events.scrollHeight;
  } catch (_) { chaosStatus.textContent = 'reading scenario state…'; }
}
// Latest per-set golden signals, keyed by set name — set by refreshFleet from the same
// snapshot it renders the boxes with, so the fleet panel and per-set boxes always agree.
let goldenBySet = new Map();
const pct = v => `${v.toFixed(v >= 99.95 || v === 0 ? (v % 1 ? 3 : 0) : 2)}%`;
// The SLA panel and per-set load come from /golden on their own fast, timed loop, wholly
// independent of the slow /fleet probe — one cheap fetch drives both the top panel and the
// box load lines (from the same snapshot, so they always agree) and can never be blocked.
async function refreshGolden() {
  try {
    const golden = await getJson('/golden');
    if (golden && golden.fleet) {
      goldenBySet = new Map((golden.sets || []).map(s => [s.set, s.signals]));
      updateSlaPanel(golden.fleet);
    }
  } catch (_) { /* keep the last good reading */ }
}
function updateSlaPanel(g) {
  try {
    document.querySelector('#slaTarget').textContent = pct(g.slaTarget);
    document.querySelector('#windowSecs').textContent = g.windowSecs;
    const availValue = document.querySelector('#availabilityValue');
    availValue.textContent = g.requests ? pct(g.availability) : '—';
    document.querySelector('#availabilitySub').innerHTML =
      `SLA ${pct(g.slaTarget)} · ${g.readyEndpoints} in pool${g.warmingUp ? ' · warming up' : ''}`;
    const card = document.querySelector('#availabilityCard');
    card.classList.toggle('met', g.requests > 0 && g.slaMet);
    card.classList.toggle('breached', g.requests > 0 && !g.slaMet);
    const gauge = document.querySelector('#availabilityGauge');
    gauge.classList.toggle('breached', g.requests > 0 && !g.slaMet);
    gauge.querySelector('span').style.width = `${g.requests ? Math.min(100, g.availability) : 0}%`;
    gauge.querySelector('.line').style.left = `${g.slaTarget}%`;
    document.querySelector('#rateValue').textContent = g.requestRate.toFixed(g.requestRate < 10 ? 1 : 0);
    document.querySelector('#errorValue').textContent = g.requests ? pct(g.errorRate) : '—';
    document.querySelector('#errorSub').textContent = `${g.errors} of ${g.requests} requests`;
    document.querySelector('#latencyValue').textContent = `${g.latencyP50Ms} / ${g.latencyP95Ms}`;
    document.querySelector('#budgetValue').textContent = g.requests ? `${g.errorBudgetRemaining.toFixed(0)}%` : '—';
    const budgetGauge = document.querySelector('#budgetGauge');
    budgetGauge.classList.toggle('breached', g.requests > 0 && !g.slaMet);
    budgetGauge.querySelector('span').style.width = `${g.requests ? g.errorBudgetRemaining : 0}%`;
  } catch (_) { /* keep the last good reading */ }
}
// Self-pacing loops: each waits for its own fetches to finish before scheduling the next,
// so a slow refresh can never pile up requests and saturate the browser's connection pool
// (which is what starved /golden and froze the SLA panel).
// ── Rollout calendar: add a UTC date to the fleet set and watch it gate ────────────
const CAL_SET = 'demo-fleet';
const todayUtc = () => new Date().toISOString().slice(0, 10);
const calDate = document.querySelector('#calDate');
const calAdd = document.querySelector('#calAdd');
const calClear = document.querySelector('#calClear');
const calStatus = document.querySelector('#calStatus');
const calPanel = document.querySelector('#calPanel');
// Default the picker to today (UTC) so a click is all it takes — no typing.
calDate.value = todayUtc();
async function calPost(url, verb) {
  calAdd.disabled = calClear.disabled = true;
  calStatus.textContent = `${verb}…`;
  try {
    const response = await fetch(url, {method: 'POST'});
    const body = await response.json();
    calStatus.textContent = response.ok ? (body.status || 'done') : `failed: ${body.error}`;
  } catch (error) { calStatus.textContent = `failed: ${error}`; }
  await refreshSets();
  calAdd.disabled = calClear.disabled = false;
}
calAdd.onclick = () => {
  const date = calDate.value || todayUtc();
  calPost(`/calendar/add?set=${CAL_SET}&date=${date}`, `adding ${date}`);
};
calClear.onclick = () => calPost(`/calendar/clear?set=${CAL_SET}`, 'clearing');
async function refreshSets() {
  try {
    const sets = await getJson('/sets');
    const set = Array.isArray(sets) ? sets.find(s => s.name === CAL_SET) : null;
    if (!set) { calPanel.innerHTML = '<span class="cal-empty">waiting for the fleet set…</span>'; return; }
    const entries = set.calendar || [];
    // The operator's status.frozen is authoritative; it lags a patch by one reconcile, so
    // show "reconciling…" while the spec has entries the status has not yet reflected.
    let badge;
    if (set.frozen === true) badge = '<span class="cal-badge frozen">frozen · waiting for a date</span>';
    else if (set.frozen === false) badge = '<span class="cal-badge open">open · rolling</span>';
    else badge = '<span class="cal-badge pending">reconciling…</span>';
    const today = todayUtc();
    const chips = entries.length
      ? entries
          .slice()
          .sort((a, b) => a.date.localeCompare(b.date))
          .map(e => `<span class="cal-chip${e.date === today ? ' today' : ''}">${e.date} · ${e.start}–${e.end}${e.date === today ? ' · today' : ''}</span>`)
          .join('')
      : '<span class="cal-empty">no dates — always open</span>';
    calPanel.innerHTML = `${badge}${chips}`;
  } catch (_) { /* keep the last good reading */ }
}
const pace = (fn, ms) => { const tick = async () => { await fn(); setTimeout(tick, ms); }; tick(); };
pace(refreshFleet, 1000);
pace(refreshChaos, 1000);
pace(refreshGolden, 1000);
pace(refreshSets, 1000);
</script>
</html>"#;
