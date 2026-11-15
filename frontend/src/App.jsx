import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import { Badge, Empty, ErrorBox, Finding, KV, SEVERITIES } from "./components.jsx";

function useHash() {
  const [hash, setHash] = useState(window.location.hash || "#/dashboard");
  useEffect(() => {
    const on = () => setHash(window.location.hash || "#/dashboard");
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}
const go = (h) => (window.location.hash = h);

export default function App() {
  const hash = useHash();
  const [health, setHealth] = useState(null);
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "unreachable" }));
  }, []);

  const route = hash.replace(/^#\//, "");
  let view;
  if (route.startsWith("case/")) view = <CaseView id={route.slice(5)} />;
  else if (route === "new") view = <NewInvestigation />;
  else view = <Dashboard />;

  const navItems = [
    ["dashboard", "Dashboard"],
    ["new", "New investigation"],
  ];
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <img src="/logo.svg" alt="" width="28" height="28" className="brand-logo" />
          Phish<span>Lab</span>
        </div>
        <div className="tagline">Investigation workbench</div>
        <nav className="nav">
          {navItems.map(([k, label]) => (
            <button
              key={k}
              className={route === k ? "active" : ""}
              onClick={() => go(`#/${k}`)}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="offline-badge">
          <b>Offline-first.</b> Static analysis makes no outbound calls.
          <br />
          Network lookups:{" "}
          {health?.network_lookups_enabled ? "enabled" : "disabled"}
        </div>
      </aside>
      <main className="main">{view}</main>
    </div>
  );
}

// ---------- Dashboard ----------
function Dashboard() {
  const [stats, setStats] = useState(null);
  const [cases, setCases] = useState([]);
  const [q, setQ] = useState("");
  const [error, setError] = useState(null);

  const load = (query = "") => {
    api.stats().then(setStats).catch(setError);
    api.listCases(query).then((r) => setCases(r.items)).catch(setError);
  };
  useEffect(() => load(), []);

  return (
    <div>
      <h1 className="h1">Dashboard</h1>
      <p className="sub">Recent investigations and case statistics.</p>
      <ErrorBox error={error} />
      <div className="grid cards" style={{ marginBottom: 18 }}>
        <div className="panel stat">
          <div className="n">{stats?.total ?? "-"}</div>
          <div className="l">Total cases</div>
        </div>
        {SEVERITIES.map((s) => (
          <div className="panel stat" key={s}>
            <div className="n">{stats?.by_severity?.[s] ?? 0}</div>
            <div className="l">
              <Badge value={s} />
            </div>
          </div>
        ))}
      </div>

      <div className="row" style={{ marginBottom: 10 }}>
        <input
          placeholder="Search subject / sender / hash"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && load(q)}
          style={{ maxWidth: 360 }}
        />
        <button onClick={() => load(q)}>Search</button>
        <span className="spacer" />
        <button className="primary" onClick={() => go("#/new")}>
          + New investigation
        </button>
      </div>

      <div className="panel">
        {cases.length === 0 ? (
          <Empty>No cases yet. Import a suspicious .eml to begin.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Created</th>
                <th>Subject</th>
                <th>Sender</th>
                <th>Severity</th>
                <th>Findings</th>
                <th>Disposition</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr
                  key={c.id}
                  className="clickable"
                  onClick={() => go(`#/case/${c.id}`)}
                >
                  <td className="note">{c.created_at?.slice(0, 19).replace("T", " ")}</td>
                  <td>{c.subject || <span className="note">(no subject)</span>}</td>
                  <td className="mono">{c.sender || "-"}</td>
                  <td><Badge value={c.highest_severity} /></td>
                  <td>{c.finding_count}</td>
                  <td><Badge value={c.disposition} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------- New investigation ----------
function NewInvestigation() {
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("file");
  const [headers, setHeaders] = useState("");
  const [text, setText] = useState("");

  const submit = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      const r = await fn();
      go(`#/case/${r.id}`);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const onFile = (file) => {
    if (!file) return;
    submit(() => api.createCaseFile(file));
  };

  return (
    <div>
      <h1 className="h1">New investigation</h1>
      <p className="sub">
        Import a suspicious email. It is treated as hostile input: nothing is executed,
        no links are opened, no remote content is loaded.
      </p>
      <ErrorBox error={error} />
      <div className="tabs">
        {[["file", "Upload .eml"], ["headers", "Paste headers"], ["text", "Paste body text"]].map(
          ([k, l]) => (
            <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
              {l}
            </button>
          )
        )}
      </div>

      {tab === "file" && (
        <div
          className={`dropzone ${drag ? "drag" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            onFile(e.dataTransfer.files[0]);
          }}
        >
          {busy ? (
            "Analyzing…"
          ) : (
            <>
              <p>Drag &amp; drop a <code>.eml</code> file here, or</p>
              <label className="primary" style={{ display: "inline-block", padding: "7px 12px", borderRadius: 6, background: "var(--accent)", color: "#fff" }}>
                Choose file
                <input
                  type="file"
                  accept=".eml,message/rfc822,.txt"
                  style={{ display: "none" }}
                  onChange={(e) => onFile(e.target.files[0])}
                />
              </label>
              <p className="note" style={{ marginTop: 14 }}>
                Max 25 MB. Attachments are never opened or executed.
              </p>
            </>
          )}
        </div>
      )}

      {tab === "headers" && (
        <div className="panel">
          <textarea
            placeholder="Paste raw email headers…"
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
          />
          <div className="row" style={{ marginTop: 10 }}>
            <button
              className="primary"
              disabled={busy || !headers.trim()}
              onClick={() => submit(() => api.createCaseText("headers", headers))}
            >
              Analyze headers
            </button>
          </div>
        </div>
      )}

      {tab === "text" && (
        <div className="panel">
          <textarea
            placeholder="Paste plain-text email body…"
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="row" style={{ marginTop: 10 }}>
            <button
              className="primary"
              disabled={busy || !text.trim()}
              onClick={() => submit(() => api.createCaseText("text", text))}
            >
              Analyze text
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Case view ----------
function CaseView({ id }) {
  const [c, setC] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("overview");
  const reload = () => api.getCase(id).then(setC).catch(setError);
  useEffect(() => {
    reload();
  }, [id]);

  if (error) return <ErrorBox error={error} />;
  if (!c) return <div className="empty">Loading…</div>;
  const a = c.analysis;
  const tabs = [
    ["overview", "Overview"],
    ["email", "Email"],
    ["indicators", "Indicators"],
    ["urls", "URLs"],
    ["attachments", "Attachments"],
    ["findings", `Findings (${a.findings.length})`],
    ["report", "Report"],
  ];

  return (
    <div>
      <div className="row">
        <button onClick={() => go("#/dashboard")}>← Cases</button>
        <span className="spacer" />
        <Badge value={a.assessment.highest_severity} />
        <Badge value={c.disposition} />
      </div>
      <h1 className="h1" style={{ marginTop: 12 }}>
        {a.summary_headers.subject || "(no subject)"}
      </h1>
      <p className="sub mono">{a.summary_headers.from}</p>

      {a.warnings?.length > 0 && (
        <div className="error" style={{ marginBottom: 12 }}>
          Parser warnings: {a.warnings.join("; ")}
        </div>
      )}

      <div className="tabs">
        {tabs.map(([k, l]) => (
          <button key={k} className={tab === k ? "active" : ""} onClick={() => setTab(k)}>
            {l}
          </button>
        ))}
      </div>

      {tab === "overview" && <Overview c={c} reload={reload} />}
      {tab === "email" && <EmailTab a={a} />}
      {tab === "indicators" && <IndicatorsTab a={a} />}
      {tab === "urls" && <UrlsTab a={a} />}
      {tab === "attachments" && <AttachmentsTab a={a} />}
      {tab === "findings" && (
        <div>
          {a.findings.length === 0 ? (
            <Empty>No findings from static analysis. Absence of evidence is not proof of safety.</Empty>
          ) : (
            a.findings.map((f, i) => <Finding key={i} f={f} />)
          )}
        </div>
      )}
      {tab === "report" && <ReportTab id={id} />}
    </div>
  );
}

function Overview({ c, reload }) {
  const a = c.analysis;
  const [rationale, setRationale] = useState(c.rationale || "");
  const [notes, setNotes] = useState(c.notes || "");
  const [saved, setSaved] = useState("");

  const dispositions = ["undetermined", "benign", "suspicious", "malicious", "inconclusive"];
  const setDisp = async (d) => {
    await api.setDisposition(c.id, d, rationale);
    setSaved("Disposition saved.");
    reload();
  };
  const saveNotes = async () => {
    await api.setNotes(c.id, notes);
    setSaved("Notes saved.");
  };

  return (
    <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
      <div className="panel">
        <h3>Assessment</h3>
        <p>{a.assessment.summary}</p>
        <div className="row">
          {Object.entries(a.assessment.counts)
            .filter(([, n]) => n > 0)
            .map(([s, n]) => (
              <span key={s} className="pill">
                {n} × {s}
              </span>
            ))}
        </div>
        <p className="note" style={{ marginTop: 10 }}>
          The overall assessment aggregates the individual findings - it is not a
          single opaque score. Severity (impact if true) and confidence (certainty)
          are reported separately per finding.
        </p>
      </div>

      <div className="panel">
        <h3>Analyst decision</h3>
        <div className="row" style={{ marginBottom: 10 }}>
          {dispositions.map((d) => (
            <button
              key={d}
              className={c.disposition === d ? "primary" : ""}
              onClick={() => setDisp(d)}
            >
              {d}
            </button>
          ))}
        </div>
        <label className="note">Rationale (why this disposition)</label>
        <textarea
          style={{ minHeight: 70 }}
          value={rationale}
          onChange={(e) => setRationale(e.target.value)}
        />
        <h3 style={{ marginTop: 16 }}>Investigation notes</h3>
        <textarea value={notes} onChange={(e) => setNotes(e.target.value)} />
        <div className="row" style={{ marginTop: 8 }}>
          <button onClick={saveNotes}>Save notes</button>
          <span className="note">{saved}</span>
        </div>
      </div>
    </div>
  );
}

function EmailTab({ a }) {
  const h = a.summary_headers;
  return (
    <div className="grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
      <div className="panel">
        <h3>Sender identity</h3>
        <KV
          rows={[
            ["From", h.from],
            ["Reply-To", h.reply_to],
            ["Return-Path", h.return_path],
            ["To", h.to],
            ["Date", h.date],
            ["Message-ID", h.message_id],
          ]}
        />
      </div>
      <div className="panel">
        <h3>Authentication</h3>
        <KV
          rows={[
            ["SPF (reported)", a.auth.spf],
            ["DKIM (reported)", a.auth.dkim],
            ["DMARC (reported)", a.auth.dmarc],
            ["Independently verified", String(a.auth.verified)],
          ]}
        />
        <p className="note" style={{ marginTop: 8 }}>
          Results are sender-reported from the Authentication-Results header. PhishLab
          does not cryptographically verify them.
        </p>
      </div>
      <div className="panel" style={{ gridColumn: "1 / -1" }}>
        <h3>MIME structure</h3>
        <table>
          <thead>
            <tr>
              <th>Depth</th>
              <th>Content-Type</th>
              <th>Encoding</th>
              <th>Filename</th>
              <th>Size</th>
              <th>Attachment</th>
            </tr>
          </thead>
          <tbody>
            {a.mime.map((p, i) => (
              <tr key={i}>
                <td>{p.depth}</td>
                <td className="mono">{p.content_type}</td>
                <td className="mono">{p.content_transfer_encoding || "-"}</td>
                <td className="mono">{p.filename || "-"}</td>
                <td>{p.size}</td>
                <td>{p.is_attachment ? "yes" : "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="panel" style={{ gridColumn: "1 / -1" }}>
        <h3>Body (sanitized source - not rendered)</h3>
        <p className="note">
          HTML is shown as source text and never rendered. No remote images or scripts load.
        </p>
        <pre className="source">
          {a.body_text || a.body_html_source || "(no textual body)"}
        </pre>
      </div>
    </div>
  );
}

function IndicatorsTab({ a }) {
  const groups = [
    ["URLs", a.indicators.urls],
    ["Domains", a.indicators.domains],
    ["IPv4", a.indicators.ipv4],
    ["IPv6", a.indicators.ipv6],
    ["Emails", a.indicators.emails],
  ];
  return (
    <div className="grid">
      {groups.map(([label, items]) => (
        <div className="panel" key={label}>
          <h3>
            {label} <span className="note">({items.length})</span>
          </h3>
          {items.length === 0 ? (
            <span className="note">None extracted.</span>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Indicator (defanged)</th>
                  <th>Source</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {items.map((it, i) => (
                  <tr key={i}>
                    <td className="defanged">{it.defanged}</td>
                    <td className="note mono">{it.source}</td>
                    <td>
                      {it.flags.map((f) => (
                        <span key={f} className="pill" style={{ marginRight: 4 }}>
                          {f}
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </div>
  );
}

function UrlsTab({ a }) {
  const urls = a.indicators.urls;
  if (urls.length === 0) return <Empty>No URLs extracted.</Empty>;
  return (
    <div className="grid">
      {urls.map((u, i) => (
        <div className="panel" key={i}>
          <div className="defanged" style={{ fontSize: 15, marginBottom: 8 }}>
            {u.defanged}
          </div>
          <div className="row">
            {u.flags.length === 0 ? (
              <span className="note">No suspicious URL characteristics.</span>
            ) : (
              u.flags.map((f) => (
                <span key={f} className="pill">
                  {f}
                </span>
              ))
            )}
          </div>
          <p className="note" style={{ marginTop: 10 }}>
            Not clickable by design. Use the opt-in redirect inspector (disabled by
            default) rather than a browser.
          </p>
        </div>
      ))}
    </div>
  );
}

function AttachmentsTab({ a }) {
  if (a.attachments.length === 0) return <Empty>No attachments.</Empty>;
  return (
    <div className="grid">
      {a.attachments.map((at, i) => (
        <div className="panel" key={i}>
          <div className="row">
            <b className="mono">{at.filename || "(unnamed)"}</b>
            <span className="spacer" />
            {at.flags.map((f) => (
              <span key={f} className="pill" style={{ color: "#fca5a5" }}>
                {f}
              </span>
            ))}
          </div>
          <KV
            rows={[
              ["Declared MIME", at.declared_mime],
              ["Detected type", at.detected_type || "unknown"],
              ["Size", `${at.size} bytes`],
              ["SHA-256", at.sha256],
              ["Extensions", at.extensions.join(", ") || "-"],
            ]}
          />
          <p className="note" style={{ marginTop: 8, color: "#fbbf24" }}>
            ⚠ Attachments are never executed or opened by PhishLab. Metadata only.
          </p>
        </div>
      ))}
    </div>
  );
}

function ReportTab({ id }) {
  const [redact, setRedact] = useState(true);
  return (
    <div className="panel">
      <h3>Generate report</h3>
      <div className="row" style={{ marginBottom: 14 }}>
        <label className="row" style={{ gap: 6 }}>
          <input
            type="checkbox"
            style={{ width: "auto" }}
            checked={redact}
            onChange={(e) => setRedact(e.target.checked)}
          />
          Redact email addresses in export
        </label>
      </div>
      <div className="row">
        <a href={api.reportPdfUrl(id, redact)} target="_blank" rel="noreferrer">
          <button className="primary">Download PDF</button>
        </a>
        <a href={api.reportJsonUrl(id, redact)} target="_blank" rel="noreferrer">
          <button>View JSON (schema v1.0)</button>
        </a>
      </div>
      <p className="note" style={{ marginTop: 12 }}>
        All URLs in reports are defanged. Reports distinguish observed evidence,
        heuristic findings, and analyst conclusions, and list limitations/caveats.
      </p>
    </div>
  );
}
