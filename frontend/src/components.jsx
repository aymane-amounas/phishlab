import React from "react";

export const SEVERITIES = ["critical", "high", "medium", "low", "informational"];

export function Badge({ kind, value }) {
  return <span className={`badge b-${value}`}>{value}</span>;
}

export function Finding({ f }) {
  return (
    <div className="finding">
      <div className="top">
        <Badge value={f.severity} />
        <span className="rid">{f.rule_id}</span>
        <span className="title">{f.title}</span>
        <span className="spacer" />
        <span className="conf">confidence: {f.confidence}</span>
      </div>
      <div className="evidence">{f.evidence}</div>
      <div className="expl">{f.explanation}</div>
      <div className="rec">{f.recommendation}</div>
      <div className="note" style={{ marginTop: 6 }}>
        source: {f.location} · category: {f.category}
      </div>
    </div>
  );
}

export function KV({ rows }) {
  return (
    <div className="kv">
      {rows.map(([k, v]) => (
        <React.Fragment key={k}>
          <div className="k">{k}</div>
          <div className="v">{v || <span className="note">-</span>}</div>
        </React.Fragment>
      ))}
    </div>
  );
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function ErrorBox({ error }) {
  if (!error) return null;
  return <div className="error">{String(error.message || error)}</div>;
}
