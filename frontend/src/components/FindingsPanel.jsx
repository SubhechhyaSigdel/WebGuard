import FindingCard from "./FindingCard";

export default function FindingsPanel({ vulns, message }) {
  const counts = { high: 0, medium: 0, low: 0 };
  for (const v of vulns) {
    const k = String(v.severity || "").toLowerCase();
    if (k in counts) counts[k]++;
  }

  return (
    <section className="panel findings-panel reveal delay-3">
      <div className="findings-header">
        <p className="panel-title" style={{ margin: 0 }}>
          Findings
        </p>
        <div className="count-pills">
          <span className="count-pill pill-all">All: {vulns.length}</span>
          <span className="count-pill pill-high">High: {counts.high}</span>
          <span className="count-pill pill-medium">Med: {counts.medium}</span>
          <span className="count-pill pill-low">Low: {counts.low}</span>
        </div>
      </div>

      {message && vulns.length === 0 && (
        <div className="findings-empty">{message}</div>
      )}

      {!message && vulns.length === 0 && (
        <div className="findings-empty">
          No results yet — start a scan above.
        </div>
      )}

      {vulns.map((v, i) => (
        <FindingCard key={i} vuln={v} />
      ))}
    </section>
  );
}
