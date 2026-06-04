function StatusBadge({ status }) {
  const s = String(status || "idle").toLowerCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

export default function StatusPanel({
  scanId,
  scanStatus,
  scanTarget,
  updatedAt,
}) {
  return (
    <section className="panel status-panel reveal delay-2">
      <p className="panel-title">Scan Status</p>
      <div className="status-grid">
        <div className="status-cell">
          <p className="status-label">Scan ID</p>
          <p className="status-value">{scanId ?? "—"}</p>
        </div>
        <div className="status-cell">
          <p className="status-label">State</p>
          <p className="status-value">
            <StatusBadge status={scanStatus} />
          </p>
        </div>
        <div className="status-cell">
          <p className="status-label">Target</p>
          <p className="status-value">{scanTarget ?? "—"}</p>
        </div>
        <div className="status-cell">
          <p className="status-label">Last Updated</p>
          <p className="status-value">{updatedAt ?? "—"}</p>
        </div>
      </div>
    </section>
  );
}
