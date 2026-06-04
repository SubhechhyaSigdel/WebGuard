function sevClass(severity) {
  const s = String(severity || "").toLowerCase();
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}

export default function FindingCard({ vuln }) {
  const sev = sevClass(vuln.severity);
  return (
    <article className={`finding-card sev-${sev}`}>
      <div className="finding-top">
        <h3 className="finding-title">{vuln.vuln_type || "Unknown"}</h3>
        <span className={`sev-badge ${sev}`}>{vuln.severity || "LOW"}</span>
      </div>
      <div className="finding-fields">
        <div className="finding-field">
          <strong>URL</strong>
          {vuln.affected_url || "—"}
        </div>
        <div className="finding-field">
          <strong>Parameter</strong>
          <code>{vuln.parameter || "—"}</code>
        </div>
        <div className="finding-field">
          <strong>Payload</strong>
          <code>{vuln.payload || "—"}</code>
        </div>
        <div className="finding-field">
          <strong>Evidence</strong>
          {vuln.evidence || "—"}
        </div>
        {vuln.description && (
          <div className="finding-field full">
            <strong>Description</strong>
            {vuln.description}
          </div>
        )}
      </div>
    </article>
  );
}
