import AuthFields from "./AuthFields";

export default function ScanForm({
  form,
  setField,
  scanning,
  onSubmit,
  onStopPolling,
}) {
  return (
    <section className="panel form-panel reveal delay-1">
      <p className="panel-title">Configure Scan</p>
      <form onSubmit={onSubmit}>
        <div className="form-grid">
          <div className="form-group">
            <label className="form-label">API Base</label>
            <input
              type="url"
              className="form-input"
              value={form.apiBase}
              onChange={(e) => setField("apiBase", e.target.value)}
              required
              placeholder="http://127.0.0.1:8000/api"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Target URL</label>
            <input
              type="url"
              className="form-input"
              value={form.targetUrl}
              onChange={(e) => setField("targetUrl", e.target.value)}
              required
              placeholder="http://target.local/"
            />
          </div>

          <div className="form-group full">
            <label className="toggle-row">
              <input
                type="checkbox"
                className="toggle-checkbox"
                checked={form.useAuth}
                onChange={(e) => setField("useAuth", e.target.checked)}
              />
              Use Authentication
            </label>
          </div>

          {form.useAuth && (
            <div className="form-group full">
              <AuthFields form={form} setField={setField} />
            </div>
          )}
        </div>

        <div className="btn-row">
          <button type="submit" className="btn btn-primary" disabled={scanning}>
            {scanning ? (
              <>
                <span className="btn-spinner" />
                Scanning…
              </>
            ) : (
              "▶ Start Scan"
            )}
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={onStopPolling}
          >
            ■ Stop Polling
          </button>
        </div>
      </form>
    </section>
  );
}
