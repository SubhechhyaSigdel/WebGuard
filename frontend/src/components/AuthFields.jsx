export default function AuthFields({ form, setField }) {
  return (
    <div className="auth-section">
      <div className="auth-grid">
        <div className="form-group">
          <label className="form-label">Login URL</label>
          <input
            type="url"
            className="form-input"
            value={form.loginUrl}
            onChange={(e) => setField("loginUrl", e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Login Method</label>
          <select
            className="form-select"
            value={form.loginMethod}
            onChange={(e) => setField("loginMethod", e.target.value)}
          >
            <option value="post">POST</option>
            <option value="get">GET</option>
          </select>
        </div>

        <div className="form-group">
          <label className="form-label">Username</label>
          <input
            type="text"
            className="form-input"
            value={form.username}
            onChange={(e) => setField("username", e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Password</label>
          <input
            type="password"
            className="form-input"
            value={form.password}
            onChange={(e) => setField("password", e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Username Field</label>
          <input
            type="text"
            className="form-input"
            value={form.usernameField}
            onChange={(e) => setField("usernameField", e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Password Field</label>
          <input
            type="text"
            className="form-input"
            value={form.passwordField}
            onChange={(e) => setField("passwordField", e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Security URL</label>
          <input
            type="url"
            className="form-input"
            value={form.securityUrl}
            onChange={(e) => setField("securityUrl", e.target.value)}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Security Level</label>
          <select
            className="form-select"
            value={form.securityLevel}
            onChange={(e) => setField("securityLevel", e.target.value)}
          >
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="impossible">impossible</option>
          </select>
        </div>

        <div className="form-group">
          <label className="form-label">Security Field</label>
          <input
            type="text"
            className="form-input"
            value={form.securityField}
            onChange={(e) => setField("securityField", e.target.value)}
          />
        </div>

        <div className="form-group full">
          <label className="form-label">Extra Fields (JSON object)</label>
          <textarea
            className="form-textarea"
            rows={3}
            value={form.extraFields}
            onChange={(e) => setField("extraFields", e.target.value)}
          />
        </div>
      </div>
    </div>
  );
}
