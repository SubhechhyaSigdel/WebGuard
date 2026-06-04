import { useState, useRef, useCallback } from "react";
import {
  normalizeBase,
  parseExtraFields,
  startScanRequest,
  fetchScanStatus,
} from "../utils/scanApi";

const INITIAL_FORM = {
  apiBase: "http://127.0.0.1:8000/api",
  targetUrl: "http://127.0.0.1:4280/",
  useAuth: true,
  loginUrl: "http://127.0.0.1:4280/login.php",
  username: "admin",
  password: "password",
  usernameField: "username",
  passwordField: "password",
  loginMethod: "post",
  securityUrl: "http://127.0.0.1:4280/security.php",
  securityLevel: "low",
  securityField: "security",
  extraFields: '{"Login":"Login"}',
};

export default function useScan() {
  const [form, setForm] = useState(INITIAL_FORM);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState("idle");
  const [scanTarget, setScanTarget] = useState(null);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [vulns, setVulns] = useState([]);
  const [message, setMessage] = useState(null);
  const [scanning, setScanning] = useState(false);

  const pollRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  function setField(key, value) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function buildPayload() {
    const payload = { url: form.targetUrl.trim() };
    if (!form.useAuth) return payload;

    const extraFields = parseExtraFields(form.extraFields);
    payload.auth = {
      login_url: form.loginUrl.trim(),
      username: form.username,
      password: form.password,
      username_field: form.usernameField.trim() || "username",
      password_field: form.passwordField.trim() || "password",
      method: form.loginMethod,
      extra_fields: extraFields,
      security_url: form.securityUrl.trim() || null,
      security_level: form.securityLevel.trim() || null,
      security_field: form.securityField.trim() || "security",
    };
    return payload;
  }

  function doStopPolling() {
    stopPolling();
    setScanning(false);
    setScanStatus("pending");
  }

  async function pollScan(base, id) {
    stopPolling();

    async function tick() {
      try {
        const result = await fetchScanStatus(base, id);
        setScanStatus(result.status || "idle");
        setScanTarget(result.target_url || form.targetUrl);
        setUpdatedAt(new Date().toLocaleTimeString());
        setVulns(result.vulnerabilities || []);
        setMessage(null);

        const done = ["completed", "failed"].includes(
          String(result.status).toLowerCase()
        );
        if (done) {
          stopPolling();
          setScanning(false);
        }
      } catch (err) {
        stopPolling();
        setScanning(false);
        setScanStatus("failed");
        setMessage(err.message);
      }
    }

    await tick();
    pollRef.current = setInterval(tick, 3000);
  }

  async function startScan(e) {
    e.preventDefault();
    stopPolling();

    let payload;
    try {
      payload = buildPayload();
    } catch (err) {
      setScanStatus("failed");
      setMessage(err.message);
      return;
    }

    const base = normalizeBase(form.apiBase);
    setScanning(true);
    setVulns([]);
    setMessage("Starting scan…");
    setScanStatus("pending");

    try {
      const data = await startScanRequest(base, payload);
      setScanId(data.scan_id);
      setScanTarget(form.targetUrl);
      setScanStatus(data.status || "pending");
      setMessage("Polling for results…");
      await pollScan(base, data.scan_id);
    } catch (err) {
      setScanning(false);
      setScanStatus("failed");
      setMessage(err.message);
    }
  }

  return {
    form,
    setField,
    scanId,
    scanStatus,
    scanTarget,
    updatedAt,
    vulns,
    message,
    scanning,
    startScan,
    stopPolling: doStopPolling,
  };
}