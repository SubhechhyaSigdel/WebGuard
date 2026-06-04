import "./App.css";
import useScan from "./hooks/useScan";
import HeroSection from "./components/HeroSection";
import ScanForm from "./components/ScanForm";
import StatusPanel from "./components/StatusPanel";
import FindingsPanel from "./components/FindingsPanel";

export default function App() {
  const {
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
    stopPolling,
  } = useScan();

  return (
    <div className="app">
      <main className="layout">
        <HeroSection />
        <ScanForm
          form={form}
          setField={setField}
          scanning={scanning}
          onSubmit={startScan}
          onStopPolling={stopPolling}
        />
        <StatusPanel
          scanId={scanId}
          scanStatus={scanStatus}
          scanTarget={scanTarget}
          updatedAt={updatedAt}
        />
        <FindingsPanel vulns={vulns} message={message} />
      </main>
    </div>
  );
}
