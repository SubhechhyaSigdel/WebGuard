import { FaShieldAlt } from "react-icons/fa";
export default function HeroSection() {
  return (
    <section className="panel hero reveal">
      <p className="hero-eyebrow">// web vulnerability scanner v1.0</p>
      <h1 className="hero-title">
        <FaShieldAlt className="hero-icon" />
        Web<span>Guard</span>
      </h1>
      <p className="hero-sub">
        Launch authenticated scans, track live status, and triage SQLi, XSS, and
        CSRF findings — all from one dashboard.
      </p>
      <div className="hero-badges">
        <span className="hero-badge">SQLi</span>
        <span className="hero-badge">XSS</span>
        <span className="hero-badge">CSRF</span>
        <span className="hero-badge">Auth-aware</span>
        <span className="hero-badge">Live polling</span>
      </div>
    </section>
  );
}
