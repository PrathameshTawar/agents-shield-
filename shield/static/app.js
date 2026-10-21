/**
 * AgentShield — Apple HIG Frontend Controller
 * Connects to AgentShield FastAPI Endpoints:
 * - /guardrails/evaluate-input
 * - /guardrails/authorize-tool
 * - /guardrails/validate-output
 * - /evaluations/run
 */

(function () {
  "use strict";

  // Safe localStorage helper to avoid crashes when third-party cookies or storage is disabled
  function safeGetStorage(key, fallback) {
    try {
      const val = localStorage.getItem(key);
      return val !== null ? val : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function safeSetStorage(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      // Storage access disabled or quota exceeded
    }
  }

  // 1. Theme Controller
  const themeToggleBtn = document.getElementById("themeToggleBtn");
  const themeToggleIcon = document.getElementById("themeToggleIcon");
  const htmlRoot = document.documentElement;

  function applyTheme(theme) {
    htmlRoot.setAttribute("data-theme", theme);
    safeSetStorage("agentshield-theme", theme);
    if (themeToggleIcon) {
      themeToggleIcon.textContent = theme === "dark" ? "☀️" : "🌙";
    }
  }

  const defaultTheme = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  const savedTheme = safeGetStorage("agentshield-theme", defaultTheme);
  applyTheme(savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      const current = htmlRoot.getAttribute("data-theme") || "light";
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }

  // 2. Subtle Matrix Canvas
  const canvas = document.getElementById("matrixCanvas");
  if (canvas) {
    const ctx = canvas.getContext("2d");
    let width = 0, height = 0;
    const gridSize = 42;
    let particles = [];

    function resize() {
      const rect = canvas.parentElement.getBoundingClientRect();
      width = canvas.width = rect.width;
      height = canvas.height = rect.height;
      particles = Array.from({ length: 24 }, () => ({
        x: Math.floor(Math.random() * (width / gridSize)) * gridSize,
        y: Math.floor(Math.random() * (height / gridSize)) * gridSize,
        speed: 1.5 + Math.random() * 2,
        radius: 2 + Math.random() * 2,
        opacity: 0.3 + Math.random() * 0.5,
      }));
    }

    function render() {
      const isDark = htmlRoot.getAttribute("data-theme") === "dark";
      ctx.clearRect(0, 0, width, height);

      // Grid
      ctx.lineWidth = 1;
      ctx.strokeStyle = isDark ? "rgba(163, 230, 53, 0.08)" : "rgba(16, 185, 129, 0.08)";
      ctx.beginPath();
      for (let x = 0; x <= width; x += gridSize) { ctx.moveTo(x, 0); ctx.lineTo(x, height); }
      for (let y = 0; y <= height; y += gridSize) { ctx.moveTo(0, y); ctx.lineTo(width, y); }
      ctx.stroke();

      // Pulses
      particles.forEach((p) => {
        p.y += p.speed;
        if (p.y > height) { p.y = 0; p.x = Math.floor(Math.random() * (width / gridSize)) * gridSize; }
        ctx.fillStyle = isDark ? "rgba(163, 230, 53, 0.85)" : "rgba(16, 185, 129, 0.75)";
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();
      });
      requestAnimationFrame(render);
    }

    window.addEventListener("resize", resize);
    resize();
    render();
  }

  // 3. Security Guardrail Evaluation
  const evaluateBtn = document.getElementById("evaluateBtn");
  const promptInput = document.getElementById("promptInput");
  const terminalLogs = document.getElementById("terminalLogs");
  const liveStatusText = document.getElementById("liveStatusText");
  const statusBeacon = document.getElementById("statusBeacon");

  function appendLog(text, type = "info") {
    const p = document.createElement("p");
    p.className = `log-line log-${type}`;
    p.textContent = text;
    terminalLogs.appendChild(p);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
  }

  async function evaluatePrompt(text) {
    terminalLogs.innerHTML = "";
    evaluateBtn.disabled = true;
    evaluateBtn.textContent = "Inspecting Security Perimeter...";
    liveStatusText.textContent = "INSPECTING...";
    statusBeacon.style.background = "#ffbd2e";
    statusBeacon.style.boxShadow = "0 0 10px #ffbd2e";

    appendLog(`[AgentShield Perimeter] Inbound Prompt: "${text}"`, "step");

    try {
      const response = await fetch("/guardrails/evaluate-input", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, is_retrieved_document: false }),
      });

      if (!response.ok) {
        throw new Error(`Server returned status ${response.status}`);
      }

      const verdict = await response.json();

      appendLog(`\n[Decision Verdict]: ${verdict.decision.toUpperCase()}`, verdict.allowed ? (verdict.pii_detected ? "warn" : "success") : "blocked");
      appendLog(`[Risk Level]: ${verdict.risk_level.toUpperCase()}`, "info");

      if (verdict.injection_detected) {
        appendLog(`[ALERT] Prompt Injection Detected!`, "blocked");
        verdict.reasons.forEach((r) => appendLog(`  • ${r}`, "blocked"));
        statusBeacon.style.background = "#ef4444";
        liveStatusText.textContent = "ATTACK DEFLECTED";
      } else if (verdict.pii_detected) {
        appendLog(`[PII Redaction Engine] Sensitive Entities Sanitized:`, "warn");
        verdict.detected_entities.forEach((e) => appendLog(`  • Entity Type: ${e}`, "warn"));
        appendLog(`\n[Sanitized Output (Safe for LLM)]:`, "step");
        appendLog(`"${verdict.sanitized_text}"`, "success");
        statusBeacon.style.background = "#F59E0B";
        liveStatusText.textContent = "PII REDACTED";
      } else {
        appendLog(`✓ Input Verified: No injection patterns or PII detected.`, "success");
        appendLog(`Safe Output: "${verdict.sanitized_text}"`, "info");
        statusBeacon.style.background = "#10B981";
        statusBeacon.style.boxShadow = "0 0 10px #10B981";
        liveStatusText.textContent = "PERIMETER SECURE";
      }
    } catch (err) {
      appendLog(`\n✗ Guardrail Error: ${err.message}`, "warn");
      statusBeacon.style.background = "#ef4444";
    } finally {
      evaluateBtn.disabled = false;
      evaluateBtn.textContent = "Evaluate Security Guardrails 🛡️";
    }
  }

  if (evaluateBtn) {
    evaluateBtn.addEventListener("click", () => {
      const val = promptInput.value.trim() || "My email is alice@company.com and card is 4532-1234-5678-9012";
      evaluatePrompt(val);
    });
  }

  // Presets
  document.querySelectorAll(".preset-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      promptInput.value = pill.getAttribute("data-preset");
    });
  });

  // 4. Modals
  const privacyModal = document.getElementById("privacyModal");
  const termsModal = document.getElementById("termsModal");
  const openPrivacyBtn = document.getElementById("openPrivacyBtn");
  const openTermsBtn = document.getElementById("openTermsBtn");

  function openM(m) { if (m) m.classList.add("active"); }
  function closeM(m) { if (m) m.classList.remove("active"); }

  if (openPrivacyBtn) openPrivacyBtn.addEventListener("click", () => openM(privacyModal));
  if (openTermsBtn) openTermsBtn.addEventListener("click", () => openM(termsModal));

  document.querySelectorAll(".modal-close-btn, #acceptPrivacyBtn, #acceptTermsBtn").forEach((btn) => {
    btn.addEventListener("click", () => {
      closeM(privacyModal);
      closeM(termsModal);
    });
  });

  [privacyModal, termsModal].forEach((m) => {
    if (m) m.addEventListener("click", (e) => { if (e.target === m) closeM(m); });
  });

  console.log("AgentShield Apple HIG Frontend Connected.");
})();
