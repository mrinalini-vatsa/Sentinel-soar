"""
SentinelSOAR — FastAPI application entry.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse

from app.routes import api_router
from app.utils.logger import setup_logging

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SentinelSOAR</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f172a;
      color: #f1f5f9;
      font-family: "SF Pro Text", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      padding: 1.5rem;
      -webkit-font-smoothing: antialiased;
    }
    .shell {
      width: 100%;
      max-width: 440px;
    }
    .card {
      background: #1e293b;
      border-radius: 16px;
      padding: 1.75rem 1.85rem;
      border: 1px solid #334155;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.45), 0 0 0 1px rgba(148, 163, 184, 0.06) inset;
    }
    .title {
      margin: 0;
      font-size: 1.55rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      line-height: 1.2;
    }
    .subtitle {
      margin: 0.4rem 0 1.35rem;
      font-size: 0.875rem;
      color: #94a3b8;
      font-weight: 500;
    }
    .section-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: #64748b;
      margin-bottom: 0.5rem;
      font-weight: 600;
    }
    label[for="ip"] {
      display: block;
      font-size: 0.8rem;
      color: #cbd5e1;
      margin-bottom: 0.4rem;
      font-weight: 500;
    }
    input[type="text"] {
      width: 100%;
      padding: 0.75rem 1rem;
      border-radius: 10px;
      border: 1px solid #475569;
      background: #0f172a;
      color: #f8fafc;
      font-size: 1rem;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="text"]:focus {
      outline: none;
      border-color: #38bdf8;
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }
    .btn-analyze {
      margin-top: 0.85rem;
      width: 100%;
      padding: 0.8rem 1rem;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      color: #052e16;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
      letter-spacing: 0.02em;
      box-shadow: 0 4px 14px rgba(34, 197, 94, 0.35);
      transition: transform 0.15s, box-shadow 0.2s, filter 0.2s;
    }
    .btn-analyze:hover:not(:disabled) {
      filter: brightness(1.08);
      box-shadow: 0 6px 20px rgba(34, 197, 94, 0.45);
      transform: translateY(-1px);
    }
    .btn-analyze:active:not(:disabled) { transform: translateY(0); }
    .btn-analyze:disabled {
      opacity: 0.55;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .results-section {
      margin-top: 1.5rem;
      padding-top: 1.35rem;
      border-top: 1px solid #334155;
    }
    .state-placeholder {
      color: #64748b;
      font-size: 0.875rem;
      line-height: 1.5;
    }
    .loader {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 1rem;
      padding: 1.25rem 0;
      color: #94a3b8;
      font-size: 0.9rem;
      font-weight: 500;
    }
    .spinner {
      width: 36px;
      height: 36px;
      border: 3px solid #334155;
      border-top-color: #38bdf8;
      border-radius: 50%;
      animation: spin 0.75s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .result-card {
      background: #0f172a;
      border-radius: 12px;
      padding: 1.1rem 1.15rem;
      border: 1px solid #334155;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .result-card.error-card { border-color: #7f1d1d; }
    .row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.75rem;
      padding: 0.55rem 0;
      border-bottom: 1px solid #1e293b;
      font-size: 0.9rem;
    }
    .row:last-child { border-bottom: none; padding-bottom: 0; }
    .row:first-of-type { padding-top: 0; }
    .row-k { color: #94a3b8; font-weight: 500; flex-shrink: 0; }
    .row-v { color: #f1f5f9; text-align: right; word-break: break-all; font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.65rem;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .badge-safe { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.45); }
    .badge-suspicious { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.45); }
    .badge-malicious { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }
    .badge-neutral { background: #334155; color: #cbd5e1; border: 1px solid #475569; }
    .progress-wrap { margin-top: 0.35rem; }
    .progress-label {
      display: flex;
      justify-content: space-between;
      font-size: 0.75rem;
      color: #94a3b8;
      margin-bottom: 0.35rem;
    }
    .progress-track {
      height: 8px;
      border-radius: 999px;
      background: #1e293b;
      overflow: hidden;
      border: 1px solid #334155;
    }
    .progress-fill {
      height: 100%;
      border-radius: 999px;
      transition: width 0.45s ease;
    }
    .progress-fill.low { background: linear-gradient(90deg, #22c55e, #4ade80); }
    .progress-fill.mid { background: linear-gradient(90deg, #ca8a04, #eab308); }
    .progress-fill.high { background: linear-gradient(90deg, #dc2626, #f87171); }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <h1 class="title">🛡️ SentinelSOAR</h1>
      <p class="subtitle">IP Threat Intelligence Dashboard</p>
      <div class="section-label">Target</div>
      <label for="ip">IP address</label>
      <input type="text" id="ip" placeholder="e.g. 8.8.8.8" autocomplete="off" />
      <button type="button" class="btn-analyze" id="btn">Analyze</button>
      <div class="results-section">
        <div class="section-label">Assessment</div>
        <div id="placeholder" class="state-placeholder">Enter an IP address and run analysis to view threat intelligence.</div>
        <div id="loader" class="loader hidden">
          <div class="spinner" aria-hidden="true"></div>
          <span>Analyzing...</span>
        </div>
        <div id="dashboard" class="hidden"></div>
      </div>
    </div>
  </div>
  <script>
    (function () {
      var ipEl = document.getElementById("ip");
      var btn = document.getElementById("btn");
      var placeholder = document.getElementById("placeholder");
      var loader = document.getElementById("loader");
      var dashboard = document.getElementById("dashboard");

      function setPhase(phase) {
        placeholder.classList.toggle("hidden", phase !== "placeholder");
        loader.classList.toggle("hidden", phase !== "loader");
        dashboard.classList.toggle("hidden", phase !== "dashboard");
      }

      function el(tag, cls) {
        var n = document.createElement(tag);
        if (cls) n.className = cls;
        return n;
      }

      function row(k, vNode) {
        var r = el("div", "row");
        var a = el("span", "row-k");
        a.textContent = k;
        var b = el("span", "row-v");
        if (typeof vNode === "string" || typeof vNode === "number") {
          b.textContent = vNode === "" ? "—" : String(vNode);
        } else {
          b.appendChild(vNode);
        }
        r.appendChild(a);
        r.appendChild(b);
        return r;
      }

      function statusBadge(status) {
        var s = (status || "").toLowerCase();
        var span = el("span", "badge");
        if (s === "safe") span.className += " badge-safe";
        else if (s === "suspicious") span.className += " badge-suspicious";
        else if (s === "malicious") span.className += " badge-malicious";
        else span.className += " badge-neutral";
        span.textContent = status || "unknown";
        return span;
      }

      function threatBar(score) {
        var n = Math.max(0, Math.min(100, Number(score) || 0));
        var wrap = el("div", "progress-wrap");
        var lab = el("div", "progress-label");
        lab.innerHTML = "<span>Threat score</span><span>" + n + " / 100</span>";
        var track = el("div", "progress-track");
        var fill = el("div", "progress-fill");
        if (n <= 39) fill.className += " low";
        else if (n <= 70) fill.className += " mid";
        else fill.className += " high";
        fill.style.width = n + "%";
        track.appendChild(fill);
        wrap.appendChild(lab);
        wrap.appendChild(track);
        return wrap;
      }

      function showSuccess(data) {
        dashboard.innerHTML = "";
        var card = el("div", "result-card");
        card.appendChild(row("IP", data.ip));
        card.appendChild(row("Country", data.country != null ? data.country : "—"));
        card.appendChild(row("ISP", data.isp != null ? data.isp : "—"));
        card.appendChild(row("Threat score", String(data.threat_score != null ? data.threat_score : "—")));
        card.appendChild(row("Status", statusBadge(data.status)));
        card.appendChild(row("Action", data.action != null ? data.action : "—"));
        card.appendChild(threatBar(data.threat_score));
        dashboard.appendChild(card);
        setPhase("dashboard");
      }

      function showError(body, statusCode) {
        dashboard.innerHTML = "";
        var card = el("div", "result-card error-card");
        var bad = el("span", "badge badge-malicious");
        bad.textContent = statusCode ? "HTTP " + statusCode : "Error";
        card.appendChild(row("Status", bad));
        var msg = body && body.message ? body.message : JSON.stringify(body, null, 2);
        card.appendChild(row("Detail", msg));
        dashboard.appendChild(card);
        setPhase("dashboard");
      }

      btn.addEventListener("click", function () {
        var ip = (ipEl.value || "").trim();
        if (!ip) {
          setPhase("placeholder");
          placeholder.textContent = "Please enter an IP address.";
          return;
        }
        placeholder.textContent = "Enter an IP address and run analysis to view threat intelligence.";
        btn.disabled = true;
        setPhase("loader");

        fetch("/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify({ ip: ip })
        })
          .then(function (res) {
            var ct = (res.headers.get("content-type") || "").toLowerCase();
            if (ct.indexOf("application/json") !== -1) {
              return res.json().then(function (body) {
                return { ok: res.ok, status: res.status, body: body };
              });
            }
            return res.text().then(function (text) {
              return { ok: res.ok, status: res.status, body: { message: text || "(empty)" } };
            });
          })
          .then(function (r) {
            if (r.ok && r.body && typeof r.body.ip === "string" && r.body.threat_score != null) {
              showSuccess(r.body);
            } else {
              showError(r.body, r.status);
            }
          })
          .catch(function (e) {
            dashboard.innerHTML = "";
            var card = el("div", "result-card error-card");
            card.appendChild(row("Network", (e && e.message) ? e.message : String(e)));
            dashboard.appendChild(card);
            setPhase("dashboard");
          })
          .finally(function () {
            btn.disabled = false;
          });
      });
    })();
  </script>
</body>
</html>
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    yield


app = FastAPI(
    title="SentinelSOAR",
    description="AI-powered SOAR system for IP threat analysis",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Consistent JSON for invalid bodies (e.g. malformed IP)."""
    errors = exc.errors()
    first = errors[0] if errors else {}
    msg = first.get("msg", "Validation error")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder(
            {
                "detail": "Request validation failed",
                "errors": errors,
                "message": msg,
            }
        ),
    )


# Register API routes first so paths like /analyze are not shadowed by catch-alls.
app.include_router(api_router)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
@app.head("/", include_in_schema=False)
async def index():
    """Browser GET/HEAD for the UI (HEAD avoids 405 from some clients)."""
    return HTMLResponse(
        content=_INDEX_HTML,
        media_type="text/html; charset=utf-8",
    )
