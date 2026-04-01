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
      color: #f8fafc;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      padding: 1.5rem;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: #1e293b;
      border-radius: 16px;
      padding: 2rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid #334155;
    }
    h1 {
      margin: 0 0 0.35rem;
      font-size: 1.65rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .sub {
      margin: 0 0 1.5rem;
      font-size: 0.875rem;
      color: #94a3b8;
    }
    label {
      display: block;
      font-size: 0.8rem;
      color: #cbd5e1;
      margin-bottom: 0.4rem;
    }
    input[type="text"] {
      width: 100%;
      padding: 0.75rem 1rem;
      border-radius: 10px;
      border: 1px solid #475569;
      background: #0f172a;
      color: #f8fafc;
      font-size: 1rem;
      outline: none;
      transition: border-color 0.15s;
    }
    input[type="text"]:focus {
      border-color: #22c55e;
    }
    button {
      margin-top: 1rem;
      width: 100%;
      padding: 0.8rem 1rem;
      border: none;
      border-radius: 10px;
      background: #22c55e;
      color: #052e16;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: filter 0.15s, transform 0.05s;
    }
    button:hover { filter: brightness(1.08); }
    button:active { transform: scale(0.98); }
    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .result {
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 12px;
      background: #0f172a;
      border: 1px solid #334155;
      min-height: 3rem;
      font-size: 0.9rem;
    }
    .result h2 {
      margin: 0 0 0.75rem;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #94a3b8;
    }
    .row {
      display: grid;
      grid-template-columns: 7rem 1fr;
      gap: 0.35rem 1rem;
      margin-bottom: 0.5rem;
    }
    .row span:first-child { color: #94a3b8; }
    .err { color: #f87171; white-space: pre-wrap; }
    .empty { color: #64748b; font-style: italic; }
  </style>
</head>
<body>
  <div class="card">
    <h1>SentinelSOAR</h1>
    <p class="sub">IP threat analysis</p>
    <label for="ip">IP address</label>
    <input type="text" id="ip" placeholder="e.g. 8.8.8.8" autocomplete="off" />
    <button type="button" id="btn">Analyze</button>
    <div class="result" id="out" aria-live="polite">
      <h2>Result</h2>
      <div class="empty" id="placeholder">Run an analysis to see details.</div>
      <div id="content" hidden></div>
    </div>
  </div>
  <script>
    (function () {
      var ipEl = document.getElementById("ip");
      var btn = document.getElementById("btn");
      var placeholder = document.getElementById("placeholder");
      var content = document.getElementById("content");

      function fieldRow(label, value) {
        var r = document.createElement("div");
        r.className = "row";
        var a = document.createElement("span");
        a.textContent = label;
        var b = document.createElement("span");
        b.textContent = value != null ? String(value) : "—";
        r.appendChild(a);
        r.appendChild(b);
        return r;
      }

      function showError(msg) {
        placeholder.hidden = true;
        content.hidden = false;
        content.innerHTML = "";
        var p = document.createElement("p");
        p.className = "err";
        p.textContent = msg;
        content.appendChild(p);
      }

      function showData(data) {
        placeholder.hidden = true;
        content.hidden = false;
        content.innerHTML = "";
        content.appendChild(fieldRow("IP", data.ip));
        content.appendChild(fieldRow("Country", data.country));
        content.appendChild(fieldRow("ISP", data.isp));
        content.appendChild(fieldRow("Threat score", data.threat_score));
        content.appendChild(fieldRow("Status", data.status));
        content.appendChild(fieldRow("Action", data.action));
      }

      btn.addEventListener("click", function () {
        var ip = (ipEl.value || "").trim();
        if (!ip) {
          showError("Please enter an IP address.");
          return;
        }
        btn.disabled = true;
        placeholder.hidden = true;
        content.hidden = false;
        content.innerHTML = "";
        var w = document.createElement("p");
        w.className = "empty";
        w.textContent = "Analyzing…";
        content.appendChild(w);

        fetch("/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip: ip })
        })
          .then(function (res) {
            return res.json().then(function (body) {
              return { ok: res.ok, status: res.status, body: body };
            });
          })
          .then(function (r) {
            if (r.ok) {
              showData(r.body);
            } else {
              var msg = r.body && r.body.message ? r.body.message : JSON.stringify(r.body);
              showError("Request failed (" + r.status + "): " + msg);
            }
          })
          .catch(function (e) {
            showError("Network error: " + (e && e.message ? e.message : String(e)));
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


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    return HTMLResponse(content=_INDEX_HTML)


app.include_router(api_router)
