"""
Streamlit dashboard for SentinelSOAR.

  streamlit run streamlit_app.py
"""

from __future__ import annotations

import asyncio
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import streamlit as st

from app.utils.logger import setup_logging

st.set_page_config(page_title="SentinelSOAR", layout="centered")
st.title("SentinelSOAR")
st.caption("IP threat analysis · AbuseIPDB · policy-driven response")

setup_logging()

ip_input = st.text_input("IP address", placeholder="e.g. 8.8.8.8", value="8.8.8.8")

if st.button("Analyze", type="primary"):
    from pydantic import ValidationError

    from app.models.schemas import AnalyzeRequest
    from app.services.pipeline import analyze_ip

    with st.spinner("Calling threat intelligence…"):
        try:
            validated = AnalyzeRequest(ip=ip_input)
        except ValidationError as exc:
            errs = exc.errors()
            msg = errs[0]["msg"] if errs else str(exc)
            st.error(f"Invalid input: {msg}")
        else:
            try:
                result = asyncio.run(analyze_ip(validated.ip))
            except Exception as exc:  # noqa: BLE001
                st.error(f"Analysis failed: {exc}")
            else:
                st.success("Done")
                st.json(result.model_dump(mode="json"))

st.divider()
st.markdown(
    "Set **`ABUSEIPDB_API_KEY`** in `.env`. "
    "Run the API with `uvicorn app.main:app` or `python main.py`."
)
