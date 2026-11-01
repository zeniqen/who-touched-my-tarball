"""Streamlit front-end for the WhoTouchedMyTarball (WTMT) Security Lab."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from whotouchedmytarball.redteam import ATTACKS  # noqa: E402

BASE_FIXTURE = ROOT / "examples" / "offline-demo" / "clean.tgz"
SOURCE_TREE = ROOT / "examples" / "offline-demo" / "source"
DEFAULT_ATTACK = "wallet-hook"


def cli(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run the WTMT CLI with an argument array (never shell=True)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "whotouchedmytarball.cli", *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        shell=False,
        timeout=timeout,
    )


def result_card(report: dict, manifest: dict | None = None) -> None:
    col1, col2 = st.columns(2)
    col1.metric("Verdict", report.get("verdict", "UNKNOWN"))
    col2.metric("Risk score", f'{report.get("risk_score", 0)}/100')
    st.write(report.get("summary", ""))
    if manifest:
        st.subheader("Modified files")
        st.write(manifest.get("changed_files", []))
        base = manifest.get("base_sha256")
        if base:
            st.caption(f'Base fixture SHA-256: {base}')
    st.subheader("Findings")
    for finding in report.get("findings", []):
        with st.container(border=True):
            st.markdown(f"**{finding['path']}** - {finding['severity'].upper()}  \n{finding['reason']}")
            signals = finding.get("signals", [])
            if signals:
                st.code(
                    "\n".join(
                        f"- {s.get('rule')} (line {s.get('line')})" for s in signals
                    ),
                    language="text",
                )
    if report.get("notes"):
        with st.expander("Analyzer notes"):
            for note in report["notes"]:
                st.write(note)


def save_upload(uploaded_file) -> tuple[Path, Path]:
    workdir = Path(tempfile.mkdtemp(prefix="wtmt-upload-"))
    suffix = Path(uploaded_file.name).suffix or ".bin"
    target = workdir / f"uploaded{suffix}"
    target.write_bytes(uploaded_file.getvalue())
    return target, workdir


st.set_page_config(page_title="WTMT Security Lab", page_icon="WTMT", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background: radial-gradient(circle at top, #111827 0%, #050816 65%); }
    .sim-label { color: #fca5a5; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("WTMT Security Lab")
st.caption("Offline simulation. Findings and metrics come only from actual WTMT analyzer and CLI output.")

page = st.sidebar.radio("Page", ["Dashboard", "Red-Team Lab", "Benchmark"])

if page == "Dashboard":
    st.header("Package Analysis")
    st.markdown(
        '<p class="sim-label">Offline demo sources are controlled, simulated attacks, never real malware.</p>',
        unsafe_allow_html=True,
    )
    uploaded = st.file_uploader("Package artifact (.tgz, .tar.gz, .whl, .zip)", type=["tgz", "tar.gz", "whl", "zip"])
    source_path = st.text_input("Source tree", value=str(SOURCE_TREE))
    if st.button("Analyze", type="primary"):
        if uploaded is None:
            st.error("Upload a package artifact first.")
        elif not Path(source_path).exists():
            st.error("Source tree does not exist.")
        else:
            artifact, workdir = save_upload(uploaded)
            report_path = workdir / "analysis.json"
            cmd = ["diff", str(artifact), str(Path(source_path).resolve()), "--no-ai", "--json", str(report_path)]
            with st.spinner("Analyzing with WTMT..."):
                result = cli(*cmd)
            if result.returncode == 0 or report_path.exists():
                report = json.loads(report_path.read_text())
                result_card(report)
                with st.expander("WTMT CLI output"):
                    st.code(result.stdout + result.stderr, language="text")
            else:
                st.error(result.stderr or "Analysis failed.")
                st.code(result.stdout + result.stderr, language="text")
            shutil.rmtree(workdir, ignore_errors=True)

elif page == "Red-Team Lab":
    st.header("Red-Team Simulation")
    st.warning("Offline fixtures only. The injected payloads are inert and never installed or executed.")

    attack = st.selectbox(
        "Attack",
        options=sorted(ATTACKS),
        index=sorted(ATTACKS).index(DEFAULT_ATTACK if DEFAULT_ATTACK in ATTACKS else sorted(ATTACKS)[0]),
        format_func=lambda item: f"{item} - {ATTACKS[item].title}",
    )
    st.caption(ATTACKS[attack].incident)

    if st.button("Run Red-Team Simulation", type="primary"):
        if not BASE_FIXTURE.exists() or not SOURCE_TREE.exists():
            st.error("Offline fixture or source tree is missing.")
        else:
            tempdir = Path(tempfile.mkdtemp(prefix="wtmt-redteam-ui-"))
            tampered_dir = tempdir / "tampered"
            report_json = tempdir / "report.json"
            tamper_result = cli("tamper", "--file", str(BASE_FIXTURE), "--attack", attack, "--out", str(tampered_dir))
            tampered = list(tampered_dir.glob("*.tgz"))
            if tamper_result.returncode != 0 or not tampered:
                st.error(tamper_result.stderr or "Tampering failed.")
                st.code(tamper_result.stdout + tamper_result.stderr, language="text")
                shutil.rmtree(tempdir, ignore_errors=True)
            else:
                tampered = tampered[0]
                manifest_path = tampered.with_name(tampered.name + ".wtmt-redteam.json")
                manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
                analysis_result = cli(
                    "diff", str(tampered), str(SOURCE_TREE.resolve()), "--no-ai", "--json", str(report_json)
                )
                if result := (report_json.exists()):
                    report = json.loads(report_json.read_text())
                    result_card(report, manifest)
                    st.subheader("Tamper CLI output")
                    st.code(tamper_result.stdout + tamper_result.stderr, language="text")
                    st.subheader("Analyzer CLI output")
                    st.code(analysis_result.stdout + analysis_result.stderr, language="text")
                else:
                    st.error(analysis_result.stderr or "Analysis failed.")
                    st.code(analysis_result.stdout + analysis_result.stderr, language="text")
                shutil.rmtree(tempdir, ignore_errors=True)

else:
    st.header("Offline Benchmark")
    st.info("Runs the actual WTMT benchmark and displays only WTMT-generated metrics.")
    scenario = st.text_input("Scenario id (optional)", value="")
    if st.button("Run Benchmark", type="primary"):
        tempdir = Path(tempfile.mkdtemp(prefix="wtmt-bench-ui-"))
        output = tempdir / "benchmark.json"
        args = ["benchmark", "run", "--output", str(output)]
        if scenario.strip():
            args.extend(["--scenario", scenario.strip()])
        with st.spinner("Running WTMT benchmark..."):
            result = cli(*args, timeout=600)
        if result.returncode == 0 and output.exists():
            data = json.loads(output.read_text())
            metrics = st.columns(4)
            metrics[0].metric("Precision", f"{data.get('precision', 0):.3f}")
            metrics[1].metric("Recall", f"{data.get('recall', 0):.3f}")
            metrics[2].metric("F1", f"{data.get('f1', 0):.3f}")
            metrics[3].metric("FPR", f"{data.get('fpr', 0):.3f}")
            st.write(f"Total: {data.get('total')}  Malicious: {data.get('malicious')}  Benign: {data.get('benign')}")
            st.write(f"TP: {data.get('tp')}  TN: {data.get('tn')}  FP: {data.get('fp')}  FN: {data.get('fn')}")
            with st.expander("Benchmark CLI output"):
                st.code(result.stdout + result.stderr, language="text")
            st.download_button("Download raw benchmark JSON", output.read_text(), file_name="benchmark.json")
        else:
            st.error(result.stderr or "Benchmark failed.")
            st.code(result.stdout + result.stderr, language="text")
        shutil.rmtree(tempdir, ignore_errors=True)
