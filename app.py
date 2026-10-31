"""ThreatGraph Streamlit dashboard.

Run from the repository root:
    streamlit run app.py

The dashboard reads evidence as data only; it never executes uploaded files.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from src.correlate import find_shared_indicators, rank_related_samples
from src.database import ThreatGraphDB
from src.pipeline import import_evidence

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "threatgraph.db"
SUPPORTED_EXTENSIONS = ["txt", "log", "csv", "json"]
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

st.set_page_config(
    page_title="ThreatGraph | Threat Intelligence Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background: #0b1020; color: #e7ecf5; }
    [data-testid="stSidebar"] { background: #10182b; border-right: 1px solid #26324a; }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #151f35, #10182a);
        border: 1px solid #293650; padding: 16px 18px; border-radius: 12px;
    }
    [data-testid="stMetricLabel"] { color: #a8b5cc; }
    [data-testid="stMetricValue"] { color: #f4f7ff; }
    div[data-testid="stDataFrame"] { border: 1px solid #293650; border-radius: 10px; }
    .tg-eyebrow { color: #7dd3fc; text-transform: uppercase; letter-spacing: .16em;
                  font-size: .75rem; font-weight: 700; }
    .tg-subtitle { color: #a8b5cc; margin-top: -.6rem; }
    .tg-card { background: #111a2d; border: 1px solid #293650;
               border-radius: 12px; padding: 16px 18px; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_db(db_path: str) -> ThreatGraphDB:
    return ThreatGraphDB(db_path)


db = get_db(str(DB_PATH))


def query_df(sql: str, params: tuple = ()) -> pd.DataFrame:
    with db._connection() as conn:
        return pd.read_sql_query(sql, conn, params=params)


def query_rows(sql: str, params: tuple = ()) -> list[dict]:
    with db._connection() as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def safe_label(value: object, limit: int = 48) -> str:
    """Escape Graphviz label text and keep graphs readable."""
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def refresh_data() -> None:
    st.cache_data.clear()
    st.rerun()


with st.sidebar:
    st.markdown('<div class="tg-eyebrow">CYBER THREAT INTELLIGENCE</div>', unsafe_allow_html=True)
    st.title("🛡️ ThreatGraph")
    st.caption("Explainable IOC correlation & evidence provenance")
    page = st.radio(
        "WORKSPACE",
        [
            "Overview",
            "Import Evidence",
            "IOC Explorer",
            "Evidence Details",
            "Correlation Graph",
            "Investigation Graph (3D)",
            "Exports",
        ],
        label_visibility="visible",
    )
    st.divider()
    st.markdown("**Local database**")
    st.caption(str(DB_PATH.relative_to(ROOT)) if DB_PATH.is_relative_to(ROOT) else str(DB_PATH))
    if st.button("↻ Refresh dashboard", use_container_width=True):
        refresh_data()
    st.caption("Evidence files are parsed as data, never executed.")


# Shared queries
sample_count = db.count("samples")
indicator_count = db.count("indicators")
import_count = db.count("imports")
occurrence_count = db.count("evidence_occurrences")


def page_header(kicker: str, title: str, subtitle: str) -> None:
    st.markdown(f'<div class="tg-eyebrow">{kicker}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<p class="tg-subtitle">{subtitle}</p>', unsafe_allow_html=True)


if page == "Overview":
    page_header(
        "THREATGRAPH / COMMAND CENTER",
        "Threat intelligence overview",
        "A provenance-first view of evidence imports, indicators, and cross-sample relationships.",
    )

    metric_cols = st.columns(4)
    for col, label, value in zip(
        metric_cols,
        ["Samples", "Unique IOCs", "Evidence imports", "IOC occurrences"],
        [sample_count, indicator_count, import_count, occurrence_count],
    ):
        col.metric(label, f"{value:,}")

    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("IOC composition")
        type_df = query_df(
            """
            SELECT ioc_type AS "IOC type", COUNT(*) AS "Unique indicators"
            FROM indicators
            GROUP BY ioc_type
            ORDER BY COUNT(*) DESC, ioc_type
            """
        )
        if type_df.empty:
            st.info("No indicators yet. Import a TXT, LOG, CSV, or JSON evidence file to get started.")
        else:
            st.bar_chart(type_df.set_index("IOC type"), height=300)
            st.dataframe(type_df, use_container_width=True, hide_index=True)
    with right:
        st.subheader("Recent imports")
        recent_df = query_df(
            """
            SELECT im.imported_at AS "Imported at",
                   im.sample_id AS "Sample",
                   im.source_file AS "Source file",
                   COUNT(e.occurrence_id) AS "Occurrences"
            FROM imports im
            LEFT JOIN evidence_occurrences e ON e.import_id = im.import_id
            GROUP BY im.import_id
            ORDER BY im.imported_at DESC
            LIMIT 8
            """
        )
        if recent_df.empty:
            st.info("No evidence has been imported.")
        else:
            st.dataframe(recent_df, use_container_width=True, hide_index=True)

    st.subheader("Most frequently observed indicators")
    top_df = query_df(
        """
        SELECT i.ioc_type AS "IOC type",
               i.canonical_value AS "Canonical value",
               COUNT(e.occurrence_id) AS "Occurrences",
               COUNT(DISTINCT e.sample_id) AS "Samples"
        FROM indicators i
        JOIN evidence_occurrences e ON e.indicator_id = i.indicator_id
        GROUP BY i.indicator_id
        ORDER BY COUNT(DISTINCT e.sample_id) DESC,
                 COUNT(e.occurrence_id) DESC,
                 i.canonical_value
        LIMIT 10
        """
    )
    if top_df.empty:
        st.caption("Your highest-frequency indicators will appear here after importing evidence.")
    else:
        st.dataframe(top_df, use_container_width=True, hide_index=True)

    st.caption("Correlation counts are based on distinct canonical IOC values shared by samples; they are not a verdict that samples belong to the same campaign.")


elif page == "Import Evidence":
    page_header(
        "INGESTION / PROVENANCE",
        "Import evidence",
        "Extract and normalize indicators while retaining source file and location metadata.",
    )
    st.info(
        "Supported formats: TXT, LOG, CSV, JSON. Maximum size: 10 MiB per file. "
        "PCAP files are not parsed directly; import a text/CSV/JSON analysis summary instead."
    )

    with st.form("evidence_import_form", clear_on_submit=False):
        sample_id = st.text_input(
            "Sample / case ID",
            placeholder="e.g. CASE-2026-001",
            help="Evidence files imported under the same ID are grouped into one sample.",
        ).strip()
        description = st.text_input(
            "Case description (optional)",
            placeholder="Short incident or investigation context",
        )
        uploads = st.file_uploader(
            "Choose evidence files",
            type=SUPPORTED_EXTENSIONS,
            accept_multiple_files=True,
            help="Evidence is read as data only; no file is executed.",
        )
        submitted = st.form_submit_button("Import evidence", type="primary", use_container_width=True)

    if submitted:
        if not sample_id:
            st.error("Enter a sample / case ID before importing.")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", sample_id):
            st.error("Use 1–100 characters: letters, numbers, dots, underscores, or hyphens; the first character must be a letter or number.")
        elif not uploads:
            st.error("Choose at least one evidence file.")
        else:
            results = []
            failures = []
            total_bytes = 0
            for upload in uploads:
                raw = upload.getvalue()
                total_bytes += len(raw)
                if len(raw) > MAX_UPLOAD_BYTES:
                    failures.append((upload.name, "File exceeds the 10 MiB per-file limit."))
                    continue
                try:
                    suffix = Path(upload.name).suffix.lower()
                    if suffix not in {".txt", ".log", ".csv", ".json"}:
                        failures.append((upload.name, "Unsupported file extension."))
                        continue
                    # Preserve the original filename for provenance in the import pipeline.
                    with tempfile.TemporaryDirectory(prefix="threatgraph_") as temp_dir:
                        local_path = Path(temp_dir) / Path(upload.name).name
                        local_path.write_bytes(raw)
                        result = import_evidence(
                            db,
                            sample_id=sample_id,
                            file_path=local_path,
                            description=description or None,
                        )
                    results.append(result)
                except Exception as exc:
                    failures.append((upload.name, f"{type(exc).__name__}: {exc}"))

            if results:
                st.success(f"Processed {len(results)} file(s) for sample **{sample_id}**.")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Source file": r.source_file,
                                "Sample": r.sample_id,
                                "SHA-256": r.file_sha256,
                                "Duplicate skipped": r.skipped_duplicate,
                                "Records processed": r.records_processed,
                                "IOC occurrences added": r.occurrences_added,
                            }
                            for r in results
                        ]
                    ),
                    use_container_width=True,
                    hide_index=True,
                )
                st.caption(f"Total uploaded data: {total_bytes / 1024:.1f} KiB.")
            if failures:
                st.warning("Some files could not be imported.")
                for filename, reason in failures:
                    st.write(f"- **{filename}** — {reason}")
            if results:
                st.button("Refresh metrics", on_click=refresh_data)


elif page == "IOC Explorer":
    page_header(
        "INVESTIGATION / INDICATORS",
        "IOC explorer",
        "Search canonical indicators and inspect how often—and in which samples—they were observed.",
    )
    all_types = query_rows("SELECT DISTINCT ioc_type FROM indicators ORDER BY ioc_type")
    type_options = ["All types"] + [row["ioc_type"] for row in all_types]
    f1, f2 = st.columns([1, 1])
    with f1:
        selected_type = st.selectbox("IOC type", type_options)
    with f2:
        search_text = st.text_input("Search value", placeholder="Search IP, domain, URL, hash, or path")
    sql = """
        SELECT i.ioc_type AS "IOC type",
               i.canonical_value AS "Canonical value",
               COUNT(e.occurrence_id) AS "Occurrences",
               COUNT(DISTINCT e.sample_id) AS "Samples",
               GROUP_CONCAT(DISTINCT e.sample_id) AS "Observed in samples"
        FROM indicators i
        LEFT JOIN evidence_occurrences e ON e.indicator_id = i.indicator_id
    """
    conditions = []
    params: list[str] = []
    if selected_type != "All types":
        conditions.append("i.ioc_type = ?")
        params.append(selected_type)
    if search_text.strip():
        conditions.append("LOWER(i.canonical_value) LIKE LOWER(?)")
        params.append(f"%{search_text.strip()}%")
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += """
        GROUP BY i.indicator_id
        ORDER BY COUNT(DISTINCT e.sample_id) DESC,
                 COUNT(e.occurrence_id) DESC, i.canonical_value
    """
    ioc_df = query_df(sql, tuple(params))
    st.caption(f"{len(ioc_df):,} indicator(s) match the current filters.")
    st.dataframe(ioc_df, use_container_width=True, hide_index=True, height=460)
    if not ioc_df.empty:
        selected_value = st.selectbox("Inspect indicator", ioc_df["Canonical value"].tolist())
        detail_df = query_df(
            """
            SELECT e.sample_id AS "Sample",
                   e.source_file AS "Source file",
                   e.file_type AS "Format",
                   e.location AS "Source location",
                   e.original_text AS "Original text",
                   e.extraction_method AS "Extraction method",
                   e.imported_at AS "Imported at"
            FROM evidence_occurrences e
            JOIN indicators i ON i.indicator_id = e.indicator_id
            WHERE i.canonical_value = ?
            ORDER BY e.sample_id, e.source_file, e.occurrence_id
            """,
            (selected_value,),
        )
        st.subheader("Indicator provenance")
        st.dataframe(detail_df, use_container_width=True, hide_index=True)


elif page == "Evidence Details":
    page_header(
        "INVESTIGATION / EVIDENCE",
        "Evidence details",
        "Trace extracted indicators back to the original file, sample, format, and source location.",
    )
    sample_rows = query_rows("SELECT sample_id, description, created_at FROM samples ORDER BY sample_id")
    if not sample_rows:
        st.info("No samples yet. Import evidence to populate this view.")
    else:
        sample_ids = [row["sample_id"] for row in sample_rows]
        selected_sample = st.selectbox("Sample / case", sample_ids)
        sample_meta = next(row for row in sample_rows if row["sample_id"] == selected_sample)
        if sample_meta.get("description"):
            st.write(sample_meta["description"])
        evidence_df = query_df(
            """
            SELECT i.ioc_type AS "IOC type",
                   i.canonical_value AS "Canonical value",
                   e.source_file AS "Source file",
                   e.file_type AS "Format",
                   e.location AS "Source location",
                   e.original_text AS "Original text",
                   e.extraction_method AS "Extraction method",
                   e.source_timestamp AS "Source timestamp",
                   e.imported_at AS "Imported at"
            FROM evidence_occurrences e
            JOIN indicators i ON i.indicator_id = e.indicator_id
            WHERE e.sample_id = ?
            ORDER BY e.source_file, e.occurrence_id
            """,
            (selected_sample,),
        )
        c1, c2 = st.columns(2)
        c1.metric("IOC occurrences", len(evidence_df))
        c2.metric("Unique indicators", evidence_df["Canonical value"].nunique() if not evidence_df.empty else 0)
        st.dataframe(evidence_df, use_container_width=True, hide_index=True, height=500)
        if not evidence_df.empty:
            st.download_button(
                "Download this sample's evidence as CSV",
                evidence_df.to_csv(index=False).encode("utf-8"),
                file_name=f"{selected_sample}_evidence.csv",
                mime="text/csv",
            )


elif page == "Correlation Graph":
    page_header(
        "INVESTIGATION / CORRELATION",
        "Cross-sample correlation",
        "Find indicators shared across samples and inspect explainable relationships between cases.",
    )
    min_samples = st.slider("Minimum distinct samples sharing an indicator", 2, 10, 2)
    shared = find_shared_indicators(db, min_samples=min_samples)
    pairs = rank_related_samples(db, min_shared=1)

    a, b = st.columns(2)
    a.metric("Shared indicators", len(shared))
    b.metric("Related sample pairs", len(pairs))

    st.subheader("Shared indicators")
    if shared:
        shared_df = pd.DataFrame(
            [
                {
                    "IOC type": item["ioc_type"],
                    "Canonical value": item["canonical_value"],
                    "Sample count": item["sample_count"],
                    "Samples": ", ".join(item["sample_ids"]),
                    "Occurrences by sample": json.dumps(item["occurrence_counts"], sort_keys=True),
                }
                for item in shared
            ]
        )
        st.dataframe(shared_df, use_container_width=True, hide_index=True)
    else:
        st.info("No indicators currently meet this sample threshold.")

    st.subheader("Related sample pairs")
    if pairs:
        pairs_df = pd.DataFrame(
            [
                {
                    "Sample A": item["sample_a"],
                    "Sample B": item["sample_b"],
                    "Shared indicators": item["shared_indicator_count"],
                    "Shared IOC values": ", ".join(
                        f'{ioc["ioc_type"]}: {ioc["canonical_value"]}'
                        for ioc in item["shared_indicators"]
                    ),
                }
                for item in pairs
            ]
        )
        st.dataframe(pairs_df, use_container_width=True, hide_index=True)
    else:
        st.info("No sample pairs share an indicator yet. Import at least two samples with overlapping IOCs.")

    st.subheader("Relationship graph")
    if pairs:
        if len(pairs) > 1:
            max_pairs = st.slider(
                "Maximum sample-pair links to draw",
                min_value=1,
                max_value=min(50, len(pairs)),
                value=min(15, len(pairs)),
            )
        else:
            max_pairs = 1

        graph_pairs = pairs[:max_pairs]
        dot_lines = [
            "graph ThreatGraph {",
            '  graph [bgcolor="#0b1020", pad="0.25", overlap=false, splines=true];',
            '  node [style="filled", fontname="Arial", fontsize=10, color="#38506f", fontcolor="#f1f5f9"];',
            '  edge [color="#64748b", fontname="Arial", fontsize=9, fontcolor="#cbd5e1"];',
        ]
        nodes = set()
        for item in graph_pairs:
            nodes.add(item["sample_a"])
            nodes.add(item["sample_b"])

        for node in sorted(nodes):
            dot_lines.append(
                f'  "{safe_label(node, 80)}" [shape=box, fillcolor="#172b46", margin="0.18,0.12"];'
            )

        for item in graph_pairs:
            a_id = safe_label(item["sample_a"], 80)
            b_id = safe_label(item["sample_b"], 80)
            count = item["shared_indicator_count"]
            dot_lines.append(
                f'  "{a_id}" -- "{b_id}" [label="{count} shared IOC(s)", '
                f'penwidth="{min(5, 1 + count * 0.5):.1f}"];'
            )

        dot_lines.append("}")
        st.graphviz_chart("\\n".join(dot_lines), use_container_width=True)
    else:
        st.caption("A graph will appear when two or more samples share canonical indicators.")

    st.caption(
        "A shared IOC is a lead for analyst review, not proof of common attribution or maliciousness."
    )


elif page == "Investigation Graph (3D)":
    page_header(
        "INVESTIGATION / 3D RELATIONSHIPS",
        "ThreatGraph Investigation Graph",
        "Explore explainable sample-to-indicator relationships in an interactive 3D network.",
    )
    st.info(
        "An edge means an indicator was observed in a sample. It does not prove "
        "communication, maliciousness, common attribution, or that two incidents "
        "belong to the same campaign."
    )

    sample_options = query_rows(
        "SELECT sample_id FROM samples ORDER BY sample_id"
    )
    sample_labels = ["All samples"] + [row["sample_id"] for row in sample_options]

    f1, f2, f3 = st.columns([1.1, 1.4, 1])
    with f1:
        graph_sample = st.selectbox("Investigation scope", sample_labels)
    with f2:
        graph_types_all = query_rows(
            "SELECT DISTINCT ioc_type FROM indicators ORDER BY ioc_type"
        )
        graph_type_options = [row["ioc_type"] for row in graph_types_all]
        selected_graph_types = st.multiselect(
            "Indicator types",
            graph_type_options,
            default=graph_type_options,
            help="Clear this filter to show no indicator types.",
        )
    with f3:
        graph_limit = st.selectbox(
            "Maximum indicator nodes",
            [50, 100, 150, 250, 400, 500],
            index=2,
            help="The most frequently observed indicators are included first.",
        )

    if not selected_graph_types:
        st.warning("Select at least one indicator type to build the graph.")
    else:
        where_parts = []
        params = []
        placeholders = ",".join("?" for _ in selected_graph_types)
        where_parts.append(f"i.ioc_type IN ({placeholders})")
        params.extend(selected_graph_types)
        if graph_sample != "All samples":
            where_parts.append("e.sample_id = ?")
            params.append(graph_sample)

        graph_rows = query_rows(
            f"""
            SELECT
                e.sample_id,
                i.ioc_type,
                i.canonical_value,
                COUNT(*) AS occurrence_count,
                GROUP_CONCAT(DISTINCT e.source_file) AS source_files
            FROM evidence_occurrences e
            JOIN indicators i ON i.indicator_id = e.indicator_id
            WHERE {" AND ".join(where_parts)}
            GROUP BY e.sample_id, i.indicator_id, i.ioc_type, i.canonical_value
            ORDER BY COUNT(*) DESC, i.ioc_type, i.canonical_value
            """,
            tuple(params),
        )

        # Rank indicators across the selected scope, then keep a bounded
        # number to avoid overwhelming the browser with a dense graph.
        indicator_totals = {}
        for row in graph_rows:
            key = (row["ioc_type"], row["canonical_value"])
            indicator_totals[key] = indicator_totals.get(key, 0) + row["occurrence_count"]

        ranked_indicators = sorted(
            indicator_totals,
            key=lambda key: (-indicator_totals[key], key[0], key[1]),
        )[:graph_limit]
        ranked_set = set(ranked_indicators)
        visible_rows = [
            row for row in graph_rows
            if (row["ioc_type"], row["canonical_value"]) in ranked_set
        ]

        sample_ids = sorted({row["sample_id"] for row in visible_rows})
        nodes = []
        links = []
        indicator_node_ids = set()
        evidence_by_indicator = {}
        samples_by_indicator = {}
        indicator_meta = {}

        for sample_id in sample_ids:
            node_id = "sample::" + sample_id
            nodes.append({
                "id": node_id,
                "label": sample_id,
                "kind": "sample",
                "color": "#60a5fa",
                "val": 9,
                "details": {
                    "Sample ID": sample_id,
                    "Relationship": "Investigation sample",
                },
            })

        for row in visible_rows:
            ioc_type = row["ioc_type"]
            canonical = row["canonical_value"]
            indicator_id = f"ioc::{ioc_type}::{canonical}"
            indicator_node_ids.add(indicator_id)
            indicator_meta[indicator_id] = (ioc_type, canonical)
            samples_by_indicator.setdefault(indicator_id, set()).add(row["sample_id"])
            evidence_by_indicator.setdefault(indicator_id, []).append({
                "sample": row["sample_id"],
                "source_files": row["source_files"] or "",
                "occurrences": row["occurrence_count"],
            })

        color_by_type = {
            "ipv4": "#f87171",
            "domain": "#a78bfa",
            "url": "#f472b6",
            "filepath": "#fb923c",
            "md5": "#4ade80",
            "sha1": "#4ade80",
            "sha256": "#4ade80",
            "sha512": "#4ade80",
        }

        for indicator_id in sorted(indicator_node_ids):
            ioc_type, canonical = indicator_meta[indicator_id]
            total_occurrences = indicator_totals[(ioc_type, canonical)]
            related_samples = sorted(samples_by_indicator[indicator_id])
            nodes.append({
                "id": indicator_id,
                "label": canonical,
                "kind": "indicator",
                "ioc_type": ioc_type,
                "color": color_by_type.get(ioc_type.lower(), "#cbd5e1"),
                "val": min(8, 3 + total_occurrences),
                "details": {
                    "IOC type": ioc_type,
                    "Canonical value": canonical,
                    "Total occurrences": total_occurrences,
                    "Observed in samples": ", ".join(related_samples),
                    "Evidence references": evidence_by_indicator[indicator_id][:8],
                },
            })

        for row in visible_rows:
            links.append({
                "source": "sample::" + row["sample_id"],
                "target": f'ioc::{row["ioc_type"]}::{row["canonical_value"]}',
                "value": row["occurrence_count"],
                "label": f'{row["occurrence_count"]} occurrence(s)',
            })

        indicator_count_graph = len(indicator_node_ids)
        st.caption(
            f"Showing {len(sample_ids)} sample(s), {indicator_count_graph} indicator(s), "
            f"and {len(links)} sample-to-indicator relationship(s). "
            f"Indicator limit: {graph_limit}."
        )

        if not nodes:
            st.info("No evidence relationships match these filters. Import evidence or change the filters.")
        else:
            graph_payload = {"nodes": nodes, "links": links}
            graph_json = json.dumps(graph_payload, ensure_ascii=True)
            # Prevent untrusted evidence strings from terminating the script
            # element or being interpreted as HTML while embedded as JSON.
            graph_json = (
                graph_json.replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace("\\u2028", "\\u2028")
                .replace("\\u2029", "\\u2029")
            )

            graph_html = f"""
            <!doctype html>
            <html>
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <style>
                html, body {{ margin:0; padding:0; background:#0b1020; color:#e7ecf5;
                               font-family:Arial,sans-serif; overflow:hidden; }}
                #graph {{ width:100%; height:590px; }}
                #hint {{ position:absolute; top:12px; left:14px; z-index:2; color:#a8b5cc;
                         background:rgba(17,26,45,.88); border:1px solid #293650;
                         border-radius:8px; padding:8px 11px; font-size:12px; }}
                #details {{ position:absolute; right:12px; top:12px; z-index:2; width:min(300px,38%);
                            max-height:48%; overflow:auto; background:rgba(17,26,45,.96);
                            border:1px solid #38506f; border-radius:10px; padding:12px;
                            box-sizing:border-box; font-size:12px; }}
                #details h3 {{ margin:0 0 8px; color:#7dd3fc; font-size:14px; }}
                .detail-row {{ margin:7px 0; overflow-wrap:anywhere; color:#dbe5f4; }}
                .detail-key {{ color:#94a3b8; display:block; margin-bottom:2px; }}
                @media(max-width:650px) {{ #details {{ width:46%; max-height:42%; }} #hint {{ max-width:40%; }} }}
              </style>
            </head>
            <body>
              <div id="hint">Drag to rotate · Scroll to zoom · Click a node for evidence context</div>
              <div id="details">
                <h3>Node inspector</h3>
                <div class="detail-row">Select a sample or indicator node to inspect its relationships.</div>
              </div>
              <div id="graph"></div>
              <script src="https://unpkg.com/3d-force-graph@1.73.3/dist/3d-force-graph.min.js"></script>
              <script>
                const data = {graph_json};
                const details = document.getElementById('details');
                function addDetail(key, value) {{
                  const row = document.createElement('div');
                  row.className = 'detail-row';
                  const label = document.createElement('span');
                  label.className = 'detail-key';
                  label.textContent = key;
                  const content = document.createElement('span');
                  if (Array.isArray(value)) {{
                    content.textContent = value.map(v => typeof v === 'object'
                      ? Object.entries(v).map(([k, val]) => k + ': ' + val).join(' · ')
                      : String(v)).join(' | ');
                  }} else if (value && typeof value === 'object') {{
                    content.textContent = JSON.stringify(value);
                  }} else {{
                    content.textContent = String(value);
                  }}
                  row.appendChild(label);
                  row.appendChild(content);
                  details.appendChild(row);
                }}
                if (typeof ForceGraph3D !== 'function') {{
                  document.getElementById('graph').textContent =
                    'The 3D graph library could not be loaded. Check your internet connection or CDN access.';
                }} else {{
                  const Graph = ForceGraph3D()(document.getElementById('graph'))
                    .backgroundColor('#0b1020')
                    .graphData(data)
                    .nodeLabel(node => String(node.label || ''))
                    .nodeColor(node => node.color || '#cbd5e1')
                    .nodeVal(node => node.val || 4)
                    .linkColor(() => 'rgba(148,163,184,0.38)')
                    .linkOpacity(0.65)
                    .linkWidth(link => Math.min(3, 0.5 + Math.log2((link.value || 1) + 1)))
                    .onNodeClick(node => {{
                      details.replaceChildren();
                      const heading = document.createElement('h3');
                      heading.textContent = node.kind === 'sample' ? 'Investigation sample' : 'Indicator details';
                      details.appendChild(heading);
                      Object.entries(node.details || {{}}).forEach(([key, value]) => addDetail(key, value));
                      Graph.cameraPosition(
                        {{ x: node.x + 35, y: node.y + 25, z: node.z + 85 }},
                        node,
                        900
                      );
                    }});
                  Graph.d3Force('charge').strength(-100);
                  Graph.d3Force('link').distance(42);
                }}
              </script>
            </body>
            </html>
            """
            components.html(graph_html, height=610, scrolling=False)

            st.caption(
                "Graph semantics: each link records that an indicator was observed in a sample. "
                "It is not proof of maliciousness, network communication, or shared attribution. "
                "The graph uses a pinned browser-side 3D visualization library loaded from a CDN."
            )
elif page == "Exports":
    page_header(
        "INVESTIGATION / EXPORT",
        "Export investigation data",
        "Download normalized indicators and evidence provenance for analysis, reporting, or downstream tooling.",
    )
    export_kind = st.radio("Dataset", ["Unique indicators", "Evidence occurrences", "Sample summary"], horizontal=True)
    if export_kind == "Unique indicators":
        export_df = query_df(
            """
            SELECT i.ioc_type AS ioc_type,
                   i.canonical_value AS canonical_value,
                   COUNT(e.occurrence_id) AS occurrence_count,
                   COUNT(DISTINCT e.sample_id) AS sample_count,
                   GROUP_CONCAT(DISTINCT e.sample_id) AS sample_ids
            FROM indicators i
            LEFT JOIN evidence_occurrences e ON e.indicator_id = i.indicator_id
            GROUP BY i.indicator_id
            ORDER BY i.ioc_type, i.canonical_value
            """
        )
        base_name = "threatgraph_indicators"
    elif export_kind == "Evidence occurrences":
        export_df = query_df(
            """
            SELECT e.sample_id, i.ioc_type, i.canonical_value, e.source_file,
                   e.file_type, e.location, e.original_text,
                   e.extraction_method, e.source_timestamp, e.imported_at
            FROM evidence_occurrences e
            JOIN indicators i ON i.indicator_id = e.indicator_id
            ORDER BY e.sample_id, e.source_file, e.occurrence_id
            """
        )
        base_name = "threatgraph_evidence_occurrences"
    else:
        export_df = query_df(
            """
            SELECT s.sample_id, s.description, s.created_at,
                   COUNT(DISTINCT im.import_id) AS import_count,
                   COUNT(DISTINCT i.indicator_id) AS unique_indicator_count,
                   COUNT(e.occurrence_id) AS occurrence_count
            FROM samples s
            LEFT JOIN imports im ON im.sample_id = s.sample_id
            LEFT JOIN evidence_occurrences e ON e.sample_id = s.sample_id
            LEFT JOIN indicators i ON i.indicator_id = e.indicator_id
            GROUP BY s.sample_id
            ORDER BY s.created_at DESC
            """
        )
        base_name = "threatgraph_sample_summary"

    st.metric("Rows available", len(export_df))
    st.dataframe(export_df.head(1000), use_container_width=True, hide_index=True)
    csv_bytes = export_df.to_csv(index=False).encode("utf-8")
    json_bytes = export_df.to_json(orient="records", indent=2, force_ascii=False).encode("utf-8")
    x1, x2 = st.columns(2)
    x1.download_button(
        "Download CSV",
        data=csv_bytes,
        file_name=f"{base_name}.csv",
        mime="text/csv",
        use_container_width=True,
    )
    x2.download_button(
        "Download JSON",
        data=json_bytes,
        file_name=f"{base_name}.json",
        mime="application/json",
        use_container_width=True,
    )
    if len(export_df) > 1000:
        st.caption("The preview shows the first 1,000 rows; the downloads contain the complete selected dataset.")
    st.warning("These are CSV/JSON evidence exports, not STIX 2.1 bundles. STIX export can be added as a separate validated milestone.")
