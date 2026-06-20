"""
dashboard/app.py — EphemeraWatch Plotly Dash Dashboard

Four-panel risk dashboard for the Ephemeral Cloud Risk Detection Platform.
All pipeline data is loaded ONCE at startup; callbacks only handle user interaction.

Panels
------
1. TTL Distribution          histogram  (top-left)
2. Creation Spike Timeline   line+burst (top-right)
3. Top Risky Resources /     bar tabs   (bottom-left, 4 cols)
   Identities
4. Incident Queue + Drill-Down  DataTable  (bottom-right, 8 cols)
"""
from __future__ import annotations

import os
import sys

# Ensure project root is on path regardless of working directory
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from collections import defaultdict
from datetime import datetime

import dash
from dash import dcc, html, dash_table, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

# ── Design tokens ───────────────────────────────────────────────────────────────
_BG     = "#0d1117"
_CARD   = "#161b22"
_CARD2  = "#1c2128"
_TEXT   = "#e6edf3"
_MUTED  = "#8b949e"
_ACCENT = "#58a6ff"
_BORDER = "#30363d"

_SEV_COLOR = {
    "critical": "#f85149",
    "high":     "#e3b341",
    "medium":   "#d29922",
    "low":      "#3fb950",
}

_LABEL_COLOR = {
    "Ephemeral":        "#f85149",
    "Likely Ephemeral": "#e3b341",
    "Persistent":       "#3fb950",
}

_MITRE_DESC = {
    "T1190": "Exploit Public-Facing Application",
    "T1610": "Deploy Container",
    "T1078": "Valid Accounts",
    "T1496": "Resource Hijacking",
    "T1036": "Masquerading",
}

_GUARDRAILS = {
    "resource_hijacking": [
        "Enable AWS Cost Anomaly Detection",
        "Require MFA for AssumeRole",
        "Tag enforcement policy via AWS Config",
    ],
    "public_exposure": [
        "Block NodePort services in production via NetworkPolicy",
        "Enable VPC Flow Logs",
        "Implement pod security standards",
    ],
    "identity_abuse": [
        "Enforce session duration limits on IAM roles",
        "Enable CloudTrail for all AssumeRole events",
        "Implement just-in-time access",
    ],
}

_GRAPH_DEFAULTS = dict(
    plot_bgcolor=_CARD,
    paper_bgcolor=_CARD,
    font_color=_TEXT,
)

_AXIS_DEFAULTS = dict(gridcolor=_BORDER, color=_TEXT, linecolor=_BORDER)


# ── Pipeline loader ─────────────────────────────────────────────────────────────

def _load_data(data_dir: str):
    """Run Feature 1 + Feature 2 pipelines and return all objects."""
    from pipeline.ingestion import IngestionPipeline
    from pipeline.enrichment import enrich
    from classifier.ephemeral_classifier import EphemeralClassifier, ClassifierConfig
    from detection.signal_scorer import score_all
    from detection.burst_detector import detect_bursts
    from detection.correlator import correlate
    from detection.incident_queue import build_queue

    pipeline = IngestionPipeline(data_dir=data_dir)
    pipeline.ingest()
    enrich(pipeline)
    clf     = EphemeralClassifier(ClassifierConfig())
    results = clf.classify_all(pipeline)

    signals   = score_all(pipeline, results)
    bursts    = detect_bursts(pipeline)
    incidents = correlate(signals, bursts, pipeline)
    queue     = build_queue(incidents)

    return pipeline, results, signals, bursts, incidents, queue


# ── Figure builders ─────────────────────────────────────────────────────────────

def _ttl_histogram(pipeline) -> go.Figure:
    """Panel 1: stacked TTL histogram coloured by ephemeral/persistent."""
    eph, per = [], []
    for asset in pipeline.asset_registry.values():
        ttl = asset.ttl_seconds
        if ttl is None:
            continue
        ttl_min = min(ttl / 60.0, 120.0)
        (eph if ttl < 3600 else per).append(ttl_min)

    fig = go.Figure()
    bin_spec = dict(start=0, end=120, size=5)
    fig.add_trace(go.Histogram(
        x=eph, name="Ephemeral",
        xbins=bin_spec, marker_color="#f85149", opacity=0.85,
    ))
    fig.add_trace(go.Histogram(
        x=per, name="Persistent",
        xbins=bin_spec, marker_color="#3fb950", opacity=0.85,
    ))
    fig.add_vline(
        x=60, line_width=2, line_dash="dash", line_color=_ACCENT,
        annotation_text="Ephemeral Threshold (60 min)",
        annotation_position="top right",
        annotation_font_color=_ACCENT,
        annotation_font_size=11,
    )
    fig.update_layout(
        **_GRAPH_DEFAULTS,
        title=dict(text="Ephemeral Resource TTL Distribution", font_color=_TEXT),
        xaxis=dict(title="TTL (minutes)", range=[0, 122], **_AXIS_DEFAULTS),
        yaxis=dict(title="Asset count", **_AXIS_DEFAULTS),
        barmode="stack",
        legend=dict(font_color=_TEXT, bgcolor=_CARD, bordercolor=_BORDER),
        margin=dict(l=50, r=20, t=50, b=50),
        height=350,
    )
    return fig


def _spike_timeline(pipeline, bursts) -> go.Figure:
    """Panel 2: 10-minute event-rate line + burst markers."""
    bucket: dict = defaultdict(int)
    for ev in pipeline.event_stream:
        ts = ev.timestamp
        key = ts.replace(minute=(ts.minute // 10) * 10, second=0, microsecond=0)
        bucket[key] += 1

    if not bucket:
        fig = go.Figure()
        fig.update_layout(**_GRAPH_DEFAULTS,
                          title=dict(text="Resource Creation Spike Timeline",
                                     font_color=_TEXT), height=350)
        return fig

    xs = sorted(bucket)
    ys = [bucket[b] for b in xs]

    # One marker per unique 10-min bucket that contains at least one burst
    burst_set: set = set()
    for b in bursts:
        bt = b.timestamp
        burst_set.add(bt.replace(minute=(bt.minute // 10) * 10,
                                  second=0, microsecond=0))
    bx = [t for t in xs if t in burst_set]
    by = [bucket[t] for t in bx]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=xs, y=ys, mode="lines", name="Event Rate",
        line=dict(color=_ACCENT, width=2),
        fill="tozeroy", fillcolor="rgba(88,166,255,0.08)",
    ))
    if bx:
        fig.add_trace(go.Scatter(
            x=bx, y=by, mode="markers", name="Burst Detected",
            marker=dict(color="#f85149", size=7, symbol="circle",
                        line=dict(color="#ff7070", width=1)),
        ))
    fig.update_layout(
        **_GRAPH_DEFAULTS,
        title=dict(text="Resource Creation Spike Timeline", font_color=_TEXT),
        xaxis=dict(title="Timestamp", **_AXIS_DEFAULTS),
        yaxis=dict(title="Events / 10-min window", **_AXIS_DEFAULTS),
        legend=dict(font_color=_TEXT, bgcolor=_CARD, bordercolor=_BORDER),
        margin=dict(l=50, r=20, t=50, b=50),
        height=350,
    )
    return fig


def _bar_chart(items: list, title: str) -> go.Figure:
    """Shared horizontal bar builder for Panel 3 (assets and identities)."""
    if not items:
        fig = go.Figure()
        fig.update_layout(**_GRAPH_DEFAULTS,
                          title=dict(text=title, font_color=_TEXT), height=400)
        return fig

    # Display bottom-to-top so highest score is at top
    items_rev  = list(reversed(items))
    ids        = [x[0][:32] for x in items_rev]
    scores     = [x[1]      for x in items_rev]
    colors     = [_LABEL_COLOR.get(x[2], _ACCENT) for x in items_rev]
    max_score  = max(scores) if scores else 1.0

    fig = go.Figure(go.Bar(
        x=scores, y=ids, orientation="h",
        marker_color=colors,
        text=[f"{s:.3f}" for s in scores],
        textposition="outside",
        textfont=dict(color=_TEXT, size=10),
    ))
    fig.update_layout(
        **_GRAPH_DEFAULTS,
        title=dict(text=title, font_color=_TEXT),
        xaxis=dict(title="Risk Score", range=[0, max_score * 1.18],
                   **_AXIS_DEFAULTS),
        yaxis=dict(color=_TEXT, tickfont=dict(size=9)),
        margin=dict(l=10, r=70, t=50, b=40),
        height=400,
    )
    return fig


def _top_assets_fig(results) -> go.Figure:
    items = sorted(
        [(r.entity_id, r.score, r.label)
         for r in results.values() if r.entity_type == "asset"],
        key=lambda x: x[1], reverse=True,
    )[:10]
    return _bar_chart(items, "Top Risky Resources")


def _top_identities_fig(results) -> go.Figure:
    items = sorted(
        [(r.entity_id, r.score, r.label)
         for r in results.values() if r.entity_type == "identity"],
        key=lambda x: x[1], reverse=True,
    )[:10]
    return _bar_chart(items, "Top Risky Identities")


# ── Incident table ──────────────────────────────────────────────────────────────

def _window_label(t0: datetime, t1: datetime) -> str:
    if t0.date() == t1.date():
        return f"{t0.strftime('%H:%M')}-{t1.strftime('%H:%M')}"
    return f"{t0.strftime('%m/%d %H:%M')} to {t1.strftime('%m/%d %H:%M')}"


def _incident_table_data(queue) -> tuple[list[dict], list[dict]]:
    rows: list[dict] = []
    for rank, inc in enumerate(queue.incidents, 1):
        t0, t1 = inc.time_window
        principals_str = ", ".join(inc.principals[:2])
        if len(inc.principals) > 2:
            principals_str += f" +{len(inc.principals)-2}"
        rows.append({
            "Rank":       rank,
            "ID":         inc.incident_id,
            "Severity":   inc.severity.upper(),
            "Type":       inc.incident_type,
            "Score":      round(inc.incident_score, 3),
            "Signals":    len(inc.signals),
            "Window":     _window_label(t0, t1),
            "Principals": principals_str,
            "MITRE":      ", ".join(inc.mitre_techniques),
        })

    columns = [
        {"name": "#",           "id": "Rank",       "type": "numeric"},
        {"name": "Incident ID", "id": "ID"},
        {"name": "Severity",    "id": "Severity"},
        {"name": "Type",        "id": "Type"},
        {"name": "Score",       "id": "Score",      "type": "numeric"},
        {"name": "Signals",     "id": "Signals",    "type": "numeric"},
        {"name": "Window",      "id": "Window"},
        {"name": "Principals",  "id": "Principals"},
        {"name": "MITRE",       "id": "MITRE"},
    ]
    return rows, columns


# ── Drill-down content ──────────────────────────────────────────────────────────

def _drilldown(inc, top_evidence_fn) -> list:
    """Build the detail card shown below the table on row click."""
    sev_color = _SEV_COLOR.get(inc.severity, _ACCENT)

    t0, t1 = inc.time_window
    if t0.date() == t1.date():
        window_str = f"{t0.strftime('%Y-%m-%d')}  {t0.strftime('%H:%M')} — {t1.strftime('%H:%M')}"
    else:
        window_str = (
            f"{t0.strftime('%Y-%m-%d %H:%M')} — {t1.strftime('%Y-%m-%d %H:%M')}"
        )

    mitre_bullets = [
        html.Li(
            [html.Strong(t, style={"color": "#e3b341"}),
             f"  —  {_MITRE_DESC.get(t, 'Threat technique')}"],
            style={"color": _TEXT, "fontSize": "13px", "marginBottom": "4px"},
        )
        for t in inc.mitre_techniques
    ]

    evidence_bullets = [
        html.Li(snip, style={"color": "#adbac7", "fontSize": "12px", "marginBottom": "4px"})
        for snip in top_evidence_fn(inc, n=5)
    ]

    # Guardrails: match incident_type or fall back to all three buckets for "mixed"
    gr_order = ["resource_hijacking", "public_exposure", "identity_abuse"]
    gr_keys  = [inc.incident_type] if inc.incident_type in _GUARDRAILS else gr_order
    seen: set = set()
    gr_bullets = []
    for key in gr_order:
        if key in gr_keys:
            for gr in _GUARDRAILS[key]:
                if gr not in seen:
                    seen.add(gr)
                    gr_bullets.append(
                        html.Li(gr, style={"color": "#3fb950", "fontSize": "13px",
                                           "marginBottom": "4px"}),
                    )

    return [html.Div([
        # ── Header row ─────────────────────────────────────────────────────────
        html.Div([
            html.Span(inc.incident_id, style={
                "color": _ACCENT, "fontWeight": "bold",
                "fontSize": "16px", "marginRight": "14px",
            }),
            html.Span(inc.severity.upper(), style={
                "backgroundColor": sev_color, "color": "#fff",
                "padding": "3px 12px", "borderRadius": "4px",
                "fontSize": "12px", "fontWeight": "bold",
            }),
            html.Span(f"  {inc.incident_type}", style={
                "color": _MUTED, "fontSize": "13px", "marginLeft": "10px",
            }),
        ], style={"marginBottom": "14px"}),

        # ── Details + MITRE + Guardrails ───────────────────────────────────────
        dbc.Row([
            dbc.Col([
                _dd_row("Window",     window_str),
                _dd_row("Score",      f"{inc.incident_score:.3f}"),
                _dd_row("Principals", ", ".join(inc.principals[:4]) or "N/A"),
                _dd_row("Namespaces", ", ".join(inc.namespaces[:4]) or "N/A"),
                _dd_row("Signals",    str(len(inc.signals))),
            ], md=4),

            dbc.Col([
                html.P("MITRE ATT&CK", style={
                    "color": _MUTED, "fontWeight": "bold",
                    "fontSize": "12px", "marginBottom": "6px",
                    "textTransform": "uppercase", "letterSpacing": "1px",
                }),
                html.Ul(mitre_bullets, style={"paddingLeft": "16px"}),
            ], md=4),

            dbc.Col([
                html.P("Recommended Guardrails", style={
                    "color": "#3fb950", "fontWeight": "bold",
                    "fontSize": "12px", "marginBottom": "6px",
                    "textTransform": "uppercase", "letterSpacing": "1px",
                }),
                html.Ul(gr_bullets, style={"paddingLeft": "16px"}),
            ], md=4),
        ]),

        html.Hr(style={"borderColor": _BORDER, "margin": "10px 0"}),

        html.P("Evidence — Top Signals", style={
            "color": _MUTED, "fontWeight": "bold",
            "fontSize": "12px", "marginBottom": "6px",
            "textTransform": "uppercase", "letterSpacing": "1px",
        }),
        html.Ul(evidence_bullets, style={"paddingLeft": "16px"}),

    ], style={
        "backgroundColor": _CARD2,
        "border": f"2px solid {sev_color}",
        "borderRadius": "8px",
        "padding": "18px 22px",
        "marginTop": "12px",
    })]


def _dd_row(label: str, value: str) -> html.P:
    return html.P(
        [html.Span(f"{label}: ", style={"color": _MUTED, "fontWeight": "bold",
                                         "fontSize": "12px"}),
         html.Span(value, style={"color": _TEXT, "fontSize": "13px"})],
        style={"marginBottom": "6px"},
    )


# ── KPI card ────────────────────────────────────────────────────────────────────

def _kpi(label: str, value: str) -> dbc.Card:
    return dbc.Card(
        dbc.CardBody([
            html.P(label, style={
                "color": _MUTED, "fontSize": "11px",
                "textTransform": "uppercase", "letterSpacing": "1px",
                "marginBottom": "6px",
            }),
            html.H4(value, style={"color": _ACCENT, "fontWeight": "bold",
                                   "marginBottom": "0"}),
        ]),
        style={"backgroundColor": _CARD, "border": f"1px solid {_BORDER}",
               "borderRadius": "8px", "textAlign": "center"},
    )


# ── DataTable style helpers ─────────────────────────────────────────────────────

_TABLE_HEADER = {
    "backgroundColor": _CARD2, "color": _TEXT,
    "fontWeight": "bold", "border": f"1px solid {_BORDER}",
    "fontSize": "12px",
}
_TABLE_CELL = {
    "backgroundColor": _CARD, "color": _TEXT,
    "border": f"1px solid {_BORDER}",
    "fontSize": "11px", "padding": "6px 10px",
    "maxWidth": "165px", "overflow": "hidden",
    "textOverflow": "ellipsis", "whiteSpace": "nowrap",
}
_TABLE_CONDITIONAL = [
    {"if": {"filter_query": '{Severity} = "CRITICAL"', "column_id": "Severity"},
     "color": "#f85149", "fontWeight": "bold"},
    {"if": {"filter_query": '{Severity} = "HIGH"',     "column_id": "Severity"},
     "color": "#e3b341", "fontWeight": "bold"},
    {"if": {"filter_query": '{Severity} = "MEDIUM"',   "column_id": "Severity"},
     "color": "#d29922"},
    {"if": {"filter_query": '{Severity} = "LOW"',      "column_id": "Severity"},
     "color": "#3fb950"},
    {"if": {"state": "active"},
     "backgroundColor": _CARD2, "border": f"1px solid {_ACCENT}"},
]


# ── App factory ─────────────────────────────────────────────────────────────────

def create_app(data_dir: str = "data/") -> dash.Dash:
    """
    Build the Dash application.

    Runs Feature 1 + Feature 2 pipelines once at startup,
    pre-computes all figures, then registers callbacks.
    Returns the configured dash.Dash instance.
    """
    # ── Load data ───────────────────────────────────────────────────────────────
    print("  [F3] Loading pipeline data (Feature 1 + 2)...")
    pipeline, results, signals, bursts, incidents, queue = _load_data(data_dir)
    from detection.incident_queue import top_evidence
    print(f"  [F3] Ready: {len(pipeline.asset_registry)} assets | "
          f"{len(incidents)} incidents | {len(bursts)} burst events")

    # Lookup dict for O(1) drill-down by incident ID
    inc_lookup = {inc.incident_id: inc for inc in incidents}

    # ── Pre-build figures ───────────────────────────────────────────────────────
    fig_ttl        = _ttl_histogram(pipeline)
    fig_timeline   = _spike_timeline(pipeline, bursts)
    fig_assets     = _top_assets_fig(results)
    fig_identities = _top_identities_fig(results)
    table_rows, table_cols = _incident_table_data(queue)

    # ── KPI values ──────────────────────────────────────────────────────────────
    total_assets   = len(pipeline.asset_registry)
    total_entities = total_assets + len(pipeline.identity_registry)
    cov_pct        = round(100 * len(results) / max(total_entities, 1))
    alert_red      = f"{queue.alert_reduction_pct:.1f}%"
    crit_cnt       = queue.stats.get("by_severity", {}).get("critical", 0)

    # ── Dash app ────────────────────────────────────────────────────────────────
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        suppress_callback_exceptions=True,
        title="EphemeraWatch",
    )

    # ── Layout ──────────────────────────────────────────────────────────────────
    app.layout = html.Div(
        style={"backgroundColor": _BG, "minHeight": "100vh",
               "fontFamily": "'Segoe UI', 'Courier New', monospace"},
        children=[

            # ── Title bar ──────────────────────────────────────────────────────
            html.Div(
                style={"backgroundColor": _CARD,
                       "borderBottom": f"2px solid {_ACCENT}",
                       "padding": "16px 30px",
                       "display": "flex", "alignItems": "center",
                       "justifyContent": "space-between"},
                children=[
                    html.Div([
                        html.H2("EphemeraWatch", style={
                            "color": _ACCENT, "fontWeight": "bold",
                            "marginBottom": "2px", "letterSpacing": "3px",
                        }),
                        html.P(
                            "Ephemeral Cloud Risk Detection Platform  —  "
                            "Real-time asset discovery, risk scoring & incident correlation",
                            style={"color": _MUTED, "fontSize": "13px",
                                   "marginBottom": "0"},
                        ),
                    ]),
                    html.Span("LIVE", style={
                        "backgroundColor": "#3fb950", "color": "#fff",
                        "padding": "5px 12px", "borderRadius": "4px",
                        "fontSize": "11px", "fontWeight": "bold",
                        "letterSpacing": "2px",
                    }),
                ],
            ),

            # ── Main content ───────────────────────────────────────────────────
            html.Div(
                style={"padding": "20px 24px"},
                children=[

                    # KPI row
                    dbc.Row([
                        dbc.Col(_kpi("Assets Discovered",  f"{total_assets:,}"), md=3, className="mb-3"),
                        dbc.Col(_kpi("Ephemeral Coverage", f"{cov_pct}%"),        md=3, className="mb-3"),
                        dbc.Col(_kpi("Alert Reduction",    alert_red),            md=3, className="mb-3"),
                        dbc.Col(_kpi("Critical Incidents", str(crit_cnt)),        md=3, className="mb-3"),
                    ]),

                    # Row 1 — Panel 1 + Panel 2
                    dbc.Row([
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    dcc.Graph(id="panel-ttl", figure=fig_ttl,
                                              config={"displayModeBar": False})
                                ),
                                style={"backgroundColor": _CARD,
                                       "border": f"1px solid {_BORDER}",
                                       "borderRadius": "8px"},
                            ),
                            md=6, className="mb-3",
                        ),
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    dcc.Graph(id="panel-timeline", figure=fig_timeline,
                                              config={"displayModeBar": False})
                                ),
                                style={"backgroundColor": _CARD,
                                       "border": f"1px solid {_BORDER}",
                                       "borderRadius": "8px"},
                            ),
                            md=6, className="mb-3",
                        ),
                    ]),

                    # Row 2 — Panel 3 (4 cols) + Panel 4 (8 cols)
                    dbc.Row([

                        # Panel 3 — tabbed bar charts
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody(
                                    dbc.Tabs([
                                        dbc.Tab(
                                            dcc.Graph(figure=fig_assets,
                                                      config={"displayModeBar": False}),
                                            label="Resources",
                                            tab_style={"color": _MUTED},
                                            active_label_style={"color": _ACCENT,
                                                                "borderColor": _ACCENT},
                                        ),
                                        dbc.Tab(
                                            dcc.Graph(figure=fig_identities,
                                                      config={"displayModeBar": False}),
                                            label="Identities",
                                            tab_style={"color": _MUTED},
                                            active_label_style={"color": _ACCENT,
                                                                "borderColor": _ACCENT},
                                        ),
                                    ]),
                                ),
                                style={"backgroundColor": _CARD,
                                       "border": f"1px solid {_BORDER}",
                                       "borderRadius": "8px"},
                            ),
                            md=4, className="mb-3",
                        ),

                        # Panel 4 — incident queue
                        dbc.Col(
                            dbc.Card(
                                dbc.CardBody([
                                    html.H6(
                                        "Incident Queue — click any row for details",
                                        style={"color": _TEXT, "marginBottom": "12px",
                                               "letterSpacing": "1px", "fontSize": "13px"},
                                    ),
                                    dash_table.DataTable(
                                        id="incident-table",
                                        columns=table_cols,
                                        data=table_rows,
                                        page_size=10,
                                        sort_action="native",
                                        filter_action="native",
                                        style_table={"overflowX": "auto"},
                                        style_header=_TABLE_HEADER,
                                        style_cell=_TABLE_CELL,
                                        style_data_conditional=_TABLE_CONDITIONAL,
                                        style_filter={
                                            "backgroundColor": _CARD2,
                                            "color": _TEXT,
                                            "border": f"1px solid {_BORDER}",
                                        },
                                    ),
                                    html.Div(id="incident-drilldown"),
                                ]),
                                style={"backgroundColor": _CARD,
                                       "border": f"1px solid {_BORDER}",
                                       "borderRadius": "8px"},
                            ),
                            md=8, className="mb-3",
                        ),
                    ]),

                    # Footer
                    html.Div(
                        f"Societe Generale Cybersecurity Hackathon  |  "
                        f"{len(signals)} risk signals  |  "
                        f"{len(bursts)} burst events  |  "
                        f"{len(incidents)} incidents",
                        style={"color": "#484f58", "fontSize": "11px",
                               "textAlign": "center", "padding": "12px 0",
                               "borderTop": f"1px solid {_BORDER}"},
                    ),

                ],
            ),
        ],
    )

    # ── Drill-down callback ─────────────────────────────────────────────────────
    @app.callback(
        Output("incident-drilldown", "children"),
        Input("incident-table", "active_cell"),
        State("incident-table", "derived_virtual_data"),
        prevent_initial_call=True,
    )
    def show_drilldown(active_cell, virtual_data):
        """Show incident details below the table when the user clicks any cell."""
        if not active_cell or not virtual_data:
            return []
        row_idx = active_cell.get("row", 0)
        if row_idx >= len(virtual_data):
            return []
        inc_id = virtual_data[row_idx].get("ID", "")
        inc = inc_lookup.get(inc_id)
        if inc is None:
            return []
        return _drilldown(inc, top_evidence)

    return app
