"""
dashboard/app.py — EphemeraWatch Plotly Dash Dashboard
 
Near real-time ephemeral risk detection dashboard with LLM narratives.
 
Run order:
    1. python feature4_main.py --data-dir data/   (generates narratives)
    2. python feature3_main.py                    (launches dashboard)
"""
from __future__ import annotations
 
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from threading import Lock
 
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
 
import dash
from dash import dcc, html, dash_table, Input, Output, State
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
 
# ── Design tokens ──────────────────────────────────────────────────────────────
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
        "Enable AWS Cost Anomaly Detection with alerts for >$100/hour spend spikes",
        "Require MFA for AssumeRole via IAM condition keys",
        "Tag enforcement policy via AWS Config — deny untagged resource creation",
    ],
    "public_exposure": [
        "Block NodePort services in production via Kubernetes NetworkPolicy",
        "Enable VPC Flow Logs and alert on unexpected inbound connections",
        "Implement Pod Security Standards (restricted profile) across namespaces",
    ],
    "identity_abuse": [
        "Enforce maximum session duration of 1 hour on assumed-role sessions",
        "Enable CloudTrail with real-time alerts for off-hours AssumeRole events",
        "Implement just-in-time access via AWS IAM Identity Center",
    ],
}
_CONF_COLOR = {"high": "#3fb950", "medium": "#e3b341", "low": "#f85149"}
_GRAPH_DEFAULTS = dict(plot_bgcolor=_CARD, paper_bgcolor=_CARD, font_color=_TEXT)
_AXIS_DEFAULTS  = dict(gridcolor=_BORDER, color=_TEXT, linecolor=_BORDER)
 
# Module-level narrative lookup — populated in create_app()
_narrative_lookup: dict = {}
 
 
# ── Stream state ───────────────────────────────────────────────────────────────
 
class StreamState:
    WINDOW_MINUTES  = 5
    REFRESH_SECONDS = 10
 
    def __init__(self, pipeline, results, all_signals, all_bursts,
                 all_incidents, all_queue):
        self._lock = Lock()
        self._pipeline   = pipeline
        self._results    = results
        self._all_queue  = all_queue
        self._sorted_events = sorted(
            pipeline.event_stream, key=lambda e: e.timestamp
        )
        self._total_events = len(self._sorted_events)
 
        if self._sorted_events:
            self._stream_start = self._sorted_events[0].timestamp
            self._stream_end   = self._sorted_events[-1].timestamp
        else:
            now = datetime.now(timezone.utc)
            self._stream_start = self._stream_end = now
 
        self._all_signals   = all_signals
        self._all_bursts    = all_bursts
        self._all_incidents = all_incidents
        self._inc_lookup    = {i.incident_id: i for i in all_incidents}
 
        self._replay_cursor  = self._stream_start
        self._replay_index   = 0
        self._visible_events: list = []
        self._visible_bursts: list = []
        self._new_inc_ids:    set  = set()
        self._tick_count  = 0
        self._last_update = time.time()
 
    def _advance(self) -> None:
        next_cursor = self._replay_cursor + timedelta(minutes=self.WINDOW_MINUTES)
        if self._replay_cursor >= self._stream_end:
            self._replay_cursor  = self._stream_start
            self._replay_index   = 0
            self._visible_events = []
            self._visible_bursts = []
            self._new_inc_ids    = set()
            next_cursor = self._replay_cursor + timedelta(minutes=self.WINDOW_MINUTES)
 
        new_events: list = []
        while (self._replay_index < self._total_events and
               self._sorted_events[self._replay_index].timestamp < next_cursor):
            new_events.append(self._sorted_events[self._replay_index])
            self._replay_index += 1
 
        self._visible_events.extend(new_events)
        new_bursts = [
            b for b in self._all_bursts
            if self._replay_cursor <= getattr(b, "timestamp", self._stream_start) < next_cursor
        ]
        self._visible_bursts.extend(new_bursts)
        self._replay_cursor = next_cursor
        self._tick_count   += 1
        self._last_update   = time.time()
 
        window_corr_ids = {
            ev.correlation_id for ev in new_events
            if getattr(ev, "correlation_id", "")
        }
        self._new_inc_ids = {
            inc.incident_id for inc in self._all_incidents
            if any(cid in window_corr_ids
                   for cid in getattr(inc, "correlation_ids", []))
        }
 
    def tick(self) -> None:
        with self._lock:
            self._advance()
 
    def snapshot(self) -> dict:
        with self._lock:
            elapsed  = time.time() - self._last_update
            total_s  = max((self._stream_end - self._stream_start).total_seconds(), 1)
            done_s   = (self._replay_cursor - self._stream_start).total_seconds()
            progress = min(100, int(done_s / total_s * 100))
            return {
                "signals":        self._all_signals,
                "bursts":         self._all_bursts,
                "incidents":      self._all_incidents,
                "queue":          self._all_queue,
                "inc_lookup":     self._inc_lookup,
                "new_inc_ids":    set(self._new_inc_ids),
                "visible_events": list(self._visible_events),
                "visible_bursts": list(self._visible_bursts),
                "tick":           self._tick_count,
                "elapsed":        elapsed,
                "events_seen":    self._replay_index,
                "total_events":   self._total_events,
                "cursor":         self._replay_cursor,
                "progress":       progress,
                "stream_start":   self._stream_start,
                "stream_end":     self._stream_end,
            }
 
    def get_incident(self, inc_id: str):
        with self._lock:
            return self._inc_lookup.get(inc_id)
 
 
# ── Figure builders ────────────────────────────────────────────────────────────
 
def _ttl_histogram(pipeline) -> go.Figure:
    eph, per = [], []
    for asset in pipeline.asset_registry.values():
        ttl = asset.ttl_seconds
        if ttl is None:
            continue
        m = min(ttl / 60.0, 120.0)
        (eph if ttl < 3600 else per).append(m)
    fig = go.Figure()
    bin_spec = dict(start=0, end=120, size=5)
    fig.add_trace(go.Histogram(
        x=eph, name="Ephemeral", xbins=bin_spec,
        marker_color="#f85149", opacity=0.85,
    ))
    fig.add_trace(go.Histogram(
        x=per, name="Persistent", xbins=bin_spec,
        marker_color="#3fb950", opacity=0.85,
    ))
    fig.add_vline(
        x=60, line_width=2, line_dash="dash", line_color=_ACCENT,
        annotation_text="Ephemeral Threshold (60 min)",
        annotation_position="top right",
        annotation_font_color=_ACCENT, annotation_font_size=11,
    )
    fig.update_layout(
        **_GRAPH_DEFAULTS,
        title=dict(text="Ephemeral Resource TTL Distribution", font_color=_TEXT),
        xaxis=dict(title="TTL (minutes)", range=[0, 122], **_AXIS_DEFAULTS),
        yaxis=dict(title="Asset count", **_AXIS_DEFAULTS),
        barmode="stack",
        legend=dict(font_color=_TEXT, bgcolor=_CARD, bordercolor=_BORDER),
        margin=dict(l=50, r=20, t=50, b=50), height=350,
    )
    return fig
 
 
def _spike_timeline(visible_events, visible_bursts, cursor) -> go.Figure:
    bucket: dict = defaultdict(int)
    for ev in visible_events:
        ts  = ev.timestamp
        key = ts.replace(minute=(ts.minute // 10) * 10, second=0, microsecond=0)
        bucket[key] += 1
    if not bucket:
        fig = go.Figure()
        fig.update_layout(
            **_GRAPH_DEFAULTS,
            title=dict(text="Resource Creation Spike Timeline (Live)", font_color=_TEXT),
            xaxis=dict(**_AXIS_DEFAULTS), yaxis=dict(**_AXIS_DEFAULTS), height=350,
        )
        return fig
    xs = sorted(bucket)
    ys = [bucket[b] for b in xs]
    burst_set: set = set()
    for b in visible_bursts:
        bt = getattr(b, "timestamp", None)
        if bt:
            burst_set.add(bt.replace(minute=(bt.minute//10)*10, second=0, microsecond=0))
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
            marker=dict(color="#f85149", size=8, symbol="circle",
                        line=dict(color="#ff7070", width=1)),
        ))
    if xs:
        fig.add_vline(
            x=cursor, line_width=1, line_dash="dot", line_color="#3fb950",
            annotation_text="NOW", annotation_font_color="#3fb950",
            annotation_font_size=10,
        )
    fig.update_layout(
        **_GRAPH_DEFAULTS,
        title=dict(text="Resource Creation Spike Timeline (Live)", font_color=_TEXT),
        xaxis=dict(title="Timestamp", **_AXIS_DEFAULTS),
        yaxis=dict(title="Events / 10-min window", **_AXIS_DEFAULTS),
        legend=dict(font_color=_TEXT, bgcolor=_CARD, bordercolor=_BORDER),
        margin=dict(l=50, r=20, t=50, b=50), height=350,
    )
    return fig
 
 
def _bar_chart(items, title) -> go.Figure:
    if not items:
        fig = go.Figure()
        fig.update_layout(**_GRAPH_DEFAULTS, title=dict(text=title, font_color=_TEXT), height=350)
        return fig
    items_rev = list(reversed(items))
    ids    = [str(x[0])[:32] for x in items_rev]
    scores = [x[1] for x in items_rev]
    colors = [_LABEL_COLOR.get(x[2], _ACCENT) for x in items_rev]
    max_s  = max(scores) if scores else 1.0
    fig = go.Figure(go.Bar(
        x=scores, y=ids, orientation="h", marker_color=colors,
        text=[f"{s:.3f}" for s in scores], textposition="outside",
        textfont=dict(color=_TEXT, size=10),
    ))
    fig.update_layout(
        **_GRAPH_DEFAULTS,
        title=dict(text=title, font_color=_TEXT),
        xaxis=dict(title="Risk Score", range=[0, max_s * 1.18], **_AXIS_DEFAULTS),
        yaxis=dict(color=_TEXT, tickfont=dict(size=9)),
        margin=dict(l=10, r=70, t=50, b=40), height=350,
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
 
 
# ── Incident table ─────────────────────────────────────────────────────────────
 
def _window_label(t0, t1) -> str:
    if t0.date() == t1.date():
        return f"{t0.strftime('%H:%M')}-{t1.strftime('%H:%M')}"
    return f"{t0.strftime('%m/%d %H:%M')} to {t1.strftime('%m/%d %H:%M')}"
 
 
def _incident_table_data(incidents, new_ids) -> tuple:
    rows = []
    for rank, inc in enumerate(incidents, 1):
        t0, t1 = inc.time_window
        ps = ", ".join(p.split("/")[-1] for p in inc.principals[:2])
        if len(inc.principals) > 2:
            ps += f" +{len(inc.principals)-2}"
        has_nar = inc.incident_id in _narrative_lookup
        rows.append({
            "New":        "🆕" if inc.incident_id in new_ids else ("🤖" if has_nar else ""),
            "Rank":       rank,
            "ID":         inc.incident_id,
            "Severity":   inc.severity.upper(),
            "Type":       inc.incident_type,
            "Score":      round(inc.incident_score, 3),
            "Signals":    len(inc.signals),
            "Window":     _window_label(t0, t1),
            "Principals": ps,
            "MITRE":      ", ".join(inc.mitre_techniques),
        })
    columns = [
        {"name": "",            "id": "New"},
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
 
 
# ── Drill-down with LLM narratives ─────────────────────────────────────────────
 
def _dd_row(label, value) -> html.P:
    return html.P(
        [html.Span(f"{label}: ", style={"color": _MUTED, "fontWeight": "bold",
                                         "fontSize": "12px"}),
         html.Span(value, style={"color": _TEXT, "fontSize": "13px"})],
        style={"marginBottom": "6px"},
    )
 
 
def _drilldown(inc) -> list:
    sev_color = _SEV_COLOR.get(inc.severity.lower(), _ACCENT)
    t0, t1    = inc.time_window
    window_str = (
        f"{t0.strftime('%Y-%m-%d')}  {t0.strftime('%H:%M')} — {t1.strftime('%H:%M')}"
        if t0.date() == t1.date()
        else f"{t0.strftime('%Y-%m-%d %H:%M')} — {t1.strftime('%Y-%m-%d %H:%M')}"
    )
 
    # ── LLM narrative lookup ───────────────────────────────────────────────────
    nar     = _narrative_lookup.get(inc.incident_id, {})
    has_nar = bool(nar)
 
    # Summary block (LLM only)
    summary_block = html.Div([
        html.P("AI Analysis", style={
            "color": _MUTED, "fontWeight": "bold", "fontSize": "11px",
            "textTransform": "uppercase", "letterSpacing": "1px", "marginBottom": "6px",
        }),
        html.P(nar.get("summary", ""), style={
            "color": _TEXT, "fontSize": "13px",
            "borderLeft": f"3px solid {_ACCENT}",
            "paddingLeft": "10px", "marginBottom": "8px",
        }),
        html.P([
            html.Span("Likely Intent: ", style={"color": _MUTED, "fontWeight": "bold",
                                                 "fontSize": "12px"}),
            html.Span(nar.get("likely_intent", ""), style={"color": _TEXT, "fontSize": "13px"}),
        ]),
    ], style={"marginBottom": "14px"}) if has_nar else None
 
    # MITRE — LLM gives per-incident specific descriptions
    if has_nar and nar.get("mitre_mapping"):
        mitre_bullets = [
            html.Li(
                [html.Strong(t, style={"color": "#e3b341"}), f"  —  {desc}"],
                style={"color": _TEXT, "fontSize": "13px", "marginBottom": "4px"},
            )
            for t, desc in nar["mitre_mapping"].items()
        ]
    else:
        mitre_bullets = [
            html.Li(
                [html.Strong(t, style={"color": "#e3b341"}),
                 f"  —  {_MITRE_DESC.get(t, 'Threat technique')}"],
                style={"color": _TEXT, "fontSize": "13px", "marginBottom": "4px"},
            )
            for t in inc.mitre_techniques
        ]
 
    # Guardrails — LLM gives incident-specific recommendations
    if has_nar and nar.get("guardrails"):
        gr_bullets = [
            html.Li(gr, style={"color": "#3fb950", "fontSize": "13px", "marginBottom": "4px"})
            for gr in nar["guardrails"]
        ]
    else:
        gr_keys = ([inc.incident_type] if inc.incident_type in _GUARDRAILS
                   else ["resource_hijacking", "public_exposure", "identity_abuse"])
        seen: set = set()
        gr_bullets = []
        for key in ["resource_hijacking", "public_exposure", "identity_abuse"]:
            if key in gr_keys:
                for gr in _GUARDRAILS[key]:
                    if gr not in seen:
                        seen.add(gr)
                        gr_bullets.append(html.Li(
                            gr, style={"color": "#3fb950", "fontSize": "13px",
                                       "marginBottom": "4px"},
                        ))
 
    # Evidence — LLM gives ordered narrative chain
    if has_nar and nar.get("evidence_chain"):
        evidence_bullets = [
            html.Li(e, style={"color": "#adbac7", "fontSize": "12px", "marginBottom": "4px"})
            for e in nar["evidence_chain"]
        ]
        evidence_label = "Evidence Chain (AI Analysis)"
    else:
        evidence_bullets = [
            html.Li(snip, style={"color": "#adbac7", "fontSize": "12px", "marginBottom": "4px"})
            for snip in getattr(inc, "evidence", [])[:5]
        ]
        evidence_label = "Evidence — Top Signals"
 
    # Confidence badge
    conf     = nar.get("confidence", "")
    model    = nar.get("model", "")
    conf_badge = html.Span(
        f"🤖 {conf.upper()} confidence",
        style={"backgroundColor": _CONF_COLOR.get(conf, _MUTED),
               "color": "#fff", "padding": "2px 8px", "borderRadius": "4px",
               "fontSize": "10px", "fontWeight": "bold", "marginLeft": "8px"}
    ) if has_nar else None
    model_badge = html.Span(
        f"  {model}",
        style={"color": _MUTED, "fontSize": "10px", "marginLeft": "6px"}
    ) if has_nar else None
 
    return [html.Div([
 
        # ── Header ─────────────────────────────────────────────────────────────
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
            conf_badge or "",
            model_badge or "",
        ], style={"marginBottom": "14px"}),
 
        # ── LLM Summary + Intent ───────────────────────────────────────────────
        summary_block or "",
 
        # ── Details + MITRE + Guardrails ───────────────────────────────────────
        dbc.Row([
            dbc.Col([
                _dd_row("Window",     window_str),
                _dd_row("Score",      f"{inc.incident_score:.3f}"),
                _dd_row("Principals", ", ".join(p.split("/")[-1] for p in inc.principals[:4]) or "N/A"),
                _dd_row("Namespaces", ", ".join(inc.namespaces[:4]) or "N/A"),
                _dd_row("Signals",    str(len(inc.signals))),
                _dd_row("Duration",   f"{getattr(inc,'duration_minutes',0):.0f} min"),
            ], md=4),
            dbc.Col([
                html.P("MITRE ATT&CK", style={
                    "color": _MUTED, "fontWeight": "bold", "fontSize": "12px",
                    "marginBottom": "6px", "textTransform": "uppercase", "letterSpacing": "1px",
                }),
                html.Ul(mitre_bullets, style={"paddingLeft": "16px"}),
            ], md=4),
            dbc.Col([
                html.P("Recommended Guardrails", style={
                    "color": "#3fb950", "fontWeight": "bold", "fontSize": "12px",
                    "marginBottom": "6px", "textTransform": "uppercase", "letterSpacing": "1px",
                }),
                html.Ul(gr_bullets, style={"paddingLeft": "16px"}),
            ], md=4),
        ]),
 
        html.Hr(style={"borderColor": _BORDER, "margin": "10px 0"}),
        html.P(evidence_label, style={
            "color": _MUTED, "fontWeight": "bold", "fontSize": "12px",
            "marginBottom": "6px", "textTransform": "uppercase", "letterSpacing": "1px",
        }),
        html.Ul(evidence_bullets, style={"paddingLeft": "16px"}),
 
    ], style={
        "backgroundColor": _CARD2,
        "border":          f"2px solid {sev_color}",
        "borderRadius":    "8px",
        "padding":         "18px 22px",
        "marginTop":       "12px",
    })]
 
 
# ── KPI card ───────────────────────────────────────────────────────────────────
 
def _kpi(label, value, color=_ACCENT) -> dbc.Card:
    return dbc.Card(
        dbc.CardBody([
            html.P(label, style={
                "color": _MUTED, "fontSize": "11px",
                "textTransform": "uppercase", "letterSpacing": "1px", "marginBottom": "6px",
            }),
            html.H4(value, style={"color": color, "fontWeight": "bold", "marginBottom": "0"}),
        ]),
        style={"backgroundColor": _CARD, "border": f"1px solid {_BORDER}",
               "borderRadius": "8px", "textAlign": "center"},
    )
 
 
# ── DataTable styles ───────────────────────────────────────────────────────────
 
_TH = {"backgroundColor": _CARD2, "color": _TEXT, "fontWeight": "bold",
       "border": f"1px solid {_BORDER}", "fontSize": "12px"}
_TC = {"backgroundColor": _CARD, "color": _TEXT,
       "border": f"1px solid {_BORDER}", "fontSize": "11px",
       "padding": "6px 10px", "maxWidth": "160px",
       "overflow": "hidden", "textOverflow": "ellipsis", "whiteSpace": "nowrap"}
_COND = [
    {"if": {"filter_query": '{Severity} = "CRITICAL"', "column_id": "Severity"},
     "color": "#f85149", "fontWeight": "bold"},
    {"if": {"filter_query": '{Severity} = "HIGH"', "column_id": "Severity"},
     "color": "#e3b341", "fontWeight": "bold"},
    {"if": {"filter_query": '{Severity} = "MEDIUM"', "column_id": "Severity"},
     "color": "#d29922"},
    {"if": {"filter_query": '{Severity} = "LOW"', "column_id": "Severity"},
     "color": "#3fb950"},
    {"if": {"state": "active"},
     "backgroundColor": _CARD2, "border": f"1px solid {_ACCENT}"},
]
 
 
# ── App factory ────────────────────────────────────────────────────────────────
 
def create_app(data_dir: str = "data/") -> dash.Dash:
    global _narrative_lookup
 
    # ── Run full pipeline ──────────────────────────────────────────────────────
    print("  [F3] Loading pipeline (Feature 1 + 2)...")
    from pipeline.ingestion import IngestionPipeline
    from pipeline.enrichment import enrich
    from classifier.ephemeral_classifier import EphemeralClassifier, ClassifierConfig
    from detection.signal_scorer  import score_all
    from detection.burst_detector import detect_bursts
    from detection.correlator     import correlate
    from detection.incident_queue import build_queue
 
    pipeline  = IngestionPipeline(data_dir=data_dir)
    pipeline.ingest()
    enrich(pipeline)
    clf       = EphemeralClassifier(ClassifierConfig())
    results   = clf.classify_all(pipeline)
    signals   = score_all(pipeline, results)
    bursts    = detect_bursts(pipeline)
    incidents = correlate(signals, bursts, pipeline)
    queue     = build_queue(incidents, raw_signal_count=len(signals))
    print(f"  [F3] Ready: {len(pipeline.asset_registry)} assets | "
          f"{len(signals)} signals | {len(incidents)} incidents")
 
    # ── Load LLM narratives ────────────────────────────────────────────────────
    narratives_path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "outputs", "narratives.json")
    try:
        with open(narratives_path) as f:
            nar_data = json.load(f)
        _narrative_lookup = {n["incident_id"]: n for n in nar_data.get("narratives", [])}
        model_name = nar_data.get("model", "unknown")
        print(f"  [F4] Loaded {len(_narrative_lookup)} LLM narratives ({model_name})")
    except FileNotFoundError:
        _narrative_lookup = {}
        print("  [F4] No narratives found — run feature4_main.py first")
    except Exception as e:
        _narrative_lookup = {}
        print(f"  [F4] Could not load narratives: {e}")
 
    # ── Static figures ─────────────────────────────────────────────────────────
    fig_ttl        = _ttl_histogram(pipeline)
    fig_assets     = _top_assets_fig(results)
    fig_identities = _top_identities_fig(results)
 
    # ── Stream state ───────────────────────────────────────────────────────────
    print("  [F3] Starting stream replay...")
    state = StreamState(pipeline, results, signals, bursts, incidents, queue)
    print("  [F3] Dashboard ready.")
 
    # ── Dash app ───────────────────────────────────────────────────────────────
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        suppress_callback_exceptions=True,
        title="EphemeraWatch",
    )
 
    nar_count = len(_narrative_lookup)
 
    app.layout = html.Div(
        style={"backgroundColor": _BG, "minHeight": "100vh",
               "fontFamily": "'Segoe UI', 'Courier New', monospace"},
        children=[
            dcc.Interval(id="live-interval",
                         interval=StreamState.REFRESH_SECONDS * 1000, n_intervals=0),
 
            # ── Title bar ──────────────────────────────────────────────────────
            html.Div(
                style={"backgroundColor": _CARD, "borderBottom": f"2px solid {_ACCENT}",
                       "padding": "16px 30px", "display": "flex",
                       "alignItems": "center", "justifyContent": "space-between"},
                children=[
                    html.Div([
                        html.H2("EphemeraWatch", style={
                            "color": _ACCENT, "fontWeight": "bold",
                            "marginBottom": "2px", "letterSpacing": "3px",
                        }),
                        html.P(
                            "Ephemeral Cloud Risk Detection Platform  —  "
                            "Real-time asset discovery, risk scoring & incident correlation",
                            style={"color": _MUTED, "fontSize": "13px", "marginBottom": "0"},
                        ),
                    ]),
                    html.Div([
                        html.Span("● LIVE", style={
                            "backgroundColor": "#3fb950", "color": "#fff",
                            "padding": "5px 12px", "borderRadius": "4px",
                            "fontSize": "11px", "fontWeight": "bold",
                            "letterSpacing": "2px", "marginRight": "12px",
                        }),
                        html.Span(
                            f"🤖 {nar_count} AI narratives ready" if nar_count
                            else "No narratives — run feature4_main.py",
                            style={"color": "#3fb950" if nar_count else "#e3b341",
                                   "fontSize": "11px", "marginRight": "12px"},
                        ),
                        html.Span(id="last-scan-label",
                                  style={"color": _MUTED, "fontSize": "11px"}),
                    ], style={"display": "flex", "alignItems": "center"}),
                ],
            ),
 
            # Progress bar
            html.Div(id="stream-progress-bar",
                     style={"height": "3px", "backgroundColor": _ACCENT,
                            "width": "0%", "transition": "width 0.5s ease"}),
 
            # ── Main content ───────────────────────────────────────────────────
            html.Div(style={"padding": "20px 24px"}, children=[
 
                # KPI row
                dbc.Row([
                    dbc.Col(html.Div(id="kpi-assets"),    md=3, className="mb-3"),
                    dbc.Col(html.Div(id="kpi-signals"),   md=3, className="mb-3"),
                    dbc.Col(html.Div(id="kpi-reduction"), md=3, className="mb-3"),
                    dbc.Col(html.Div(id="kpi-critical"),  md=3, className="mb-3"),
                ]),
 
                # Row 1 — TTL + live timeline
                dbc.Row([
                    dbc.Col(
                        dbc.Card(dbc.CardBody(
                            dcc.Graph(figure=fig_ttl, config={"displayModeBar": False})
                        ), style={"backgroundColor": _CARD, "border": f"1px solid {_BORDER}",
                                  "borderRadius": "8px"}),
                        md=6, className="mb-3",
                    ),
                    dbc.Col(
                        dbc.Card(dbc.CardBody(
                            dcc.Graph(id="panel-timeline", config={"displayModeBar": False})
                        ), style={"backgroundColor": _CARD, "border": f"1px solid {_BORDER}",
                                  "borderRadius": "8px"}),
                        md=6, className="mb-3",
                    ),
                ]),
 
                # Row 2 — entities + incident queue
                dbc.Row([
                    dbc.Col(
                        dbc.Card(dbc.CardBody(dbc.Tabs([
                            dbc.Tab(
                                dcc.Graph(figure=fig_assets, config={"displayModeBar": False}),
                                label="Resources",
                                tab_style={"color": _MUTED},
                                active_label_style={"color": _ACCENT, "borderColor": _ACCENT},
                            ),
                            dbc.Tab(
                                dcc.Graph(figure=fig_identities, config={"displayModeBar": False}),
                                label="Identities",
                                tab_style={"color": _MUTED},
                                active_label_style={"color": _ACCENT, "borderColor": _ACCENT},
                            ),
                        ])), style={"backgroundColor": _CARD, "border": f"1px solid {_BORDER}",
                                    "borderRadius": "8px"}),
                        md=4, className="mb-3",
                    ),
                    dbc.Col(
                        dbc.Card(dbc.CardBody([
                            html.H6(
                                "Incident Queue — live  |  🤖 = AI narrative  |  click row for details",
                                style={"color": _TEXT, "marginBottom": "12px",
                                       "letterSpacing": "1px", "fontSize": "13px"},
                            ),
                            dash_table.DataTable(
                                id="incident-table",
                                columns=[], data=[],
                                page_size=10, sort_action="native", filter_action="native",
                                style_table={"overflowX": "auto"},
                                style_header=_TH, style_cell=_TC,
                                style_data_conditional=_COND,
                                style_filter={"backgroundColor": _CARD2, "color": _TEXT,
                                              "border": f"1px solid {_BORDER}"},
                            ),
                            html.Div(id="incident-drilldown"),
                        ]), style={"backgroundColor": _CARD, "border": f"1px solid {_BORDER}",
                                   "borderRadius": "8px"}),
                        md=8, className="mb-3",
                    ),
                ]),
 
                # Footer
                html.Div(id="footer-stats", style={
                    "color": "#484f58", "fontSize": "11px",
                    "textAlign": "center", "padding": "12px 0",
                    "borderTop": f"1px solid {_BORDER}",
                }),
            ]),
        ],
    )
 
    # ── Callbacks ──────────────────────────────────────────────────────────────
 
    @app.callback(
        Output("kpi-assets",          "children"),
        Output("kpi-signals",         "children"),
        Output("kpi-reduction",       "children"),
        Output("kpi-critical",        "children"),
        Output("panel-timeline",      "figure"),
        Output("incident-table",      "data"),
        Output("incident-table",      "columns"),
        Output("last-scan-label",     "children"),
        Output("stream-progress-bar", "style"),
        Output("footer-stats",        "children"),
        Input("live-interval",        "n_intervals"),
    )
    def live_update(n_intervals):
        state.tick()
        snap   = state.snapshot()
        q      = snap["queue"]
        by_sev = q.stats.get("by_severity", {}) if q else {}
 
        n_assets  = len(pipeline.asset_registry)
        n_signals = len(snap["signals"])
        alert_red = q.alert_reduction_pct if q else 0.0
        crit_cnt  = by_sev.get("CRITICAL", 0)
        elapsed   = snap["elapsed"]
        progress  = snap["progress"]
        cursor    = snap["cursor"]
 
        kpi_assets    = _kpi("Assets Discovered",  f"{n_assets:,}")
        kpi_signals   = _kpi("Signals Detected",   f"{n_signals:,}",
                             color="#e3b341" if n_signals > 0 else _ACCENT)
        kpi_reduction = _kpi("Alert Reduction",    f"{alert_red:.1f}%", color="#3fb950")
        kpi_critical  = _kpi("Critical Incidents", str(crit_cnt),
                             color="#f85149" if crit_cnt > 0 else _ACCENT)
 
        fig_timeline = _spike_timeline(snap["visible_events"], snap["visible_bursts"], cursor)
        rows, cols   = _incident_table_data(snap["incidents"], snap["new_inc_ids"])
        scan_label   = (f"Last scanned {int(elapsed)}s ago  |  "
                        f"Events: {snap['events_seen']:,} / {snap['total_events']:,}")
        bar_style    = {"height": "3px", "backgroundColor": _ACCENT,
                        "width": f"{progress}%", "transition": "width 0.5s ease"}
        footer       = (
            f"Societe Generale Cybersecurity Hackathon  |  "
            f"{n_signals} signals  |  {len(snap['bursts'])} burst events  |  "
            f"{len(snap['incidents'])} incidents  |  "
            f"{len(_narrative_lookup)} AI narratives  |  "
            f"Streaming: {cursor.strftime('%m/%d %H:%M')} → {snap['stream_end'].strftime('%m/%d %H:%M')}"
        )
        return (kpi_assets, kpi_signals, kpi_reduction, kpi_critical,
                fig_timeline, rows, cols, scan_label, bar_style, footer)
 
    @app.callback(
        Output("incident-drilldown", "children"),
        Input("incident-table",      "active_cell"),
        State("incident-table",      "derived_virtual_data"),
        prevent_initial_call=True,
    )
    def show_drilldown(active_cell, virtual_data):
        if not active_cell or not virtual_data:
            return []
        row_idx = active_cell.get("row", 0)
        if row_idx >= len(virtual_data):
            return []
        inc_id = virtual_data[row_idx].get("ID", "")
        inc    = state.get_incident(inc_id)
        if inc is None:
            return []
        return _drilldown(inc)
 
    return app
 