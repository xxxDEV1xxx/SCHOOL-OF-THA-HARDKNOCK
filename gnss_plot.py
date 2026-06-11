"""
gnss_plot.py  --  GNSS Forensic Map Viewer
Loads the latest GNSS_AttackCase_* points.csv and renders an interactive
street/satellite map in your default browser using Folium + Leaflet.

Dependencies (install once):
    pip install folium pandas

Usage:
    python gnss_plot.py
    python gnss_plot.py --dir "D:\\custom\\path"
    python gnss_plot.py --csv "C:\\exact\\path\\to\\points.csv"
    python gnss_plot.py --tiles satellite     # street | satellite | topo | dark
    python gnss_plot.py --port 9000           # change localhost port (default 8765)
    python gnss_plot.py --no-serve            # open file:// directly (tiles may 403)

WHY THE LOCAL SERVER:
  When a map HTML is opened via file://, the browser sends no Referer header
  with tile requests.  CDNs that enforce "Referer required" (OpenTopoMap,
  some ESRI endpoints) return HTTP 403, leaving grey squares on the map.
  Serving via http://localhost gives every tile request a valid Referer.
  Press Ctrl+C to stop the server when you are done.
"""

import os
import sys
import glob
import time
import argparse
import webbrowser
import tempfile
import threading
import http.server
import socketserver
import pandas as pd
import folium
from folium.plugins import MousePosition, MeasureControl, MiniMap

# ---------------------------------------------------------------------------
# CLI ARGS
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="GNSS Forensic Map Viewer")
parser.add_argument("--dir", default=r"C:\gnss\forensic_output",
                    help="Base directory containing GNSS_AttackCase_* folders")
parser.add_argument("--csv", default=None,
                    help="Direct path to a points.csv (overrides --dir)")
parser.add_argument("--tiles", default="street",
                    choices=["street", "satellite", "topo", "dark"],
                    help="Starting tile style (default: street)")
parser.add_argument("--out", default=None,
                    help="Output HTML path (default: system temp file)")
parser.add_argument("--port", type=int, default=8765,
                    help="Localhost port (default: 8765)")
parser.add_argument("--no-serve", dest="no_serve", action="store_true",
                    help="Open via file:// instead of localhost (tiles may 403)")
args = parser.parse_args()

# ---------------------------------------------------------------------------
# LOAD CSV
# ---------------------------------------------------------------------------

if args.csv:
    CSV_PATH = args.csv
else:
    pattern = os.path.join(args.dir, "GNSS_AttackCase_*")
    folders = glob.glob(pattern)
    if not folders:
        sys.exit(f"[ERROR] No GNSS_AttackCase_* folders found in: {args.dir}")
    latest_folder = max(folders, key=os.path.getmtime)
    CSV_PATH = os.path.join(latest_folder, "points.csv")

print(f"Loading: {CSV_PATH}")
df = pd.read_csv(CSV_PATH)

if "UtcTime" in df.columns:
    df["UtcTime"] = pd.to_datetime(df["UtcTime"], errors="coerce")
    df["DepartureTime"] = df["UtcTime"].shift(-1)
else:
    df["DepartureTime"] = None

df = df.dropna(subset=["Latitude", "Longitude"])
if df.empty:
    sys.exit("[ERROR] No valid lat/lon rows in CSV.")

# ---------------------------------------------------------------------------
# TILE PROVIDER CONFIG
#
# All four providers below work correctly when served from localhost.
# OpenTopoMap is the most commonly blocked from file:// -- localhost fixes it.
# ESRI satellite accepts localhost Referer without an API key.
# ---------------------------------------------------------------------------

TILE_CONFIGS = {
    "street": {
        "tiles": "OpenStreetMap",
        "attr":  None,
        "name":  "Street (OSM)",
    },
    "satellite": {
        "tiles": ("https://server.arcgisonline.com/ArcGIS/rest/services/"
                  "World_Imagery/MapServer/tile/{z}/{y}/{x}"),
        "attr":  ("Tiles &copy; Esri &mdash; Source: Esri, Maxar, GeoEye, "
                  "Earthstar Geographics, CNES/Airbus DS, USDA, USGS, AeroGRID, IGN"),
        "name":  "Satellite (ESRI)",
    },
    "topo": {
        "tiles": "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png",
        "attr":  ("Map data: &copy; OpenStreetMap contributors, SRTM | "
                  "Map style: &copy; OpenTopoMap (CC-BY-SA)"),
        "name":  "Topographic (OpenTopoMap)",
    },
    "dark": {
        "tiles": "CartoDB dark_matter",
        "attr":  None,
        "name":  "Dark (CartoDB)",
    },
}

# ---------------------------------------------------------------------------
# BUILD MAP
# ---------------------------------------------------------------------------

center_lat = df["Latitude"].mean()
center_lon = df["Longitude"].mean()

span = max(df["Latitude"].max() - df["Latitude"].min(),
           df["Longitude"].max() - df["Longitude"].min())
if   span < 0.001: initial_zoom = 18
elif span < 0.005: initial_zoom = 16
elif span < 0.02:  initial_zoom = 15
elif span < 0.1:   initial_zoom = 13
elif span < 0.5:   initial_zoom = 11
else:              initial_zoom = 9

cfg = TILE_CONFIGS[args.tiles]
tile_kwargs = {"tiles": cfg["tiles"]}
if cfg["attr"]:
    tile_kwargs["attr"] = cfg["attr"]

m = folium.Map(
    location=[center_lat, center_lon],
    zoom_start=initial_zoom,
    control_scale=True,
    zoom_control=True,
    **tile_kwargs,
)

# All four tile styles as switchable layers in the top-right layer control
def add_tile_layer(fmap, key, active=False):
    c = TILE_CONFIGS[key]
    kw = {"tiles": c["tiles"], "name": c["name"], "overlay": False, "show": active}
    if c["attr"]:
        kw["attr"] = c["attr"]
    folium.TileLayer(**kw).add_to(fmap)

for key in TILE_CONFIGS:
    add_tile_layer(m, key, active=(key == args.tiles))

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def safe(val, fmt=None):
    """Return formatted value or em-dash when missing/NaN."""
    try:
        if pd.isna(val):
            return "&mdash;"
    except (TypeError, ValueError):
        pass
    if val is None or str(val).strip() in ("", "nan", "None"):
        return "&mdash;"
    if fmt:
        try:
            return fmt.format(val)
        except Exception:
            return str(val)
    return str(val)


# ---------------------------------------------------------------------------
# ANOMALY PRE-COMPUTATION  (data-driven, works on any dataset)
#
# Priority order (highest wins when a point matches multiple categories):
#   1. RESERVED_TAC  — TAC is 0, 65535, or other 3GPP-reserved sentinel value
#   2. PCI_COLLISION — this PCI is seen on 2+ different EARFCNs in the dataset
#   3. FLASH_CELL    — this Cell_ECI appears only once in the entire dataset
#   4. RSRQ_INVALID  — RSRQ value exceeds the LTE spec ceiling of 34
#   5. NORMAL        — no anomaly detected
#   6. NO_DATA       — required cell columns absent or all-null
# ---------------------------------------------------------------------------

# Reserved / sentinel TAC values defined by 3GPP
RESERVED_TACS = {0, 65535, 0xFFFE}

# LTE RSRQ is mapped to indices 0–34 (spec TS 36.133 table 9.1.7-1)
RSRQ_SPEC_MAX = 34

# Build lookup sets from the data
_pci_col    = "Cell_PCI"
_earfcn_col = "Cell_EARFCN"
_eci_col    = "Cell_ECI"
_tac_col    = "Cell_TAC"
_rsrq_col   = "Cell_RSRQ"   # may not exist in every dataset

def _iget(row, col, default=None):
    """Return int value of a column, or default on missing/NaN."""
    v = row.get(col, default)
    try:
        if pd.isna(v):
            return default
        return int(v)
    except Exception:
        return default

# PCI collision: PCIs that appear on more than one EARFCN
_collision_pcis: set = set()
if _pci_col in df.columns and _earfcn_col in df.columns:
    _pci_earfcns = (
        df[[_pci_col, _earfcn_col]]
        .dropna()
        .astype(int)
        .drop_duplicates()
        .groupby(_pci_col)[_earfcn_col]
        .nunique()
    )
    _collision_pcis = set(_pci_earfcns[_pci_earfcns > 1].index)

# Flash cells: Cell_ECI values seen only once
_flash_ecis: set = set()
if _eci_col in df.columns:
    _eci_counts = df[_eci_col].dropna().astype(int).value_counts()
    _flash_ecis = set(_eci_counts[_eci_counts == 1].index)

# RSRQ outlier threshold from spec
_has_rsrq = _rsrq_col in df.columns


def classify_point(row):
    """Return (category_string, anomaly_flag_messages_list)."""
    flags = []

    tac    = _iget(row, _tac_col)
    pci    = _iget(row, _pci_col)
    earfcn = _iget(row, _earfcn_col)
    eci    = _iget(row, _eci_col)

    # No cell data at all
    if tac is None and pci is None and eci is None:
        return "no_data", flags

    # 1. Reserved TAC
    if tac is not None and tac in RESERVED_TACS:
        flags.append(f"&#9873; Reserved/phantom TAC: {tac}")

    # 2. PCI collision (same PCI on multiple EARFCNs)
    if pci is not None and pci in _collision_pcis:
        # How many EARFCNs carry this PCI?
        n = int(_pci_earfcns.get(pci, 2))
        flags.append(f"&#9873; PCI {pci} collision — seen on {n} different EARFCNs")

    # 3. Flash cell (single-observation ECI)
    if eci is not None and eci in _flash_ecis:
        flags.append(f"&#9873; Flash cell — ECI {eci} appears only once in session")

    # 4. RSRQ out of spec
    if _has_rsrq:
        rsrq_val = row.get(_rsrq_col)
        try:
            if not pd.isna(rsrq_val) and float(rsrq_val) > RSRQ_SPEC_MAX:
                flags.append(
                    f"&#9873; RSRQ {rsrq_val:.1f} exceeds LTE spec max ({RSRQ_SPEC_MAX})"
                )
        except Exception:
            pass

    # Assign priority category
    if tac is not None and tac in RESERVED_TACS:
        return "reserved_tac", flags
    if pci is not None and pci in _collision_pcis:
        return "pci_collision", flags
    if eci is not None and eci in _flash_ecis:
        return "flash_cell", flags
    if flags:  # RSRQ-only anomaly
        return "rsrq_invalid", flags

    return "normal", flags


# Map category -> Folium color string and hex for legend
CATEGORY_STYLE = {
    #  category        folium_color   hex       label
    "reserved_tac":  ("black",       "#111",   "Reserved/phantom TAC (0 or 65535)"),
    "pci_collision": ("red",         "#e53935", "PCI collision — same PCI on multiple EARFCNs"),
    "flash_cell":    ("orange",      "#e67e22", "Flash cell — ECI seen only once in session"),
    "rsrq_invalid":  ("purple",      "#8e44ad", "RSRQ out of LTE spec (index > 34)"),
    "normal":        ("blue",        "#1a7bcc", ""),   # no label
    "no_data":       ("gray",        "#888",    "No cell data"),
}


def marker_color(row):
    category, _ = classify_point(row)
    return CATEGORY_STYLE[category][0]   # folium color string


_FMT8 = "{:.8f}"   # pre-defined so f-string escaping cannot corrupt it

def point_popup_html(row):
    toa = row.get("UtcTime", None)
    tod = row.get("DepartureTime", None)
    toa_str = toa.strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notnull(toa) else "&mdash;"
    tod_str = tod.strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notnull(tod) else "&mdash;"

    category, flags = classify_point(row)

    flag_block = ""
    if flags:
        items = "".join(
            f'<div style="color:#c0392b;font-weight:bold">{f}</div>' for f in flags
        )
        flag_block = items + '<hr style="margin:4px 0;border-color:#e99">'

    return f"""
<div style="font-family:monospace;font-size:12px;min-width:290px;line-height:1.65">
  <b style="font-size:13px">Point #{safe(row.get('LineNumber'))}</b><br>
  {flag_block}
  <b>Position</b><br>
  &nbsp;Lat: {safe(row.get('Latitude'),  _FMT8)}<br>
  &nbsp;Lon: {safe(row.get('Longitude'), _FMT8)}<br>
  &nbsp;Alt: {safe(row.get('AltitudeMeters'))} m &nbsp; Accuracy: {safe(row.get('AccuracyMeters'))} m<br>
  &nbsp;Dist to truth: {safe(row.get('DistToTruth_m'))} m / {safe(row.get('DistToTruth_ft'))} ft<br>
  <b>Timing</b><br>
  &nbsp;Arrival:&nbsp;&nbsp;&nbsp;{toa_str}<br>
  &nbsp;Departure: {tod_str}<br>
  <b>GNSS</b><br>
  &nbsp;Provider: {safe(row.get('Provider'))} ({safe(row.get('ProviderClass'))})<br>
  &nbsp;Used signals: {safe(row.get('UsedSignals'))}<br>
  <hr style="margin:4px 0;border-color:#ccc">
  <b>Cell tower (CellMapper)</b><br>
  &nbsp;Lat/Lon: {safe(row.get('Cell_Lat'))}, {safe(row.get('Cell_Lon'))}<br>
  &nbsp;MCC/MNC: {safe(row.get('Cell_MCC'))}/{safe(row.get('Cell_MNC'))}<br>
  &nbsp;TAC: {safe(row.get('Cell_TAC'))} &nbsp; ECI: {safe(row.get('Cell_ECI'))}<br>
  &nbsp;RSRP: {safe(row.get('Cell_RSRP'))} dBm<br>
  &nbsp;RAT: {safe(row.get('Cell_RAT1'))}/{safe(row.get('Cell_RAT2'))}<br>
  &nbsp;PCI: {safe(row.get('Cell_PCI'))} &nbsp; EARFCN: {safe(row.get('Cell_EARFCN'))}<br>
  &nbsp;Dist to tower: {safe(row.get('Cell_DistMeters'))} m<br>
</div>"""


def point_tooltip(row):
    toa = row.get("UtcTime", None)
    t   = toa.strftime("%H:%M:%S") if pd.notnull(toa) else "?"
    category, _ = classify_point(row)
    cat_label = CATEGORY_STYLE[category][2]
    suffix = f"  |  {cat_label}" if cat_label else ""
    return (f"#{safe(row.get('LineNumber'))}  {t}  "
            f"PCI {safe(row.get('Cell_PCI'))}  "
            f"RSRP {safe(row.get('Cell_RSRP'))} dBm{suffix}")

# ---------------------------------------------------------------------------
# TRACK PATH + POINT MARKERS
# ---------------------------------------------------------------------------

folium.PolyLine(
    locations=list(zip(df["Latitude"], df["Longitude"])),
    color="#555", weight=1.2, opacity=0.5,
    tooltip="Track path",
).add_to(m)

for _, row in df.iterrows():
    color  = marker_color(row)
    radius = 8 if color in ("darkred", "black") else 6
    folium.CircleMarker(
        location=[row["Latitude"], row["Longitude"]],
        radius=radius,
        color=color, fill=True, fill_color=color,
        fill_opacity=0.85, weight=1.5,
        tooltip=folium.Tooltip(point_tooltip(row), sticky=True),
        popup=folium.Popup(point_popup_html(row), max_width=340),
    ).add_to(m)

# ---------------------------------------------------------------------------
# CELL TOWER MARKERS  (deduplicated from CellMapper columns)
# ---------------------------------------------------------------------------

if all(c in df.columns for c in ["Cell_Lat", "Cell_Lon"]):
    wanted = ["Cell_Lat", "Cell_Lon", "Cell_ECI", "Cell_PCI",
              "Cell_EARFCN", "Cell_TAC", "Cell_MCC", "Cell_MNC"]
    towers = (df[[c for c in wanted if c in df.columns]]
              .dropna(subset=["Cell_Lat", "Cell_Lon"])
              .drop_duplicates(subset=["Cell_Lat", "Cell_Lon"]))
    for _, t in towers.iterrows():
        try:
            tc = "red" if int(t.get("Cell_PCI", -1)) == 242 else (
                 "darkred" if int(t.get("Cell_TAC", 0)) == 65535 else "black")
        except Exception:
            tc = "black"
        folium.Marker(
            location=[t["Cell_Lat"], t["Cell_Lon"]],
            tooltip=folium.Tooltip(
                f"Tower  ECI:{safe(t.get('Cell_ECI'))}  "
                f"PCI:{safe(t.get('Cell_PCI'))}  "
                f"EARFCN:{safe(t.get('Cell_EARFCN'))}  "
                f"TAC:{safe(t.get('Cell_TAC'))}", sticky=True),
            icon=folium.Icon(color=tc, icon="signal", prefix="fa"),
        ).add_to(m)

# ---------------------------------------------------------------------------
# LEGEND
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# LEGEND  (only shows categories actually present in this dataset)
# ---------------------------------------------------------------------------

# Determine which categories appear so we don't show unused legend rows
_present_cats = set()
for _, row in df.iterrows():
    cat, _ = classify_point(row)
    _present_cats.add(cat)

_legend_rows = ""
for cat, (fcol, hexcol, label) in CATEGORY_STYLE.items():
    if cat in _present_cats:
        if label:
            _legend_rows += f'<span style="color:{hexcol}">&#9679;</span> {label}<br>\n'
        else:
            _legend_rows += f'<span style="color:{hexcol}">&#9679;</span> (no anomaly flags)<br>\n'

m.get_root().html.add_child(folium.Element(f"""
<div style="position:fixed;bottom:40px;right:12px;z-index:1000;
  background:rgba(255,255,255,0.93);border:1px solid #bbb;border-radius:6px;
  padding:10px 14px;font-family:monospace;font-size:12px;line-height:2;
  box-shadow:0 2px 6px rgba(0,0,0,0.2)">
  <b>Point color</b><br>
  {_legend_rows}
  <hr style="margin:4px 0">Click point for full detail<br>Hover for summary
</div>
"""))

# ---------------------------------------------------------------------------
# PLUGINS
# ---------------------------------------------------------------------------

MousePosition(
    position="bottomleft", separator=" | ", prefix="Cursor:",
    lat_formatter="function(n){return n.toFixed(6);}",
    lng_formatter="function(n){return n.toFixed(6);}",
).add_to(m)

MeasureControl(
    position="topleft",
    primary_length_unit="meters",
    secondary_length_unit="miles",
    primary_area_unit="sqmeters",
).add_to(m)

MiniMap(toggle_display=True, position="bottomright").add_to(m)
folium.LayerControl(position="topright", collapsed=False).add_to(m)

# ---------------------------------------------------------------------------
# SAVE HTML
# ---------------------------------------------------------------------------

if args.out:
    out_path = args.out
else:
    tmp = tempfile.NamedTemporaryFile(
        suffix=".html", prefix="gnss_map_", delete=False
    )
    out_path = tmp.name
    tmp.close()

m.save(out_path)
print(f"Map saved : {out_path}")

# ---------------------------------------------------------------------------
# OPEN  --  localhost server (default) or file:// (--no-serve)
#
# The server is a standard-library SimpleHTTPRequestHandler restricted to the
# folder containing the HTML file.  It auto-bumps the port if the default is
# already in use.  The browser opens after a short delay so the server is
# ready to accept the first request.
# ---------------------------------------------------------------------------

if args.no_serve:
    url = "file:///" + out_path.replace("\\", "/")
    print(f"Opening  : {url}")
    print("NOTE: tile 403 errors may appear (no Referer from file://).")
    webbrowser.open(url)

else:
    serve_dir  = os.path.dirname(os.path.abspath(out_path))
    html_fname = os.path.basename(out_path)
    port       = args.port

    class _SilentHandler(http.server.SimpleHTTPRequestHandler):
        """SimpleHTTPRequestHandler pinned to serve_dir, no console spam."""
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=serve_dir, **kw)
        def log_message(self, fmt, *a):
            pass  # suppress per-request output

    # Walk up from the preferred port until one is free
    for _ in range(20):
        try:
            httpd = socketserver.TCPServer(("127.0.0.1", port), _SilentHandler)
            httpd.allow_reuse_address = True
            break
        except OSError:
            port += 1
    else:
        sys.exit(
            f"[ERROR] Could not bind to any port in range "
            f"{args.port}\u2013{args.port + 19}."
        )

    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    url = f"http://127.0.0.1:{port}/{html_fname}"
    print(f"Serving  : {url}")
    print("Press Ctrl+C to stop the server.")

    time.sleep(0.4)   # brief pause so server is ready before browser hits it
    webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nServer stopped.")
        httpd.shutdown()
