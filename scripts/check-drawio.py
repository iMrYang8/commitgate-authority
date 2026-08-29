#!/usr/bin/env python3

import base64
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


source = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/commitgate-authority-v2.drawio")
preview = Path(sys.argv[2] if len(sys.argv) > 2 else "docs/commitgate-authority-v2.svg")
root = ET.parse(source).getroot()
pages = root.findall("diagram")
if len(pages) != 2:
    raise SystemExit(f"expected 2 pages, found {len(pages)}")

for page in pages:
    graph_root = page.find("mxGraphModel/root")
    if graph_root is None:
        raise SystemExit(f"{page.get('name')}: missing graph root")
    cells = graph_root.findall("mxCell")
    ids = [cell.get("id") for cell in cells]
    if None in ids or len(ids) != len(set(ids)):
        raise SystemExit(f"{page.get('name')}: missing or duplicate cell ID")
    known = set(ids)
    for edge in (cell for cell in cells if cell.get("edge") == "1"):
        if edge.get("source") not in known or edge.get("target") not in known:
            raise SystemExit(f"{page.get('name')}: invalid edge reference {edge.get('id')}")
        geometry = edge.find("mxGeometry")
        if geometry is None or geometry.get("relative") != "1":
            raise SystemExit(f"{page.get('name')}: invalid edge geometry {edge.get('id')}")

svg = preview.read_text(encoding="utf8")
ET.fromstring(svg)
match = re.search(
    r'<metadata id="drawio-source" data-encoding="base64">([^<]+)</metadata>',
    svg,
)
if not match or base64.b64decode(match.group(1)) != source.read_bytes():
    raise SystemExit("SVG does not embed the exact draw.io source")

print("verified: 2 pages, unique IDs, valid edges, exact embedded SVG source")
