#!/usr/bin/env python3
"""Render a deterministic SVG preview from an uncompressed draw.io document."""

from __future__ import annotations

import argparse
import base64
import html
import re
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path


def style_map(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in raw.split(";"):
        if "=" in item:
            key, value = item.split("=", 1)
            result[key] = value
    return result


def text_lines(raw: str) -> list[str]:
    value = re.sub(r"(?i)<br\s*/?>", "\n", raw)
    value = re.sub(r"<[^>]+>", "", value)
    return [line.strip() for line in html.unescape(value).splitlines() if line.strip()]


def fitted_lines(raw: str, width: float, base_size: float) -> list[tuple[str, float]]:
    result: list[tuple[str, float]] = []
    for index, line in enumerate(text_lines(raw)):
        size = 15.0 if index > 0 and base_size >= 20 else base_size
        limit = max(8, int(width / max(1.0, size * 0.55)))
        wrapped = textwrap.wrap(line, width=limit, break_long_words=False) or [line]
        result.extend((part, size) for part in wrapped)
    return result


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def geometry(cell: ET.Element) -> tuple[float, float, float, float]:
    node = cell.find("mxGeometry")
    if node is None:
        return 0, 0, 0, 0
    return tuple(float(node.get(key, "0")) for key in ("x", "y", "width", "height"))


def render(source: Path, target: Path) -> None:
    root = ET.parse(source).getroot()
    pages = root.findall("diagram")
    page_width = 1640
    page_gap = 45
    rendered_pages: list[str] = []
    canvas_height = 0

    for page_index, diagram in enumerate(pages):
        model = diagram.find("mxGraphModel")
        if model is None:
            continue
        graph_root = model.find("root")
        if graph_root is None:
            continue
        cells = {cell.get("id", ""): cell for cell in graph_root.findall("mxCell")}

        cache: dict[str, tuple[float, float, float, float]] = {}

        def absolute(cell_id: str) -> tuple[float, float, float, float]:
            if cell_id in cache:
                return cache[cell_id]
            cell = cells[cell_id]
            x, y, width, height = geometry(cell)
            parent = cell.get("parent")
            if parent in cells and cells[parent].get("vertex") == "1":
                px, py, _, _ = absolute(parent)
                x += px
                y += py
            cache[cell_id] = (x, y, width, height)
            return cache[cell_id]

        vertices = [cell for cell in cells.values() if cell.get("vertex") == "1"]
        edges = [cell for cell in cells.values() if cell.get("edge") == "1"]
        max_y = max((absolute(cell.get("id", ""))[1] + absolute(cell.get("id", ""))[3] for cell in vertices), default=700)
        page_height = max(720, int(max_y + 65))
        offset_y = canvas_height
        canvas_height += page_height + (page_gap if page_index < len(pages) - 1 else 0)

        parts = [
            f'<g id="page-{page_index + 1}" transform="translate(0 {offset_y})">',
            f'<rect x="0" y="0" width="{page_width}" height="{page_height}" rx="18" fill="#F8FAFC" stroke="#CBD5E1"/>',
        ]

        for edge in edges:
            source_id, target_id = edge.get("source"), edge.get("target")
            if source_id not in cells or target_id not in cells:
                continue
            sx, sy, sw, sh = absolute(source_id)
            tx, ty, tw, th = absolute(target_id)
            start_x, start_y = sx + sw, sy + sh / 2
            end_x, end_y = tx, ty + th / 2
            if end_x < start_x:
                start_x, start_y = sx + sw / 2, sy + sh
                end_x, end_y = tx + tw / 2, ty
            middle_x = (start_x + end_x) / 2
            style = style_map(edge.get("style", ""))
            stroke = style.get("strokeColor", "#64748B")
            dash = ' stroke-dasharray="7 6"' if style.get("dashed") == "1" else ""
            width = style.get("strokeWidth", "2")
            parts.append(
                f'<path d="M {start_x:.1f} {start_y:.1f} L {middle_x:.1f} {start_y:.1f} '
                f'L {middle_x:.1f} {end_y:.1f} L {end_x:.1f} {end_y:.1f}" '
                f'fill="none" stroke="{esc(stroke)}" stroke-width="{esc(width)}"{dash} marker-end="url(#arrow)"/>'
            )

        for cell in vertices:
            cell_id = cell.get("id", "")
            x, y, width, height = absolute(cell_id)
            style = style_map(cell.get("style", ""))
            fill = style.get("fillColor", "none")
            stroke = style.get("strokeColor", "none")
            stroke_width = style.get("strokeWidth", "1")
            rounded = "14" if style.get("rounded") == "1" else "3"
            opacity = style.get("opacity", "100")
            if fill != "none" or stroke != "none":
                parts.append(
                    f'<rect x="{x:.1f}" y="{y:.1f}" width="{width:.1f}" height="{height:.1f}" '
                    f'rx="{rounded}" fill="{esc(fill)}" stroke="{esc(stroke)}" '
                    f'stroke-width="{esc(stroke_width)}" opacity="{float(opacity) / 100:.2f}"/>'
                )
            raw_value = cell.get("value", "")
            font_size = float(style.get("fontSize", "12"))
            lines = fitted_lines(raw_value, width - 18, font_size)
            if not lines:
                continue
            font_color = style.get("fontColor", "#0F172A")
            secondary_match = re.search(r'<font[^>]*color="([^"]+)"', raw_value, re.I)
            secondary_color = secondary_match.group(1) if secondary_match else font_color
            align = style.get("align", "center")
            text_x = x + (12 if align == "left" else width / 2)
            anchor = "start" if align == "left" else "middle"
            total_height = sum(size * 1.35 for _, size in lines)
            cursor_y = y + max(lines[0][1] + 5, (height - total_height) / 2 + lines[0][1])
            for line_index, (line, size) in enumerate(lines):
                weight = "700" if line_index == 0 and ("<b>" in raw_value or font_size >= 15) else "500"
                color = font_color if line_index == 0 else secondary_color
                parts.append(
                    f'<text x="{text_x:.1f}" y="{cursor_y:.1f}" text-anchor="{anchor}" '
                    f'font-family="Arial" font-size="{size:.1f}" fill="{esc(color)}" '
                    f'font-weight="{weight}">{esc(line)}</text>'
                )
                cursor_y += size * 1.35

        parts.append("</g>")
        rendered_pages.append("\n".join(parts))

    encoded_source = base64.b64encode(source.read_bytes()).decode("ascii")
    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{page_width}" height="{canvas_height}" viewBox="0 0 {page_width} {canvas_height}">
  <metadata id="drawio-source" data-encoding="base64">{encoded_source}</metadata>
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L0,6 L9,3 z" fill="#64748B"/>
    </marker>
  </defs>
  {''.join(rendered_pages)}
</svg>
'''
    target.write_text(svg, encoding="utf8")
    print(f"Rendered {len(pages)} page(s): {target}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    render(args.source, args.target)
