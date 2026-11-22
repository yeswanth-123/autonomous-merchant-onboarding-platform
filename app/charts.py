from math import pi

from markupsafe import Markup, escape

TONE_COLORS = {"info": "#4f6df5", "success": "#16a34a", "warn": "#d97706", "orange": "#ea580c", "danger": "#dc2626",
               "muted": "#94a3b8"}
TONE_BY_STATE = {"SUBMITTED": "info", "EXTRACTING": "info", "VERIFYING": "info", "NEEDS_INFO": "warn",
                 "MANUAL_REVIEW": "orange", "APPROVED": "success", "ACTIVE": "success", "REJECTED": "danger",
                 "PROVISIONING_FAILED": "danger", "EXPIRED": "muted", "WITHDRAWN": "muted"}


def donut(count_by_state: dict, size: int = 190) -> Markup:
    total = sum(count_by_state.values())
    center = size / 2
    radius, stroke_width = size / 2 - 14, 26
    circumference = 2 * pi * radius
    if total == 0:
        return Markup(f'<svg viewBox="0 0 {size} {size}" class="chart" role="img" aria-label="No applications">'
                      f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="var(--line)" '
                      f'stroke-width="{stroke_width}"/>'
                      f'<text x="{center}" y="{center + 5}" text-anchor="middle" class="chart-num">0</text></svg>')
    segments, offset_fraction = [], 0.0
    for state_name, count in count_by_state.items():
        if not count:
            continue
        fraction = count / total
        segments.append(
            f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" '
            f'stroke="{TONE_COLORS[TONE_BY_STATE[state_name]]}" stroke-width="{stroke_width}" '
            f'stroke-dasharray="{fraction * circumference:.2f} {circumference:.2f}" '
            f'stroke-dashoffset="{-offset_fraction * circumference:.2f}" transform="rotate(-90 {center} {center})">'
            f'<title>{escape(state_name)}: {count}</title></circle>')
        offset_fraction += fraction
    return Markup(f'<svg viewBox="0 0 {size} {size}" class="chart" role="img" aria-label="Applications by state">'
                  f'{"".join(segments)}<text x="{center}" y="{center + 4}" text-anchor="middle" class="chart-num">'
                  f'{total}</text><text x="{center}" y="{center + 22}" text-anchor="middle" class="chart-sub">'
                  f'applications</text></svg>')


def bars(rows: list[tuple[str, float, float | None, str]], unit: str = "s") -> Markup:
    if not rows:
        return Markup('<p class="muted">No data yet.</p>')
    max_value = max(max(value, marker_value or 0) for _label, value, marker_value, _tone in rows) or 1
    row_height, chart_width, label_width = 30, 560, 150
    svg_parts = [f'<svg viewBox="0 0 {chart_width + 70} {row_height * len(rows) + 6}" class="chart wide" role="img">']
    for index, (label, value, marker_value, tone) in enumerate(rows):
        row_top = index * row_height + 4
        bar_width = (chart_width - label_width) * value / max_value
        svg_parts.append(f'<text x="0" y="{row_top + 17}" class="chart-lab">{escape(label)}</text>')
        svg_parts.append(
            f'<rect x="{label_width}" y="{row_top + 4}" width="{max(bar_width, 2):.1f}" height="16" rx="4" '
            f'fill="{TONE_COLORS[tone]}"><title>avg {value}{unit}</title></rect>'
        )
        if marker_value:
            marker_x = label_width + (chart_width - label_width) * marker_value / max_value
            svg_parts.append(f'<line x1="{marker_x:.1f}" x2="{marker_x:.1f}" y1="{row_top + 1}" y2="{row_top + 23}" '
                             f'stroke="var(--ink)" stroke-width="2"><title>p95 {marker_value}{unit}</title></line>')
        svg_parts.append(f'<text x="{label_width + max(bar_width, 2) + 8:.1f}" y="{row_top + 17}" '
                         f'class="chart-val">{value}{unit}</text>')
    svg_parts.append("</svg>")
    return Markup("".join(svg_parts))
