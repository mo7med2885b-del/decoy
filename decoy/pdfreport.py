"""PDF report of one scan: verdict, reasons, what the attacker would have received, the screenshots the sealed browser took, the visitors' views,
and (when the analysts ran) the incident report with indicators. Built with reportlab from the data the app already holds; nothing is fetched."""
import io
import re
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image, KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BLUE, ORANGE, INK, MUTED, LINE = colors.HexColor("#1f63f0"), colors.HexColor("#f26a0a"), colors.HexColor("#0b1530"), colors.HexColor("#56658a"), colors.HexColor("#d2dcf1")
LEVEL_TXT = {"DANGEROUS": "Dangerous link", "SUSPICIOUS": "Suspicious link", "NEEDS A LOOK": "Needs a human look", "NO THREAT FOUND": "No threat found", "LOOKS SAFE": "Looks safe"}


def _esc(s) -> str:
    return re.sub(r"[<>&]", lambda m: {"<": "&lt;", ">": "&gt;", "&": "&amp;"}[m.group(0)], str(s or ""))


def _img(path: Path, width_mm: float):
    try:
        w, h = ImageReader(str(path)).getSize()
        return Image(str(path), width=width_mm * mm, height=width_mm * mm * h / w)
    except Exception:
        return None


def build(scan_id: str, url: str, v: dict, report: dict | None, runs_dir: Path, logo: Path | None = None) -> bytes:
    ss = getSampleStyleSheet()
    H = ParagraphStyle("h", parent=ss["Heading2"], textColor=INK, fontSize=13, spaceBefore=10, spaceAfter=4)
    P = ParagraphStyle("p", parent=ss["BodyText"], textColor=INK, fontSize=9.5, leading=13)
    S = ParagraphStyle("s", parent=P, textColor=MUTED, fontSize=8)
    T = ParagraphStyle("t", parent=ss["Title"], textColor=INK, fontSize=22, alignment=0, spaceAfter=2)
    level = v.get("level", "")
    lvl_color = ORANGE if level in ("DANGEROUS", "SUSPICIOUS", "NEEDS A LOOK") else BLUE
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm, title="Decoy link report", author="Decoy")
    out = []
    head = [[_img(logo, 14) if logo and logo.exists() else "", Paragraph(f"<b>Decoy</b> · link check report<br/><font size=8 color='#56658a'>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · scan {_esc(scan_id)}</font>", P)]]
    t = Table(head, colWidths=[18 * mm, 150 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    out += [t, Spacer(1, 4)]
    out += [Paragraph(f"<font color='{lvl_color.hexval()}'>{_esc(LEVEL_TXT.get(level, level))}</font>", T), Paragraph(f"<b>{_esc(url)}</b>", P), Spacer(1, 4)]
    box = Table([[Paragraph(f"<font size=22 color='{lvl_color.hexval()}'><b>{_esc(v.get('score'))}</b></font><br/><font size=7 color='#56658a'>out of 100, counted by code</font>", P), Paragraph(_esc(v.get("summary", "")), P)]], colWidths=[34 * mm, 134 * mm])
    box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, LINE), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f7ff")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    out += [box]
    if level in ("DANGEROUS", "SUSPICIOUS", "NEEDS A LOOK"):
        out += [Spacer(1, 3), Paragraph("Most links people check are harmless, so a flag can be a false alarm. Read the reasons and the screenshots before you block anything.", S)]
    uo = v.get("user_override")
    if uo:
        out += [Spacer(1, 3), Paragraph(f"Your earlier decision ({_esc(uo.get('decision'))}) won over the score. Decoy's own reading was {_esc(LEVEL_TXT.get(uo.get('level_was'), uo.get('level_was')))} ({_esc(uo.get('score_was'))}/100).", S)]
    ad = v.get("address") or {}
    if ad.get("reasons"):
        out += [Spacer(1, 3), Paragraph(f"Address read: {_esc(ad.get('score'))}/100. " + " ".join(_esc(r) for r in ad["reasons"]), S)]

    ev = v.get("evidence") or []
    if ev:
        out += [Paragraph("Why this verdict", H), ListFlowable([ListItem(Paragraph(f"{_esc(e.get('text'))} <font color='#56658a'>(+{_esc(e.get('weight'))})</font>", P)) for e in ev], bulletType="1", leftIndent=14)]
    got = v.get("attacker_got") or []
    out += [Paragraph("What the attacker would have received", H)]
    if got:
        geo = {g.get("host"): g for g in (v.get("exfil_geo") or [])}
        for g in got:
            where = geo.get(g.get("host"), {})
            place = ", ".join(x for x in (where.get("city"), where.get("code")) if x)
            out += [Paragraph(f"<b>{_esc(g.get('host'))}</b>{(' (' + _esc(place) + ')') if place else ''} received the fake: {_esc(', '.join(g.get('what') or g.get('kinds') or []))}", P)]
    else:
        out += [Paragraph("Nothing was sent to another server. Only fake data was ever typed; nothing real left anyone's hands.", P)]
    cons = v.get("consensus") or {}
    if cons.get("text"):
        out += [Paragraph("Agent debate", H), Paragraph(_esc(cons["text"]), P)]

    shots = sorted(p for p in runs_dir.glob("step-*.jpg") if "full" not in p.name)[:6]
    if shots:
        out += [Paragraph("What the sealed browser saw", H)]
        cells = []
        for i, p in enumerate(shots):
            im = _img(p, 80)
            if im:
                cells.append([im, Paragraph(f"Step {i}", S)])
        rows = [cells[i:i + 2] for i in range(0, len(cells), 2)]
        for r in rows:
            tb = Table([[c[0] for c in r], [c[1] for c in r]], colWidths=[84 * mm] * len(r))
            tb.setStyle(TableStyle([("BOX", (0, 0), (-1, 0), 0.5, LINE), ("ALIGN", (0, 0), (-1, -1), "LEFT")]))
            out += [KeepTogether([tb, Spacer(1, 3)])]
    sw = v.get("swarm") or []
    if sw:
        out += [Paragraph("Three visitors, the same link", H)]
        rows = [["Visitor", "Device", "Saw", "Verdict"]] + [[_esc(x.get("name")), _esc(x.get("device")), Paragraph(_esc(x.get("title") or x.get("error") or ""), S), _esc(LEVEL_TXT.get(x.get("level"), x.get("level") or ""))] for x in sw]
        tb = Table(rows, colWidths=[34 * mm, 34 * mm, 70 * mm, 30 * mm])
        tb.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("FONTSIZE", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2ff"))]))
        out += [tb]
        thumbs = []
        for x in sw:
            f = runs_dir / Path(x.get("shot") or "").name
            if x.get("shot") and f.exists():
                im = _img(f, 52)
                if im:
                    thumbs.append(im)
        if thumbs:
            out += [Spacer(1, 4), Table([thumbs], colWidths=[56 * mm] * len(thumbs))]

    if report:
        out += [Paragraph("Incident report", H), Paragraph(f"<b>{_esc(report.get('headline') or '')}</b>", P)]
        for title, key in (("How the scam works", "how_it_works"), ("Recommended actions", "actions")):
            items = report.get(key) or []
            if items:
                out += [Paragraph(title, H), ListFlowable([ListItem(Paragraph(_esc(i if isinstance(i, str) else i.get("text", "")), P)) for i in items], bulletType="bullet", leftIndent=12)]
        att = report.get("techniques") or []
        if att:
            out += [Paragraph("Suggested ATT&amp;CK mapping (for an analyst to confirm)", H), ListFlowable([ListItem(Paragraph(f"<b>{_esc(a.get('id') or '')}</b> {_esc(a.get('name'))}: {_esc(a.get('why'))}", P)) for a in att], bulletType="bullet", leftIndent=12)]
        iocs = report.get("iocs") or []
        if iocs:
            rows = [["Type", "Value", "Role"]] + [[_esc(i.get("type")), Paragraph(_esc(i.get("value")), S), _esc(i.get("role"))] for i in iocs[:40]]
            tb = Table(rows, colWidths=[22 * mm, 110 * mm, 36 * mm])
            tb.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("FONTSIZE", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2ff"))]))
            out += [Paragraph("Indicators", H), tb]
        for a in (report.get("analysts") or []):
            f = a.get("findings") or []
            if f:
                out += [Paragraph(f"{_esc(a.get('name'))} <font size=8 color='#56658a'>({_esc(a.get('by') or '')})</font>", H), ListFlowable([ListItem(Paragraph(_esc(x), P)) for x in f], bulletType="bullet", leftIndent=12)]
    out += [Spacer(1, 10), Paragraph("Passive analysis of what a sealed sandbox observed. A clean result means nothing harmful was seen during this visit; it is not a guarantee. Decoy never blocks or reports anything by itself: a person decides. Only fake data was typed.", S)]
    doc.build(out)
    return buf.getvalue()
