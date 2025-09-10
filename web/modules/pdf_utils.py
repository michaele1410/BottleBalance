
import fitz  # PyMuPDF
import os
from reportlab.platypus import Table, TableStyle, Paragraph, Image, PageBreak, Spacer
from reportlab.lib.units import mm
from reportlab.lib import colors

from modules.core_utils import (
    localize_dt,
    localize_dt_str
)

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER") or "uploads"

def build_audit_table(audits, styles, tz_name=None):
    audit_data = [[
        Paragraph("<b>Zeitpunkt</b>", styles['Normal']),
        Paragraph("<b>Aktion</b>", styles['Normal']),
        Paragraph("<b>Benutzer</b>", styles['Normal']),
        Paragraph("<b>Details</b>", styles['Normal']),
    ]]

    for a in audits:
        # Lokalisierter Zeitstempel
        formatted_time = localize_dt_str(a.get('timestamp'), tz_name, '%d.%m.%Y %H:%M:%S')

        audit_data.append([
            formatted_time,
            a.get('action', ''),
            a.get('username', 'Unbekannt'),
            Paragraph((a.get('detail') or '').replace('\n', '<br/>'), styles['Normal'])
        ])

    table = Table(audit_data, colWidths=[36*mm, 32*mm, 35*mm, None], repeatRows=1)
    table.setStyle(standard_table_style())
    return table


def standard_table_style():
    return TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f3f5')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#212529')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fcfcfd')]),
        ('GRID', (0,0), (-1,-1), 0.25, colors.HexColor('#dee2e6')),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ])

def footer(canvas, doc_):
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(doc_.pagesize[0] - 18*mm, 12, f"Seite {doc_.page}")
    canvas.restoreState()

def embed_pdf_attachments(antrag_id, attachments, story, styles):
    for att in attachments:
        path = os.path.join(UPLOAD_FOLDER, f"antrag_{antrag_id}", att['stored_name'])
        if not os.path.exists(path):
            continue
        if att['content_type'].startswith('image/'):
            story.append(PageBreak())
            story.append(Paragraph(f"<b>Anhang: {att['original_name']}</b>", styles['Heading3']))
            story.append(Spacer(1, 6))
            try:
                img = Image(path)
                img._restrictSize(160*mm, 120*mm)
                story.append(img)
            except Exception as e:
                story.append(Paragraph(f"Fehler beim Einfügen von {att['original_name']}: {e}", styles['Normal']))
        elif att['content_type'] == 'application/pdf':
            try:
                pdf_doc = fitz.open(path)
                for page_num in range(len(pdf_doc)):
                    page = pdf_doc.load_page(page_num)
                    pix = page.get_pixmap(dpi=150)
                    img_path = f"/tmp/antrag_{antrag_id}_page_{page_num}.png"
                    pix.save(img_path)

                    story.append(PageBreak())
                    story.append(Paragraph(f"<b>Anhang (PDF): {att['original_name']} – Seite {page_num + 1}</b>", styles['Heading3']))
                    story.append(Spacer(1, 6))

                    img = Image(img_path)
                    img._restrictSize(160*mm, 120*mm)
                    story.append(img)

                    # 🧹 Temporäre Datei löschen
                    try:
                        os.remove(img_path)
                    except Exception as e:
                        story.append(Paragraph(f"Fehler beim Löschen von temporärer Datei: {img_path} – {e}", styles['Normal']))
            except Exception as e:
                story.append(Paragraph(f"Fehler beim Einfügen von PDF {att['original_name']}: {e}", styles['Normal']))

        else:
            story.append(Paragraph(f"{att['original_name']} – nicht eingebettet (Dateityp: {att['content_type']})", styles['Normal']))
            story.append(Spacer(1, 4))
    return story
