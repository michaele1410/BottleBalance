
import fitz
import os
from reportlab.platypus import Table, TableStyle, Paragraph, Image, PageBreak, Spacer
from reportlab.lib.units import mm
from reportlab.lib import colors
from flask_babel import gettext as _

from modules.core_utils import (
    localize_dt_str
)

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER") or "uploads"

def build_audit_table(audits, styles, tz_name=None):
    audit_data = [[
            Paragraph(f"<b>{_('Timestamp')}</b>", styles['Normal']),
            Paragraph(f"<b>{_('Action')}</b>", styles['Normal']),
            Paragraph(f"<b>{_('User')}</b>", styles['Normal']),
            Paragraph(f"<b>{_('Details')}</b>", styles['Normal']),
        ]]

    for a in audits:
        # Localized timestamp
        formatted_time = localize_dt_str(a.get('timestamp'), tz_name, '%d.%m.%Y %H:%M:%S')

        audit_data.append([
            formatted_time,
            a.get('action', ''),
            a.get('username', 'Unknown'),
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
    label = _("Page")
    page_no = canvas.getPageNumber()
    canvas.drawRightString(doc_.pagesize[0] - 18*mm, 12, f"{label} {page_no}")
    canvas.restoreState()

def embed_pdf_attachments(request_id, attachments, story, styles):
    for att in attachments:
        path = os.path.join(UPLOAD_FOLDER, f"payment_request_{request_id}", att['stored_name'])
        if not os.path.exists(path):
            continue

        # === Bild-Anlagen (PNG/JPG/WEBP/...) ===
        if att['content_type'].startswith('image/'):
            story.append(PageBreak())
            story.append(Paragraph(
                f"<b>{_('Attachment')}: {att['original_name']}</b>",
                styles['Heading3']
            ))
            story.append(Spacer(1, 6))
            try:
                img = Image(path)
                img._restrictSize(160*mm, 120*mm)
                story.append(img)
            except Exception as e:
                story.append(Paragraph(
                    _("Error while inserting of %(name)s: %(err)s", name=att['original_name'], err=str(e)),
                    styles['Normal']
                ))

        # === PDF-Anlagen → Seiten als Bilder einbetten ===
        elif att['content_type'] == 'application/pdf':
            try:
                pdf_doc = fitz.open(path)
                for page_num in range(len(pdf_doc)):
                    page = pdf_doc.load_page(page_num)
                    pix = page.get_pixmap(dpi=150)
                    img_path = f"/tmp/payment_request_{request_id}_page_{page_num}.png"
                    pix.save(img_path)

                    story.append(PageBreak())
                    story.append(Paragraph(
                        f"<b>{_('Attachment (PDF)')}: {att['original_name']} – {(_('Page'))} {page_num + 1}</b>",
                        styles['Heading3']
                    ))
                    story.append(Spacer(1, 6))

                    img = Image(img_path)
                    img._restrictSize(160*mm, 120*mm)
                    story.append(img)

                    # Temporäre Datei löschen
                    try:
                        os.remove(img_path)
                    except Exception as e:
                        story.append(Paragraph(
                            _("Error deleting temporary file: %(path)s – %(err)s", path=img_path, err=str(e)),
                            styles['Normal']
                        ))
            except Exception as e:
                story.append(Paragraph(
                    _("Error while inserting PDF %(name)s: %(err)s", name=att['original_name'], err=str(e)),
                    styles['Normal']
                ))

        # === Nicht-embeddbare Dateitypen ===
        else:
            story.append(Paragraph(
                _("%(name)s – not embedded (file type: %(ctype)s)", name=att['original_name'], ctype=att['content_type']),
                styles['Normal']
            ))
            story.append(Spacer(1, 4))

    return story
