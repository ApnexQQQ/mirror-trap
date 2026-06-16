"""
LIAR'S ECHO - Weekly PDF Threat Report
Generates a professional PDF with attacker stats, charts, and recommendations.
Run: python3 -m modules.pdf_report
Output: /tmp/liarsecho_report_YYYY-MM-DD.pdf
"""
import os, sys, sqlite3, json
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    REPORTLAB = True
except ImportError:
    REPORTLAB = False

DB = '/tmp/liars_echo_fingerprints.db'
OUTPUT_DIR = '/tmp'


def fetch_data():
    conn = sqlite3.connect(DB, timeout=10)
    c = conn.cursor()
    total = c.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
    unique_ips = c.execute('SELECT COUNT(DISTINCT ip) FROM sessions').fetchone()[0]
    by_type = c.execute('SELECT attacker_type, COUNT(*) as cnt FROM sessions GROUP BY attacker_type ORDER BY cnt DESC').fetchall()
    by_skill = c.execute('SELECT skill_level, COUNT(*) as cnt FROM sessions GROUP BY skill_level ORDER BY cnt DESC').fetchall()
    by_tool = c.execute('SELECT likely_tool, COUNT(*) as cnt FROM sessions GROUP BY likely_tool ORDER BY cnt DESC LIMIT 10').fetchall()
    all_ports = c.execute('SELECT ports FROM sessions').fetchall()
    port_counts = {}
    for row in all_ports:
        try:
            for p in json.loads(row[0]):
                p = str(p)
                port_counts[p] = port_counts.get(p, 0) + 1
        except:
            pass
    top_ports = sorted(port_counts.items(), key=lambda x: -x[1])[:10]
    week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
    recent = c.execute('SELECT COUNT(*) FROM sessions WHERE last_seen >= ?', (week_ago,)).fetchone()[0]
    top_attackers = c.execute('SELECT ip, probe_count, attacker_type, skill_level, last_seen FROM sessions ORDER BY probe_count DESC LIMIT 10').fetchall()
    conn.close()
    return {
        'total': total, 'unique_ips': unique_ips,
        'by_type': by_type, 'by_skill': by_skill, 'by_tool': by_tool,
        'top_ports': top_ports, 'recent_week': recent,
        'top_attackers': top_attackers,
        'date': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
    }


def build_pdf(data, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    st = ParagraphStyle('CustomTitle', parent=styles['Title'],
                        fontSize=24, textColor=colors.HexColor('#0a0a23'), spaceAfter=6)
    ss = ParagraphStyle('Subtitle', parent=styles['Normal'],
                        fontSize=10, textColor=colors.HexColor('#555'), spaceAfter=20)
    ssec = ParagraphStyle('Section', parent=styles['Heading2'],
                          fontSize=14, textColor=colors.HexColor('#1a1a4e'),
                          spaceBefore=16, spaceAfter=8)
    sfoot = ParagraphStyle('Footer', parent=styles['Normal'],
                           fontSize=8, textColor=colors.gray)
    normal = styles['Normal']
    elements = []

    # Cover
    elements.append(Spacer(1, 40*mm))
    elements.append(Paragraph("LIAR'S ECHO", st))
    elements.append(Paragraph('Threat Intelligence Report',
                    ParagraphStyle('ST2', parent=ss, fontSize=16,
                                   textColor=colors.HexColor('#333'))))
    elements.append(Spacer(1, 10*mm))
    elements.append(Paragraph('Generated: ' + data['date'], ss))
    elements.append(Spacer(1, 30*mm))
    sd = [['Metric', 'Value'],
          ['Total Sessions', str(data['total'])],
          ['Unique IPs', str(data['unique_ips'])],
          ['Sessions This Week', str(data['recent_week'])],
          ['Top Port Hit', data['top_ports'][0][0] if data['top_ports'] else 'N/A']]
    t = Table(sd, colWidths=[120*mm, 60*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a4e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ccc')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f5f5ff'), colors.white]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    elements.append(t)
    elements.append(PageBreak())

    # Attacker Types
    elements.append(Paragraph('1. Attacker Classification', ssec))
    elements.append(Spacer(1, 4*mm))
    td = [['Type', 'Count', '%']]
    for t, c in data['by_type']:
        pct = round(c / data['total'] * 100, 1) if data['total'] else 0
        td.append([t, str(c), str(pct) + '%'])
    t2 = Table(td, colWidths=[80*mm, 40*mm, 40*mm])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#8B0000')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#fff5f5'), colors.white]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    elements.append(t2)
    elements.append(Spacer(1, 8*mm))

    # Skill Levels
    elements.append(Paragraph('2. Skill Level Distribution', ssec))
    elements.append(Spacer(1, 4*mm))
    skd = [['Skill Level', 'Count']]
    for s, c in data['by_skill']:
        skd.append([s, str(c)])
    t3 = Table(skd, colWidths=[80*mm, 40*mm])
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a4e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f5f5ff'), colors.white]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    elements.append(t3)
    elements.append(Spacer(1, 8*mm))

    # Top Ports
    elements.append(Paragraph('3. Most Targeted Ports', ssec))
    elements.append(Spacer(1, 4*mm))
    pd = [['Port', 'Hits']]
    for p, c in data['top_ports']:
        pd.append([p, str(c)])
    t4 = Table(pd, colWidths=[80*mm, 40*mm])
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#006400')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f0fff0'), colors.white]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    elements.append(t4)
    elements.append(PageBreak())

    # Top Tools
    elements.append(Paragraph('4. Top Attacker Tools', ssec))
    elements.append(Spacer(1, 4*mm))
    tod = [['Tool', 'Detections']]
    for t, c in data['by_tool']:
        tod.append([t, str(c)])
    t5 = Table(tod, colWidths=[80*mm, 40*mm])
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4a0080')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#f5f0ff'), colors.white]),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    elements.append(t5)
    elements.append(Spacer(1, 8*mm))

    # Top Attackers
    elements.append(Paragraph('5. Most Active Attackers', ssec))
    elements.append(Spacer(1, 4*mm))
    ad = [['IP', 'Probes', 'Type', 'Skill', 'Last Seen']]
    for row in data['top_attackers']:
        ip, probes, atype, skill, last = row
        ad.append([ip, str(probes), atype or '?', skill or '?', last[:10]])
    t6 = Table(ad, colWidths=[45*mm, 20*mm, 35*mm, 20*mm, 35*mm])
    t6.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#8B0000')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ddd')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [colors.HexColor('#fff5f5'), colors.white]),
    ]))
    elements.append(t6)
    elements.append(Spacer(1, 12*mm))

    # Recommendations
    elements.append(Paragraph('6. Recommendations', ssec))
    elements.append(Spacer(1, 4*mm))
    tps = ', '.join([str(p[0]) for p in data['top_ports'][:3]]) if data['top_ports'] else 'N/A'
    tt = data['by_tool'][0][0] if data['by_tool'] else 'N/A'
    recs = [
        '- Close or restrict ports: ' + tps + ' if not needed',
        '- Monitor SSH and database ports - they attract skilled attackers',
        '- Top tool: ' + str(tt) + ' - consider blocking its signature',
        '- Enable 2FA on exposed services',
        '- Run: python3 -m modules.pdf_report for periodic reviews',
    ]
    for r in recs:
        elements.append(Paragraph(r, normal))
        elements.append(Spacer(1, 2*mm))

    elements.append(Spacer(1, 20*mm))
    elements.append(Paragraph(
        "LIAR'S ECHO - Deceptive Honeypot | github.com/ApnexQQQ/liars-echo",
        sfoot))
    doc.build(elements)
    return output_path


def generate_report():
    if not REPORTLAB:
        print('[ERROR] Install reportlab: pip3 install reportlab')
        return None
    data = fetch_data()
    if data['total'] == 0:
        print('[REPORT] No sessions - nothing to report')
        return None
    fn = 'liarsecho_report_' + datetime.utcnow().strftime('%Y-%m-%d') + '.pdf'
    out = os.path.join(OUTPUT_DIR, fn)
    build_pdf(data, out)
    print('[REPORT] Generated: ' + out)
    print('[REPORT] Sessions: ' + str(data['total']))
    print('[REPORT] Unique IPs: ' + str(data['unique_ips']))
    return out


if __name__ == '__main__':
    generate_report()
