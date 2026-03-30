from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from threats.models import Threat, Vulnerability, PlantAsset
from risk_assessment.models import TAMAssessment
from security_controls.models import SecurityControl, SecurityPolicy
from authentication.models import CustomUser
from authentication.decorators import role_required
import io, json
from datetime import datetime
from django.db.models import Avg, Count

@login_required
def reports_home(request):
    threats = Threat.objects.all()
    assessments = TAMAssessment.objects.all()
    controls = SecurityControl.objects.all()

    # Severity breakdown
    severity_data = {
        'critical': threats.filter(severity='critical').count(),
        'high': threats.filter(severity='high').count(),
        'medium': threats.filter(severity='medium').count(),
        'low': threats.filter(severity='low').count(),
    }

    # Control status breakdown
    control_data = {
        'implemented': controls.filter(status='implemented').count(),
        'partial': controls.filter(status='partial').count(),
        'planned': controls.filter(status='planned').count(),
        'not_implemented': controls.filter(status='not_implemented').count(),
    }

    # Risk level breakdown from assessments
    risk_data = {
        'critical': assessments.filter(risk_level='critical').count(),
        'high': assessments.filter(risk_level='high').count(),
        'medium': assessments.filter(risk_level='medium').count(),
        'low': assessments.filter(risk_level='low').count(),
    }

    # Top 5 highest risk assets
    top_risk_assets = TAMAssessment.objects.order_by(
        '-overall_risk_score').select_related('asset')[:5]

    # Mitigation effectiveness
    avg_effectiveness = controls.aggregate(
        avg=Avg('effectiveness_score'))['avg'] or 0

    # Vulnerability stats
    total_vulns = Vulnerability.objects.count()
    patched_vulns = Vulnerability.objects.filter(is_patched=True).count()
    patch_rate = round((patched_vulns / total_vulns * 100), 1) if total_vulns > 0 else 0

    context = {
        'total_assets': PlantAsset.objects.count(),
        'total_threats': threats.count(),
        'critical_threats': threats.filter(severity='critical').count(),
        'active_threats': threats.filter(status='active').count(),
        'total_assessments': assessments.count(),
        'total_controls': controls.count(),
        'implemented_controls': controls.filter(status='implemented').count(),
        'severity_data': json.dumps(severity_data),
        'control_data': json.dumps(control_data),
        'risk_data': json.dumps(risk_data),
        'top_risk_assets': top_risk_assets,
        'avg_effectiveness': round(avg_effectiveness, 1),
        'total_vulns': total_vulns,
        'patched_vulns': patched_vulns,
        'patch_rate': patch_rate,
    }
    return render(request, 'reports/reports_home.html', context)

@login_required
@role_required('admin')
def admin_monitor(request):
    """System-wide monitoring for admin."""
    threats = Threat.objects.all()
    assessments = TAMAssessment.objects.all()
    controls = SecurityControl.objects.all()
    users = CustomUser.objects.all()

    # Monthly threat trend (last 6 months simulation from existing data)
    threat_by_severity = {
        'critical': threats.filter(severity='critical').count(),
        'high': threats.filter(severity='high').count(),
        'medium': threats.filter(severity='medium').count(),
        'low': threats.filter(severity='low').count(),
    }

    control_compliance = {
        'implemented': controls.filter(status='implemented').count(),
        'partial': controls.filter(status='partial').count(),
        'planned': controls.filter(status='planned').count(),
        'not_implemented': controls.filter(status='not_implemented').count(),
    }

    total_controls = controls.count()
    compliance_rate = round(
        (controls.filter(status='implemented').count() / total_controls * 100), 1
    ) if total_controls > 0 else 0

    total_vulns = Vulnerability.objects.count()
    patched = Vulnerability.objects.filter(is_patched=True).count()
    patch_rate = round((patched / total_vulns * 100), 1) if total_vulns > 0 else 0

    avg_risk = assessments.aggregate(avg=Avg('overall_risk_score'))['avg'] or 0

    critical_assets = TAMAssessment.objects.filter(
        risk_level='critical').order_by('-overall_risk_score')[:5]

    context = {
        'total_users': users.count(),
        'active_users': users.filter(is_active=True).count(),
        'total_assets': PlantAsset.objects.count(),
        'critical_assets_count': PlantAsset.objects.filter(criticality='critical').count(),
        'total_threats': threats.count(),
        'active_threats': threats.filter(status='active').count(),
        'critical_threats': threats.filter(severity='critical').count(),
        'total_vulns': total_vulns,
        'unpatched_vulns': total_vulns - patched,
        'patch_rate': patch_rate,
        'total_assessments': assessments.count(),
        'avg_risk_score': round(avg_risk, 2),
        'compliance_rate': compliance_rate,
        'threat_by_severity': json.dumps(threat_by_severity),
        'control_compliance': json.dumps(control_compliance),
        'critical_assets': critical_assets,
        'recent_assessments': assessments.order_by('-assessment_date')[:6],
    }
    return render(request, 'reports/admin_monitor.html', context)

@login_required
def generate_pdf_report(request):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    elements = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('T', parent=styles['Title'],
                                  fontSize=20, textColor=colors.HexColor('#0d47a1'),
                                  spaceAfter=6)
    sub_style = ParagraphStyle('S', parent=styles['Normal'],
                                fontSize=10, textColor=colors.grey, spaceAfter=20)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                               fontSize=13, textColor=colors.HexColor('#0d47a1'),
                               spaceBefore=16, spaceAfter=8)
    normal = styles['Normal']

    # Title
    elements.append(Paragraph("Nuclear Power Plant Cybersecurity Assessment Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')} | "
        f"Generated by: {request.user.get_full_name() or request.user.username} | "
        f"Standard: NEI 13-10", sub_style))
    elements.append(Spacer(1, 0.2*inch))

    # Executive Summary table
    elements.append(Paragraph("Executive Summary", h2_style))
    summary_data = [
        ['Metric', 'Value', 'Status'],
        ['Total Plant Assets', str(PlantAsset.objects.count()), 'Monitored'],
        ['Total Cyber Threats', str(Threat.objects.count()),
         f"{Threat.objects.filter(status='active').count()} Active"],
        ['Critical Threats', str(Threat.objects.filter(severity='critical').count()), 'HIGH PRIORITY'],
        ['Total Vulnerabilities', str(Vulnerability.objects.count()),
         f"{Vulnerability.objects.filter(is_patched=False).count()} Unpatched"],
        ['TAM Assessments', str(TAMAssessment.objects.count()), 'Completed'],
        ['Security Controls', str(SecurityControl.objects.count()),
         f"{SecurityControl.objects.filter(status='implemented').count()} Implemented"],
        ['Security Policies', str(SecurityPolicy.objects.count()), 'Active'],
    ]
    t = Table(summary_data, colWidths=[2.8*inch, 1.5*inch, 2.2*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d47a1')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4ff'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d8e8')),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (1, 0), (2, -1), 'CENTER'),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.2*inch))

    # Critical Threats
    elements.append(Paragraph("Critical & High Severity Threats", h2_style))
    threats_qs = Threat.objects.filter(severity__in=['critical', 'high'])[:10]
    if threats_qs:
        tdata = [['Title', 'Severity', 'Status', 'Attack Vector', 'Risk Score']]
        for th in threats_qs:
            tdata.append([
                th.title[:35], th.severity.upper(), th.status.upper(),
                th.attack_vector[:20], str(th.risk_score())
            ])
        tt = Table(tdata, colWidths=[2.1*inch, 0.9*inch, 0.9*inch, 1.4*inch, 0.9*inch])
        tt.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c62828')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fff3f3'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ffcdd2')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(tt)
    elements.append(Spacer(1, 0.2*inch))

    # Top Risk Assets
    elements.append(Paragraph("Highest Risk Assets (TAM Results)", h2_style))
    top_assets = TAMAssessment.objects.order_by('-overall_risk_score')[:8]
    if top_assets:
        adata = [['Asset Name', 'Asset Type', 'Risk Score', 'Risk Level', 'Assessed By']]
        for a in top_assets:
            adata.append([
                a.asset.name[:30], a.asset.get_asset_type_display(),
                str(a.overall_risk_score), a.risk_level.upper(), a.assessed_by
            ])
        at = Table(adata, colWidths=[2.0*inch, 1.4*inch, 1.0*inch, 1.0*inch, 1.1*inch])
        at.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e65100')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#fff8f0'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ffe0b2')),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(at)
    elements.append(Spacer(1, 0.2*inch))

    # NEI 13-10 Controls Compliance
    elements.append(Paragraph("NEI 13-10 Security Controls Compliance", h2_style))
    cdata = [['Control ID', 'Title', 'Type', 'Status', 'Effectiveness']]
    for c in SecurityControl.objects.all()[:12]:
        cdata.append([
            c.nei_control_id, c.title[:30], c.get_control_type_display(),
            c.get_status_display(), f"{c.effectiveness_score}/10"
        ])
    ct = Table(cdata, colWidths=[1.1*inch, 2.2*inch, 1.0*inch, 1.2*inch, 1.0*inch])
    ct.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1b5e20')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0fff4'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#c8e6c9')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(ct)

    doc.build(elements)
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = (
        f'attachment; filename="NPP_Cyber_Report_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf"'
    )
    return response