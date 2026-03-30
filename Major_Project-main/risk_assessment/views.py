from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django import forms
from .models import TAMAssessment, RiskMatrix
from threats.models import PlantAsset
from authentication.decorators import role_required

class TAMEditForm(forms.ModelForm):
    class Meta:
        model = TAMAssessment
        fields = ['title', 'confidentiality_score', 'integrity_score', 'availability_score',
                  'threat_likelihood', 'vulnerability_factor', 'control_effectiveness', 'notes']
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

@login_required
def assessment_list(request):
    assessments = TAMAssessment.objects.all().order_by('-assessment_date')
    context = {
        'assessments': assessments,
        'critical_count': assessments.filter(risk_level='critical').count(),
        'high_count': assessments.filter(risk_level='high').count(),
        'medium_count': assessments.filter(risk_level='medium').count(),
        'low_count': assessments.filter(risk_level='low').count(),
    }
    return render(request, 'risk_assessment/assessment_list.html', context)

@login_required
def assessment_detail(request, pk):
    assessment = get_object_or_404(TAMAssessment, pk=pk)
    risk_matrix = RiskMatrix.objects.filter(assessment=assessment)
    return render(request, 'risk_assessment/assessment_detail.html', {
        'assessment': assessment, 'risk_matrix': risk_matrix
    })

@login_required
@role_required('admin', 'analyst')
def run_assessment(request):
    assets = PlantAsset.objects.filter(is_active=True)
    if request.method == 'POST':
        asset_id = request.POST.get('asset')
        asset = get_object_or_404(PlantAsset, pk=asset_id)
        assessment = TAMAssessment(
            title=f"TAM Assessment - {asset.name}",
            asset=asset,
            confidentiality_score=float(request.POST.get('confidentiality', 5)),
            integrity_score=float(request.POST.get('integrity', 5)),
            availability_score=float(request.POST.get('availability', 5)),
            threat_likelihood=float(request.POST.get('likelihood', 5)),
            vulnerability_factor=float(request.POST.get('vulnerability', 5)),
            control_effectiveness=float(request.POST.get('control_effectiveness', 5)),
            assessed_by=request.user.username,
            notes=request.POST.get('notes', ''),
            status='completed'
        )
        assessment.calculate_risk()
        assessment.save()
        messages.success(request, f'Assessment completed. Risk Score: {assessment.overall_risk_score} ({assessment.risk_level.upper()})')
        return redirect('risk_assessment:detail', pk=assessment.pk)
    return render(request, 'risk_assessment/run_assessment.html', {'assets': assets})

@login_required
@role_required('admin')
def edit_assessment(request, pk):
    assessment = get_object_or_404(TAMAssessment, pk=pk)
    form = TAMEditForm(request.POST or None, instance=assessment)
    if request.method == 'POST' and form.is_valid():
        assessment = form.save(commit=False)
        assessment.calculate_risk()
        assessment.save()
        messages.success(request, f'Assessment updated. New Risk Score: {assessment.overall_risk_score}')
        return redirect('risk_assessment:detail', pk=assessment.pk)
    return render(request, 'risk_assessment/edit_assessment.html', {
        'form': form, 'assessment': assessment
    })

@login_required
@role_required('admin')
def delete_assessment(request, pk):
    assessment = get_object_or_404(TAMAssessment, pk=pk)
    if request.method == 'POST':
        assessment.delete()
        messages.success(request, 'Assessment deleted.')
        return redirect('risk_assessment:list')
    return render(request, 'risk_assessment/confirm_delete.html', {'assessment': assessment})
