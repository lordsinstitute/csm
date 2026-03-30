from django.db import models
from threats.models import PlantAsset, Threat

class TAMAssessment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
    ]
    title = models.CharField(max_length=200)
    asset = models.ForeignKey(PlantAsset, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    confidentiality_score = models.FloatField(default=0.0)
    integrity_score = models.FloatField(default=0.0)
    availability_score = models.FloatField(default=0.0)
    threat_likelihood = models.FloatField(default=0.0)
    vulnerability_factor = models.FloatField(default=0.0)
    control_effectiveness = models.FloatField(default=0.0)
    
    overall_risk_score = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=20, default='low')
    
    assessed_by = models.CharField(max_length=100)
    assessment_date = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    def calculate_risk(self):
        cia = (self.confidentiality_score + self.integrity_score + self.availability_score) / 3
        risk = cia * self.threat_likelihood * self.vulnerability_factor * (1 - self.control_effectiveness / 10)
        self.overall_risk_score = round(risk, 2)
        if self.overall_risk_score >= 7.5:
            self.risk_level = 'critical'
        elif self.overall_risk_score >= 5.0:
            self.risk_level = 'high'
        elif self.overall_risk_score >= 2.5:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'
        return self.overall_risk_score

    def __str__(self):
        return f"TAM - {self.asset.name} ({self.assessment_date.date()})"

class RiskMatrix(models.Model):
    assessment = models.ForeignKey(TAMAssessment, on_delete=models.CASCADE)
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    likelihood = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    impact = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    risk_score = models.FloatField()
    mitigation_notes = models.TextField(blank=True)

    def __str__(self):
        return f"Risk: {self.threat.title}"