from django import forms
from .models import IP , Historial_IP_FW_Permitidas

class IPForm(forms.ModelForm):
    class Meta:
        model = IP
        fields = ['ip', 'estado', 'malicioso', 'isp', 'tipoUso', 'pais', 'dominio', 'ataques', 'descripcion', 'peticiones', 'firewall', 'usuario']
        widgets = {
            'ip': forms.TextInput(attrs={'class': 'form-control'}),
            'estado': forms.Select(attrs={'class': 'form-control'}),
            'malicioso': forms.NumberInput(attrs={'class': 'form-control'}),
            'isp': forms.TextInput(attrs={'class': 'form-control'}),
            'tipoUso': forms.TextInput(attrs={'class': 'form-control'}),
            'pais': forms.Select(attrs={'class': 'form-control'}),
            'dominio': forms.Select(attrs={'class': 'form-control'}),
            'ataques': forms.TextInput(attrs={'class': 'form-control'}),
            'descripcion': forms.TextInput(attrs={'class': 'form-control'}),
            'peticiones': forms.NumberInput(attrs={'class': 'form-control'}),
            'firewall': forms.Select(attrs={'class': 'form-control'}),
            'usuario': forms.TextInput(attrs={'class': 'form-control'}),
        }

class Historial_IP_FW_PermitidasForm(forms.ModelForm):
    class Meta:
        model = Historial_IP_FW_Permitidas
        fields = ['ipPermitida', 'descripcion']
        widgets = {
            'ipPermitida': forms.TextInput(attrs={'class': 'form-control'}),
            'descripcion': forms.TextInput(attrs={'class': 'form-control'}),
        }

class OTPVerificationForm(forms.Form):
    otp_code = forms.CharField(max_length=6, label='Código de Verificación')
