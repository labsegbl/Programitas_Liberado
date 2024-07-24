# myapp/resources.py
from import_export import resources
from .models import IP

class IPResource(resources.ModelResource):
    class Meta:
        model = IP
        # Puedes especificar los campos que quieres exportar aquí
        fields = ('ip', 'estado', 'malicioso', 'isp', 'tipoUso', 'pais', 'dominio', 'ataques', 'descripcion', 'peticiones', 'firewall', 'usuario')
