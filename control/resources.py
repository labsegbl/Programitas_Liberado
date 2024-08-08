# myapp/resources.py
from import_export import resources
from .models import IP

class IPResource(resources.ModelResource):
    class Meta:
        model = IP
        # Puedes especificar los campos que quieres exportar aquí
        fields = ('ip', 'estado', 'malicioso', 'isp', 'tipoUso', 'pais', 'dominio', 'ataques', 'descripcion', 'peticiones', 'firewall', 'usuario')

    def dehydrate_pais(self, ip):
            pais = ip.pais
            return pais.nombre if pais else None
    
    def dehydrate_dominio(self, ip):
            dominio = ip.dominio
            return dominio.nomDominio if dominio else None