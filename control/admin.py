from django.contrib import admin
from control.models import *

# Register your models here.
admin.site.register(IP)
admin.site.register(Pais)
admin.site.register(Dominio)
admin.site.register(DominioPermitido)
admin.site.register(Historial_IP_FW_Permitidas)
admin.site.register(Historial_IP_FW_Bloqueadas)
admin.site.register(Logs)
admin.site.register(Casos_Especiales)
admin.site.register(BloqueadasTemporales)


