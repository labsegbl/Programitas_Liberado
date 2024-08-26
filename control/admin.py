from django.contrib import admin
from control.models import *
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin

from import_export import resources
from import_export.admin import ImportExportModelAdmin
from control.models import *

# Define el recurso de importación/exportación
class UserResource(resources.ModelResource):
    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'email', 'first_name', 'last_name', 'otp_secret')

# Extiende UserAdmin con ExportActionModelAdmin
class UserAdmin(ImportExportModelAdmin, DefaultUserAdmin):
    resource_class = UserResource
    model = User

    list_display = DefaultUserAdmin.list_display + ('otp_secret',) # Aumenta los campos que se aumentan en el administrador.
    fieldsets = DefaultUserAdmin.fieldsets + (
        (None, {'fields': ('otp_secret',)}),
    )
    add_fieldsets = DefaultUserAdmin.add_fieldsets + (
        (None, {'fields': ('otp_secret',)}),
    )

# Re-registrar el modelo User con el UserAdmin extendido
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

# ==================================================================================================================
#                            Clases para exportar los models en el administrador 
# ==================================================================================================================

class IpResource(resources.ModelResource):
    class Meta:
        model = IP 
class IpAdmin(ImportExportModelAdmin):
    resource_class = IpResource

class PaisResource(resources.ModelResource):
    class Meta:
        model = Pais
class PaisAdmin(ImportExportModelAdmin):
    resource_class = PaisResource

class DominioResource(resources.ModelResource):
    class Meta:
        model = Dominio
class DominioAdmin(ImportExportModelAdmin):
    resource_class = DominioResource

class DominioPermitidoResource(resources.ModelResource):
    class Meta:
        model = DominioPermitido
class DominioPermitidoAdmin(ImportExportModelAdmin):
    resource_class = DominioPermitidoResource

class Historial_IP_FW_PermitidasResource(resources.ModelResource):
    class Meta:
        model = Historial_IP_FW_Permitidas
class Historial_IP_FW_PermitidasAdmin(ImportExportModelAdmin):
    resource_class = Historial_IP_FW_PermitidasResource

class Historial_IP_FW_BloqueadasResource(resources.ModelResource):
    class Meta:
        model = Historial_IP_FW_Bloqueadas
class Historial_IP_FW_BloqueadasAdmin(ImportExportModelAdmin):
    resource_class = Historial_IP_FW_BloqueadasResource

class BloqueadasTemporalesResource(resources.ModelResource):
    class Meta:
        model = BloqueadasTemporales
class BloqueadasTemporalesAdmin(ImportExportModelAdmin):
    resource_class = BloqueadasTemporalesResource

class Casos_EspecialesResource(resources.ModelResource):
    class Meta:
        model = Casos_Especiales
class Casos_EspecialesAdmin(ImportExportModelAdmin):
    resource_class = Casos_EspecialesResource

class RangoExoneradoResource(resources.ModelResource):
    class Meta:
        model = RangoExonerado
class RangoExoneradoAdmin(ImportExportModelAdmin):
    resource_class = RangoExoneradoResource

# ==================================================================================================================
#                               Modelos para mostrar en el administrador
# ==================================================================================================================

# Register your models here.
admin.site.register(IP, IpAdmin)
admin.site.register(Pais, PaisAdmin)
admin.site.register(Dominio, DominioAdmin)
admin.site.register(DominioPermitido, DominioPermitidoAdmin)
admin.site.register(Historial_IP_FW_Permitidas, Historial_IP_FW_PermitidasAdmin)
admin.site.register(Historial_IP_FW_Bloqueadas, Historial_IP_FW_BloqueadasAdmin)
admin.site.register(Casos_Especiales, Casos_EspecialesAdmin)
admin.site.register(BloqueadasTemporales, BloqueadasTemporalesAdmin)
admin.site.register(RangoExonerado, RangoExoneradoAdmin)
admin.site.register(Logs)
