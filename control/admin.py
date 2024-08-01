from django.contrib import admin
from control.models import *
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin

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
admin.site.register(RangoExonerado)


class UserAdmin(DefaultUserAdmin):
    model = User

    list_display = DefaultUserAdmin.list_display + ('otp_secret',) # Lista de campos que se muestreb en el administrador

    fieldsets = DefaultUserAdmin.fieldsets + (
        (None, {'fields': ('otp_secret',)}),
    )
    add_fieldsets = DefaultUserAdmin.add_fieldsets + (
        (None, {'fields': ('otp_secret',)}),
    )

# Re-registrar el modelo User con el UserAdmin extendido
admin.site.unregister(User)
admin.site.register(User, UserAdmin)