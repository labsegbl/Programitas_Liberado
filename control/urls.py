from django.urls import path
from django.contrib.auth.views import LoginView, LogoutView # Para Autenticación
from django.conf.urls import handler404 # Para los errores
from django.conf import settings
from django.conf.urls.static import static

from . import views


urlpatterns = [
    path("", views.index, name="index"),
    path("inicio/",views.inicio , name="inicio"),
    path('setup-2fa/', views.setup_2fa, name='setup_2fa'),
    path('signout/', views.signout, name='signout'),
    path('validarUsuario/', views.validarUsuario , name="validarUsuario"),
    path('crearUsuario/', views.crearUsuario , name="crearUsuario"),
    path('listaNegra/', views.listaNegra, name="listaNegra"),
    path('listaBlanca/', views.listaBlanca, name="listaBlanca"),
    path('enRevision/', views.enRevision, name="enRevision"),
    path('enRevision/retirar/<int:id>/', views.salirRevision, name="salirRevision"),
    path('detectorIP/', views.detector, name="detector"),  
    path('detectorIP/ingresarRango/', views.ingresarRangoIps, name="ingresarRangoIps"),  
    path('detectorIP/blanca/<int:id>/<str:rutaRetorno>/', views.anadirABlanca, name='añadirABlanca'),
    path('detectorIP/negra/<int:id>/<str:rutaRetorno>/', views.anadirANegra, name='anadirANegra'),
    path('detectorIP/eliminar/<int:id>/<str:rutaRetorno>/', views.eliminar, name='eliminar'),
    path('detectorIP/modificar/<int:id>/<str:rutaRetorno>/', views.modificar, name='modificar'),
    path('detectorIP/noBloquear/<int:id>/', views.noBloquear, name='noBloquear'),
    path('detectorIP/enPendiente/<int:id>/', views.enPendiente, name='enPendiente'),
    path('detectorIP/accionesMultiples/',views.accionesMultiples, name='accionesMultiples'),
    path('detectorIP/ingresarIP/',views.anadirIndividual , name="anadirIndividual"),
    path('exportar/<int:tipo>/', views.exportar, name='exportar'),
    path("block_ips.txt",views.endpointBloqueadas , name="endpoint"), 
    path("ipsTemporales/",views.revisarIPsTemporales , name="revisarIPsTemporales"),    
    path("anadirDominioExonerado/",views.anadirDominioExonerado , name="anadirDominioExonerado"),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) # Añadir linea para generar las imagenes de los codigo QR de 2FA
