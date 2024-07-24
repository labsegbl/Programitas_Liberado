from django.urls import path
from django.contrib.auth.views import LoginView, LogoutView # Para Autenticación
from django.conf.urls import handler404 # Para los errores

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("inicio/",views.inicio , name="inicio"),
    path('signout/', views.signout, name='signout'),
    path('validarUsuario/', views.validarUsuario , name="validarUsuario"),
    path('crearUsuario/', views.crearUsuario , name="crearUsuario"),
    path('listaNegra/', views.listaNegra, name="listaNegra"),
    path('listaBlanca/', views.listaBlanca, name="listaBlanca"),
    path('enRevision/', views.enRevision, name="enRevision"),
    path('enRevision/retirar/<int:id>/', views.salirRevision, name="salirRevision"),
    path('detectorIP/', views.detector, name="detector"),  
    path('detectorIP/blanca/<int:id>/<str:rutaRetorno>/', views.anadirABlanca, name='añadirABlanca'),
    path('detectorIP/negra/<int:id>/<str:rutaRetorno>/', views.anadirANegra, name='anadirANegra'),
    path('detectorIP/eliminar/<int:id>/<str:rutaRetorno>/', views.eliminar, name='eliminar'),
    path('detectorIP/modificar/<int:id>/<str:rutaRetorno>/', views.modificar, name='modificar'),
    path('detectorIP/noBloquear/<int:id>/', views.noBloquear, name='noBloquear'),
    path('detectorIP/enPendiente/<int:id>/', views.enPendiente, name='enPendiente'),
    path('detectorIP/accionesMultiples/',views.accionesMultiples, name='accionesMultiples'),
    path('detectorIP/ingresarIP/',views.anadirIndividual , name="anadirIndividual"),
    path('exportar/<int:tipo>/', views.exportar, name='exportar'),
    path("ipsBloqueadas/",views.endpointBloqueadas , name="endpoint"), 
    path("ipsTemporales/",views.revisarIPsTemporales , name="revisarIPsTemporales"),    
    path("anadirDominioExonerado/",views.anadirDominioExonerado , name="anadirDominioExonerado"),
]
