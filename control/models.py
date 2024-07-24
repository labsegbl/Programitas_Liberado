from django.db import models
from datetime import datetime 
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db.models import UniqueConstraint

#=============================================================================================
#                 Modelos generados para control de IPs
#=============================================================================================

class Pais(models.Model):
    nombre = models.CharField(max_length=100, null=False, unique=True)
    name = models.CharField(max_length=100 , default="Desconocido")
    iso2 = models.CharField(max_length=2 , default="00")
    iso3 = models.CharField(max_length=3 , default="000")
    phonecod = models.CharField(max_length=5 , default="00000")

    def __str__(self):
        return self.nombre
    
class Dominio(models.Model):
    nomDominio = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.nomDominio

class DominioPermitido(models.Model):
    nomDominio = models.ForeignKey(Dominio, on_delete=models.CASCADE)

    def __str__(self):
        return self.nomDominio.nomDominio

class IP(models.Model):
    fw = (
        ("SI", 'SI'),
        ("NO", 'NO'),
    )
    estados = (
        ("Bloqueado","Bloqueado"),
        ("Bloqueado Temporal","Bloqueado Temporal"),
        ("Pendiente","Pendiente"),
        ("Exonerado","Exonerado"),
        ("No Bloqueado","No Bloqueado"),
        ("Nuevo","Nuevo"),
    )
    ip = models.CharField(max_length=20 , unique=True)
    estado = models.CharField(max_length=100 , choices=estados , default="Nuevo")
    malicioso = models.IntegerField(null=True)
    isp = models.CharField(max_length=100 , null=True)
    tipoUso = models.CharField(max_length=100 , null=True)
    pais = models.ForeignKey(Pais, on_delete=models.CASCADE , null=True)
    dominio = models.ForeignKey(Dominio, on_delete=models.CASCADE)
    ataques = models.CharField(max_length=100 , null=True)
    descripcion = models.CharField(max_length=500 , null=True)
    peticiones = models.IntegerField(null=True , default=0)
    firewall = models.CharField(max_length=5, choices=fw , default= "NO")
    usuario = models.CharField(max_length=100 , null=True)
    fecha = models.DateTimeField(null=True , default=datetime.now())

    def __str__(self):
        return self.ip

class Historial_IP_FW_Permitidas(models.Model):
    ipPermitida = models.OneToOneField(IP, on_delete=models.CASCADE, unique=True)
    descripcion = models.CharField(max_length=200 , null=True)

    def __str__(self):
        return str(self.ipPermitida)
    
    def set_firewall_to_no(self):
        self.ipPermitida.firewall = 'NO'
        self.ipPermitida.save()

class Historial_IP_FW_Bloqueadas(models.Model):
    ipBloqueada = models.OneToOneField(IP, on_delete=models.CASCADE, unique=True)

    def __str__(self):
        return str(self.ipBloqueada)
    
    def set_firewall_to_si(self):
        self.ipBloqueada.firewall = 'SI'
        self.ipBloqueada.save()
    
class BloqueadasTemporales(models.Model):
    ipBloqueada = models.OneToOneField(Historial_IP_FW_Bloqueadas, on_delete=models.CASCADE, unique=True)
    fechaInicio = models.DateTimeField(null=True , default=datetime.now())
    fechaFin = models.DateTimeField(null=False)

    def __str__(self):
        return str(self.ipBloqueada)
        
class Casos_Especiales(models.Model):
    ipEspecial = models.OneToOneField(IP, on_delete=models.CASCADE, unique=True)
    razon = models.CharField(max_length=200, default="Motivo Desconocido")

    def __str__(self):
        return str(self.ipEspecial)
    
    def set_firewall_to_no(self):
        self.ipEspecial.firewall = 'NO'
        self.ipEspecial.save()

class Logs(models.Model):
    acciones = (
        ("REGISTRADO", 'Registrado'),
        ("BLOQUEADO", 'Bloqueado'),
        ("PERMITIDO", 'Permitido'),
    )
    ip = models.ForeignKey(IP, on_delete=models.CASCADE)
    accion = models.CharField(max_length=20, choices=acciones)
    fecha = models.DateTimeField()

    def __str__(self):
        return f"{self.ip} - {self.fecha}"
 


#=============================================================================================
#          Signals para automatizar el estado del firewall
#=============================================================================================

@receiver(post_save, sender=Historial_IP_FW_Bloqueadas)
def update_ip_firewall(sender, instance, created, **kwargs):
    if created:
        instance.set_firewall_to_si()

@receiver(post_save, sender=Historial_IP_FW_Permitidas)
def update_no_firewall_permitidas(sender, instance, created, **kwargs):
    if created:
        instance.set_firewall_to_no()

@receiver(post_save, sender=Casos_Especiales)
def update_ip_firewall_especiales(sender, instance, created, **kwargs):
    if created:
        instance.set_firewall_to_no()

