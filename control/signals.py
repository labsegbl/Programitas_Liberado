"""from django.core.mail import send_mail
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in

@receiver(user_logged_in)
def send_login_email(sender, request, user, **kwargs):

    subject = 'Nuevo inicio de sesión'
    message = f'El usuario {user.username} ha iniciado sesión en el panel de administración.'
    from_email = 'labsegbl@gmail.com'
    recipient_list = ['labsegbl@gmail.com','davidmartinez2807@gmail.com']  # Lista de destinatarios

    send_mail(subject, message, from_email, recipient_list)"""


from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.core.mail import send_mail

@receiver(user_logged_in)
def send_login_email(sender, user, **kwargs):
    print("Llego a la funcion de enviar email")
    send_mail(
        'Acceso al Panel de Administración',
        f'El usuario {user.username} ha iniciado sesión en el panel de administración.',
        'labsegbl@gmail.com',
        ['labsegbl@gmail.com','davidmartinez2807@gmail.com'],
        fail_silently=False
    )