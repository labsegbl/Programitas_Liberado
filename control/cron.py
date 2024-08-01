from django_cron import CronJobBase, Schedule
from . import views

class RevisarIPsTemporalesCronJob(CronJobBase):
    RUN_AT_TIMES = ['00:00']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'control.revisar_ips_temporales'  # Nombre único para la tarea

    def do(self):
        # Se llama la función desde views para cada día revisar los bloqueos temporales
        views.revisarIPsTemporales()
