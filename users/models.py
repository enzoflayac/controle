from django.conf import settings
from django.db import models

def user_directory_path(instance, filename):
    # fichier sera uploadé à MEDIA_ROOT/user_<id>/<filename>
    return 'user_{0}/{1}'.format(instance.user.id, filename)

# models.py
class UploadedFile(models.Model):
    file = models.FileField(upload_to=user_directory_path)
    original_name = models.CharField(max_length=255, null=True)  # Ajoutez null=True ici
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)
    