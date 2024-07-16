# users/forms.py
from django import forms
from .models import UploadedFile
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm


class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['file']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(UploadFileForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        instance = super(UploadFileForm, self).save(commit=False)
        instance.user = self.user
        if commit:
            instance.save()
        return instance

class CustomPasswordResetForm(PasswordResetForm):
    pass

class CustomSetPasswordForm(SetPasswordForm):
    # Vous pouvez ajouter des champs personnalisés ici si nécessaire
    pass