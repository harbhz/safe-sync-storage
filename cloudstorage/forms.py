from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from .models import Profile, UploadFile, Chat

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=50, required=True)
    last_name = forms.CharField(max_length=50, required=True)
    email = forms.EmailField(
        max_length=254,
        required=True,
        help_text='Required. A valid email address is needed for account notifications.',
    )
    security_question = forms.CharField(max_length=255, required=True, help_text='A security question used for future step-up verification.')
    security_answer = forms.CharField(max_length=128, required=True, widget=forms.PasswordInput, help_text='Answer to the security question. Keep it secret.')

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', )

    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip().lower()
        if not email:
            raise forms.ValidationError('Email is required for registration.')
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError('This email address is already in use.')
        return email

    def save(self, commit=True):
        user = super().save(commit=commit)
        # Persist security question/answer to profile
        question = self.cleaned_data.get('security_question')
        answer = self.cleaned_data.get('security_answer')
        if question and answer:
            try:
                profile = user.profile
                profile.security_question = question
                profile.security_answer_hash = make_password(answer)
                profile.save(update_fields=['security_question', 'security_answer_hash'])
            except Exception:
                pass
        return user

class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email')

class ProfileForm(forms.ModelForm):
    security_question = forms.CharField(max_length=255, required=False, help_text='Security question used for step-up verification.')
    security_answer = forms.CharField(max_length=128, required=False, widget=forms.PasswordInput, help_text='Answer to your security question. Leave blank to keep existing answer.')

    class Meta:
        model = Profile
        fields = ('gender', 'mobile', 'address', 'pin', 'city', 'state', 'security_question')

    def save(self, commit=True):
        profile = super().save(commit=False)
        answer = self.cleaned_data.get('security_answer')
        if answer:
            profile.security_answer_hash = make_password(answer)
        if commit:
            profile.save()
        return profile

class FileUploadForm(forms.ModelForm):
    """
    Upload form — sensitivity is intentionally absent.
    The adaptive cryptographic engine classifies files automatically based on
    file extension, file size, user risk score, and device context.
    """
    file_name = forms.CharField(max_length=100, required=True)
    file_path = forms.FileField(required=True)
    file_password = forms.CharField(
        min_length=8,
        max_length=64,
        required=True,
        widget=forms.PasswordInput,
        help_text='8–64 characters. Used to authenticate access to this file at download time.',
    )

    class Meta:
        model = UploadFile
        fields = ('file_name', 'file_path')


class ChatForm(forms.ModelForm):
    class Meta:
        model = Chat
        fields = ('receiver_user', 'message')


class StepUpSecurityForm(forms.Form):
    answer = forms.CharField(
        max_length=255,
        label='Security answer',
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
        help_text='Enter the answer to your security question.',
    )
