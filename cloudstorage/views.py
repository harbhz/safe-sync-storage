import os
import hashlib
from os.path import basename
from datetime import timedelta
from django.db.models import Q
from django.http import HttpResponse, HttpResponseRedirect, Http404, HttpResponseNotAllowed, HttpResponseForbidden
from django.urls import reverse, reverse_lazy
from django.contrib import messages
from django.contrib.auth import login, authenticate, update_session_auth_hash
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.views.generic.edit import DeleteView, CreateView, FormView
from django.views.generic import ListView, TemplateView, View
from django.views.generic.edit import FormMixin
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.contrib.auth.hashers import make_password, check_password
from typing import ClassVar

from .models import (
    Contact,
    UploadFile,
    ActivityLogs,
    AnomalyEvent,
    FileTransfer,
    Chat,
    Profile,
    UserECCKey,
)
from .anomaly_detection import record_and_apply
from .forms import SignUpForm, ProfileForm, UserForm, FileUploadForm, ChatForm, StepUpSecurityForm
from .step_up import start_security_challenge, verify_security_answer_and_activate, has_recent_verification
from django.conf import settings
from typing import Optional
import logging


def get_profile(user) -> Optional[Profile]:
    if not getattr(user, 'is_authenticated', False):
        return None
    return getattr(user, 'profile', None)

# --------------------------------------------------------------------------
# Cryptographic engine imports
# --------------------------------------------------------------------------
# Legacy ECB path (kept for backward-compatible download of old files)
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Adaptive cryptographic engine
from .crypto_policy import get_crypto_policy, get_adaptive_policy
from .encryption import derive_key, encrypt_file_gcm, decrypt_file_gcm, InvalidTag

# Adaptive Cryptographic Engine — ECC key-wrapping
from .ecc_keywrap import generate_ecc_keypair, generate_dek, wrap_dek, unwrap_dek

# ---------------------------------------------------------------------------
# Adaptive Cryptographic Engine — auto-provisioning helper
# ---------------------------------------------------------------------------
def _ensure_ecc_keys(user):
    """
    Guarantee the user has an ECC key pair stored in the database.
    Called transparently at upload time so the user never has to visit
    /ecc-keys/ manually.
    Returns the UserECCKey instance (always populated after this call).
    """
    try:
        record = user.ecc_key
        # If private key somehow missing (e.g. legacy record), regenerate
        if not record.private_key_pem:
            private_pem, public_pem = generate_ecc_keypair()
            record.private_key_pem = private_pem
            record.public_key_pem = public_pem
            record.save(update_fields=['private_key_pem', 'public_key_pem', 'date_updated'])
        return record
    except UserECCKey.DoesNotExist:
        private_pem, public_pem = generate_ecc_keypair()
        return UserECCKey.objects.create(
            user=user,
            public_key_pem=public_pem,
            private_key_pem=private_pem,
        )

# Home page view
def home(request):
    return render(request, 'index.html')


class StepUpLoginView(auth_views.LoginView):
    def form_valid(self, form):
        response = super().form_valid(form)
        needs_step_up = bool(
            self.request.session.get('login_step_up_required')
            or self.request.session.get('anomaly_force_step_up')
            or self.request.session.get('login_network_warning')
        )
        if not needs_step_up:
            return response
        # Persist desired redirect target then start/require TOTP verification
        next_url = self.get_success_url()
        self.request.session['step_up_next_url'] = next_url
        # If user has no security question, ask them to set it in profile
        question = start_security_challenge(self.request, self.request.user)
        if not question:
            messages.info(self.request, 'Step-up verification required: please set your security question in your profile.')
            return redirect('profile')
        messages.info(self.request, 'Step-up verification required: answer your security question to continue.')
        return redirect('step-up-otp')


class StepUpOTPView(LoginRequiredMixin, FormView):
    template_name = 'cloudstorage/step_up_otp.html'
    form_class = StepUpSecurityForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        profile = get_profile(self.request.user)
        context['security_question'] = profile.security_question if profile else None
        context['step_up_next_url'] = self.request.session.get('step_up_next_url') or ''
        context['security_configured'] = bool(profile and getattr(profile, 'security_question', None))
        return context

    def get(self, request, *args, **kwargs):
        if has_recent_verification(request):
            next_url = (
                request.session.get('step_up_next_url')
                or request.session.get('step_up_return_url')
                or request.GET.get('next')
                or '/'
            )
            return redirect(next_url)
        profile = get_profile(request.user)
        if not (profile and getattr(profile, 'security_question', None)):
            messages.info(request, 'Please configure your security question before continuing.')
            return redirect('profile')
        # Preserve any previously-set explicit next target in session
        if not request.session.get('step_up_return_url'):
            # Prefer explicit ?next= over stored step_up_next_url or default '/'
            request.session['step_up_return_url'] = request.GET.get('next') or request.session.get('step_up_next_url') or '/'
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if 'resend' in request.POST:
            messages.info(request, 'To change your security question go to your profile.')
            return redirect('profile')
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        next_url = self.request.session.get('step_up_return_url') or self.request.session.get('step_up_next_url') or self.request.GET.get('next') or '/'
        verified, error_message = verify_security_answer_and_activate(self.request, self.request.user, form.cleaned_data['answer'])
        if not verified:
            form.add_error('answer', error_message)
            return self.form_invalid(form)

        self.request.session.pop('step_up_return_url', None)
        self.request.session.pop('step_up_next_url', None)
        messages.success(self.request, 'Verification completed. You can continue now.')
        return redirect(next_url)

# Platform overview
@login_required
def overview(request):
    """Render the platform overview / architecture explainer page."""
    from .models import UserECCKey
    has_ecc = UserECCKey.objects.filter(user=request.user).exists()
    file_count = UploadFile.objects.filter(user=request.user).count()
    return render(request, 'cloudstorage/overview.html', {
        'has_ecc': has_ecc,
        'file_count': file_count,
    })

# Utility: Activity log
def activity_log_function(user, activity, event_request, description=None):
    ip_address = event_request.META.get('REMOTE_ADDR', '')
    user_agent = event_request.META.get('HTTP_USER_AGENT', '')
    ActivityLogs.objects.create(
        user=user,
        activity_log=activity,
        ip_address=ip_address,
        user_agent=user_agent,
        description=description
    )

# User registration
def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('home')
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form})

# Password change
@login_required(login_url='/login/')
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            activity_log_function(
                user=request.user,
                activity="ChangePassword",
                event_request=request
            )
            return redirect('account/change_password')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'account/change_password.html', {'form': form})

# Contact form
class ContactView(CreateView):
    model = Contact
    fields = ['name','email','mobile','description']
    template_name = 'contact.html'
    success_url = '/thanks/'

# File listing for the logged-in user
class FileListView(LoginRequiredMixin, ListView):
    model = UploadFile
    paginate_by = 20

    def get_queryset(self):
        return UploadFile.objects.filter(user=self.request.user).order_by('-date_created')

# File upload with context-aware AES-GCM encryption
class UploadCreate(LoginRequiredMixin, CreateView):
    model = UploadFile
    form_class = FileUploadForm
    template_name = 'cloudstorage/addfile.html'
    success_url = '/thanks/'

    def form_valid(self, form):
        form.instance.user = self.request.user
        file_obj  = form.cleaned_data['file_path']
        file_name = basename(file_obj.name)
        raw_password = form.cleaned_data['file_password']

        # ------------------------------------------------------------------
        # Adaptive Cryptographic Engine — Step 1: Classify & Select
        # Auto-provision ECC key pair (transparent; no user action needed).
        # Multi-factor policy: file type + size + user risk + device context.
        # ------------------------------------------------------------------
        ecc_key_record = _ensure_ecc_keys(self.request.user)
        file_data      = file_obj.read()
        file_size_bytes = len(file_data)

        policy = get_adaptive_policy(
            file_name=file_name,
            file_size_bytes=file_size_bytes,
            user=self.request.user,
            request=self.request,
        )
        sensitivity = policy['sensitivity']
        cipher_mode = policy['cipher_mode']
        key_size    = policy['key_size']

        # ------------------------------------------------------------------
        # Step 2: Password gate — PBKDF2-SHA256 hash stored; plaintext never
        # written to disk.
        # ------------------------------------------------------------------
        form.instance.file_password_hash = make_password(raw_password)
        form.instance.file_size_bytes    = file_size_bytes

        # ------------------------------------------------------------------
        # Step 3: Encryption path chosen by the adaptive engine.
        #
        # ECIES-DIRECT  — tiny files: raw bytes become the ECIES plaintext.
        #                 No separate AES step; unwrap_dek() at download time
        #                 returns the original file bytes directly.
        # AES-128/256-GCM — Random DEK generated, file encrypted with AES-GCM,
        #                   then DEK wrapped with user's ECC public key.
        # ------------------------------------------------------------------
        if cipher_mode == 'ECIES-DIRECT':
            wrap_result = wrap_dek(file_data, ecc_key_record.public_key_pem)
            form.instance.encrypted_data      = None
            form.instance.nonce               = None
            form.instance.wrapped_dek         = wrap_result['wrapped_dek']
            form.instance.wrap_nonce          = wrap_result['wrap_nonce']
            form.instance.ephemeral_public_key = wrap_result['ephemeral_public_pem']
        else:
            dek = generate_dek(key_size)
            ciphertext, file_nonce = encrypt_file_gcm(file_data, dek)
            wrap_result = wrap_dek(dek, ecc_key_record.public_key_pem)
            form.instance.encrypted_data      = ciphertext
            form.instance.nonce               = file_nonce
            form.instance.wrapped_dek         = wrap_result['wrapped_dek']
            form.instance.wrap_nonce          = wrap_result['wrap_nonce']
            form.instance.ephemeral_public_key = wrap_result['ephemeral_public_pem']

        form.instance.sensitivity        = sensitivity
        form.instance.cipher_used        = cipher_mode
        form.instance.require_step_up    = policy['require_step_up']
        form.instance.file_name_with_ext = file_name

        decision = record_and_apply(
            user=self.request.user,
            request=self.request,
            event_type='upload',
            details={
                'file_name': file_name,
                'cipher_mode': cipher_mode,
                'risk_score': policy['risk_score'],
                'source': 'upload',
            },
        )
        if decision.severity in {'medium', 'high'}:
            form.instance.require_step_up = True

        activity_log_function(
            user=self.request.user,
            activity='FileUpload',
            event_request=self.request,
            description=(
                f"File '{file_name}' | size={file_size_bytes}B | "
                f"cipher={cipher_mode} | auto_sensitivity={sensitivity} | "
                f"risk={policy['risk_score']:.2f} | device={policy['device_type']} | "
                f"ext={policy['factors']['ext_sensitivity']} | "
                f"step_up={policy['require_step_up']}"
            ),
        )

        if policy['require_step_up']:
            self.request.session['pending_step_up_file'] = file_name

        # Zero-knowledge architecture: save encrypted model instance to DB
        # while preventing Django from writing the unencrypted plaintext file to disk in MEDIA_ROOT.
        self.object = form.save(commit=False)
        self.object.file_path = None
        self.object.save()
        return HttpResponseRedirect(self.get_success_url())

# File delete view
class FileDelete(LoginRequiredMixin, DeleteView):
    model = UploadFile
    success_url = '/filelist/'

    def form_valid(self, form):
        messages.success(self.request, "The file was deleted successfully.")
        activity_log_function(
            user=self.request.user,
            activity="DeleteFile",
            event_request=self.request
        )
        return super().form_valid(form)

# File download with decryption
class DownloadFile(LoginRequiredMixin, View):
    template_name = 'cloudstorage/download_file_form.html'

    def _get_transfer_for_user(self, upload_file, user):
        """Return the FileTransfer for this file/receiver pair, or None."""
        return FileTransfer.objects.filter(
            file_name=upload_file,
            receiver_user=user
        ).order_by('-date_created').first()

    def _get_file_context(self, upload_file, transfer=None):
        """Build template context dict for the given file record."""
        ctx = {
            'upload_file': upload_file,
            'sensitivity': upload_file.sensitivity,
            'cipher_used': upload_file.cipher_used,
            'require_step_up': upload_file.require_step_up,
            'ecc_encrypted': bool(upload_file.wrapped_dek),
        }
        if transfer:
            ctx['transfer'] = transfer
            ctx['transfer_expires_at'] = transfer.expires_at
            ctx['transfer_expired'] = transfer.is_expired()
        return ctx

    def get(self, request, *args, **kwargs):
        file_id = kwargs.get('pk')
        upload_file = get_object_or_404(UploadFile, id=file_id)
        is_owner = (upload_file.user == request.user)
        transfer = None if is_owner else self._get_transfer_for_user(upload_file, request.user)
        if upload_file.require_step_up and not has_recent_verification(request):
            request.session['step_up_next_url'] = reverse('download-file', kwargs={'pk': upload_file.pk})
            # Ensure user has configured a security question
            question = start_security_challenge(request, request.user)
            if not question:
                messages.warning(request, 'This download requires step-up verification. Please set your security question in your profile.')
                return redirect('profile')
            messages.warning(request, 'This download requires step-up verification. Answer your security question to continue.')
            return redirect('step-up-otp')
        context = self._get_file_context(upload_file, transfer)
        return render(request, self.template_name, context)

    def post(self, request, *args, **kwargs):
        file_password = request.POST.get('file_password', '')
        file_id = kwargs.get('pk')
        upload_file = get_object_or_404(UploadFile, id=file_id)
        is_owner = (upload_file.user == request.user)
        transfer = None if is_owner else self._get_transfer_for_user(upload_file, request.user)
        if upload_file.require_step_up and not has_recent_verification(request):
            request.session['step_up_next_url'] = reverse('download-file', kwargs={'pk': upload_file.pk})
            question = start_security_challenge(request, request.user)
            if not question:
                messages.warning(request, 'This download requires step-up verification. Please set your security question in your profile.')
                return redirect('profile')
            messages.warning(request, 'Step-up verification required. Answer your security question to continue.')
            return redirect('step-up-otp')
        context = self._get_file_context(upload_file, transfer)

        # Transfer expiry enforcement
        if not is_owner and transfer and transfer.is_expired():
            expires_at = transfer.expires_at
            if expires_at is None:
                context['errors'] = 'This shared file link is missing its expiry timestamp.'
                return render(request, self.template_name, context)
            context['errors'] = (
                f'This shared file link expired on '
                f'{expires_at.strftime("%d %b %Y at %H:%M UTC")}. '
                f'Ask the owner to re-share the file.'
            )
            return render(request, self.template_name, context)

        # Guard: ECIES-DIRECT files have no encrypted_data (it's None)
        encrypted_content = bytes(upload_file.encrypted_data) if upload_file.encrypted_data else b''

        # ------------------------------------------------------------------
        # Secure Retrieval — dual-layer decryption
        # Layer 1 (gate): Password verification via PBKDF2-SHA256 hash check.
        # Layer 2 (crypto): ECC path chosen by stored cipher_used value.
        #   ECIES-DIRECT  — unwrap_dek returns original file bytes directly.
        #   AES-128/256-GCM — unwrap_dek returns DEK; AES-GCM decrypts file.
        # ------------------------------------------------------------------
        try:
            if upload_file.wrapped_dek:  # ECC + password path (new files)
                # --- Layer 1: Password gate ---
                if not file_password:
                    context['errors'] = 'Please enter your file password.'
                    return render(request, self.template_name, context)

                if upload_file.file_password_hash and not check_password(file_password, upload_file.file_password_hash):
                    context['errors'] = 'Incorrect file password.'
                    return render(request, self.template_name, context)

                # --- Layer 2: ECC key-unwrapping (transparent to user) ---
                try:
                    owner = upload_file.user
                    if owner is None:
                        raise UserECCKey.DoesNotExist
                    ecc_key_record = UserECCKey.objects.get(user=owner)
                    private_key_pem = ecc_key_record.private_key_pem
                    if private_key_pem is None:
                        raise UserECCKey.DoesNotExist
                except UserECCKey.DoesNotExist:
                    context['errors'] = (
                        'The file owner does not have ECC keys on record. '
                        'This file cannot be decrypted.'
                    )
                    return render(request, self.template_name, context)

                if upload_file.cipher_used == 'ECIES-DIRECT':
                    # File content was the ECIES plaintext — unwrap returns it directly.
                    ephemeral_public_pem = upload_file.ephemeral_public_key
                    wrap_nonce = upload_file.wrap_nonce
                    if ephemeral_public_pem is None or wrap_nonce is None:
                        context['errors'] = 'Missing ECC wrapping metadata for this file.'
                        return render(request, self.template_name, context)
                    decrypted_content = unwrap_dek(
                        ephemeral_public_pem=ephemeral_public_pem,
                        wrapped_dek=bytes(upload_file.wrapped_dek),
                        wrap_nonce=bytes(wrap_nonce),
                        recipient_private_pem=private_key_pem,
                    )
                else:
                    # AES-128-GCM or AES-256-GCM: unwrap DEK, then AES-GCM decrypt.
                    ephemeral_public_pem = upload_file.ephemeral_public_key
                    wrap_nonce = upload_file.wrap_nonce
                    file_nonce = upload_file.nonce
                    if (
                        ephemeral_public_pem is None
                        or wrap_nonce is None
                        or file_nonce is None
                    ):
                        context['errors'] = 'Missing encryption metadata for this file.'
                        return render(request, self.template_name, context)
                    dek = unwrap_dek(
                        ephemeral_public_pem=ephemeral_public_pem,
                        wrapped_dek=bytes(upload_file.wrapped_dek),
                        wrap_nonce=bytes(wrap_nonce),
                        recipient_private_pem=private_key_pem,
                    )
                    file_nonce = bytes(file_nonce)
                    decrypted_content = decrypt_file_gcm(encrypted_content, file_nonce, dek)

            elif upload_file.nonce:  # Password-derived AES-GCM (intermediate era)
                if not file_password:
                    context['errors'] = 'Please enter your file password.'
                    return render(request, self.template_name, context)
                key_size = 32 if '256' in upload_file.cipher_used else 16
                key = derive_key(file_password.encode('utf-8'), key_size)
                decrypted_content = decrypt_file_gcm(
                    encrypted_content, bytes(upload_file.nonce), key
                )

            else:  # Legacy AES-128-ECB (original prototype)
                if len(file_password) != 16:
                    context['errors'] = (
                        'This is a legacy-encrypted file. '
                        'Please provide the original 16-character password.'
                    )
                    return render(request, self.template_name, context)
                key = file_password.encode('utf-8')
                backend = default_backend()
                cipher_obj = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
                decryptor = cipher_obj.decryptor()
                padded = decryptor.update(encrypted_content) + decryptor.finalize()
                unpadder = sym_padding.PKCS7(128).unpadder()
                decrypted_content = unpadder.update(padded) + unpadder.finalize()

        except (InvalidTag, ValueError, Exception) as exc:  # noqa: BLE001
            if isinstance(exc, InvalidTag):
                err = (
                    'File integrity check failed. The file may have been tampered with '
                    'or the stored encryption keys are corrupted.'
                )
            else:
                err = 'Decryption failed: incorrect password or corrupted file.'
            context['errors'] = err
            return render(request, self.template_name, context)

        record_and_apply(
            user=request.user,
            request=request,
            event_type='download',
            details={
                'file_name': upload_file.file_name,
                'cipher_mode': upload_file.cipher_used,
                'source': 'download',
            },
        )

        response = HttpResponse(decrypted_content, content_type='application/octet-stream')
        response['Content-Disposition'] = (
            f'attachment; filename="{upload_file.file_name_with_ext}"'
        )
        return response


# ---------------------------------------------------------------------------
# Profile update
# ---------------------------------------------------------------------------
@login_required
@transaction.atomic
def update_profile(request):
    if request.method == 'POST':
        # Ensure the Profile exists for this user before binding forms
        profile_instance, _ = Profile.objects.get_or_create(user=request.user)
        user_form = UserForm(request.POST, instance=request.user)
        profile_form = ProfileForm(request.POST, instance=profile_instance)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            activity_log_function(
                user=request.user,
                activity='UpdateProfile',
                event_request=request,
            )
            messages.success(request, 'Profile updated successfully.')
            return redirect('profile')
    else:
        # Ensure the Profile exists for this user before creating forms
        profile_instance, _ = Profile.objects.get_or_create(user=request.user)
        user_form = UserForm(instance=request.user)
        profile_form = ProfileForm(instance=profile_instance)
    profile = get_profile(request.user)
    return render(request, 'account/profile.html', {
        'user_form': user_form,
        'profile_form': profile_form,
        'security_configured': bool(profile and getattr(profile, 'security_question', None)),
    })


@login_required
def update_security_question(request):
    """Allow user to add or update their security question/answer from profile."""
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])
    if not request.user.is_authenticated:
        return HttpResponseForbidden()
    question = request.POST.get('security_question')
    answer = request.POST.get('security_answer')
    if not question or not answer:
        messages.error(request, 'Both question and answer are required.')
        return redirect('profile')
    try:
        profile = get_profile(request.user)
        if profile is None:
            # ensure a Profile exists for this user
            from .models import Profile as _Profile
            profile, _ = _Profile.objects.get_or_create(user=request.user)
        profile.security_question = question
        profile.security_answer_hash = make_password(answer)
        profile.save(update_fields=['security_question', 'security_answer_hash'])
        messages.success(request, 'Security question updated.')
    except Exception:
        messages.error(request, 'Unable to update security question.')
    return redirect('profile')


# ---------------------------------------------------------------------------
# ECC Key Management — Adaptive Cryptographic Engine
# ---------------------------------------------------------------------------
@login_required
def ecc_key_view(request):
    """
    Informational view for ECC key management.
    Keys are now auto-generated at first upload, so this page shows status
    and allows voluntary regeneration (useful if the user suspects their
    stored private key has been compromised — old files will still decrypt,
    but new uploads will use the fresh key pair).
    """
    try:
        ecc_record = request.user.ecc_key
        has_key = True
        has_private = bool(ecc_record.private_key_pem)
    except UserECCKey.DoesNotExist:
        ecc_record = None
        has_key = False
        has_private = False

    if request.method == 'POST':
        private_pem, public_pem = generate_ecc_keypair()
        UserECCKey.objects.update_or_create(
            user=request.user,
            defaults={'public_key_pem': public_pem, 'private_key_pem': private_pem},
        )
        activity_log_function(
            user=request.user,
            activity='UpdateProfile',
            event_request=request,
            description='Regenerated ECC key pair (SECP256R1). Both keys stored server-side.',
        )
        return render(request, 'cloudstorage/ecc_keys.html', {
            'generated': True,
            'public_pem': public_pem,
            'has_key': True,
            'has_private': True,
        })

    return render(request, 'cloudstorage/ecc_keys.html', {
        'has_key': has_key,
        'has_private': has_private,
    })


# Activity log listing
class ActivityLogListView(LoginRequiredMixin, ListView):
    model = ActivityLogs
    paginate_by = 50

    def get_queryset(self):
        return ActivityLogs.objects.filter(user=self.request.user).order_by('-id')


@login_required
def anomaly_dashboard(request):
    event_qs = AnomalyEvent.objects.filter(user=request.user).order_by('-date_created')
    log_qs = ActivityLogs.objects.filter(user=request.user).order_by('-date_created')
    file_qs = UploadFile.objects.filter(user=request.user).order_by('-date_created')

    anomaly_counts = {
        'low': AnomalyEvent.objects.filter(user=request.user, severity='low').count(),
        'medium': AnomalyEvent.objects.filter(user=request.user, severity='medium').count(),
        'high': AnomalyEvent.objects.filter(user=request.user, severity='high').count(),
    }
    step_up_required = file_qs.filter(require_step_up=True).count()
    forced_aes256 = file_qs.filter(cipher_used='AES-256-GCM').count()

    return render(request, 'cloudstorage/anomaly_dashboard.html', {
        'recent_events': list(event_qs[:15]),
        'recent_logs': list(log_qs[:10]),
        'recent_files': list(file_qs[:10]),
        'anomaly_counts': anomaly_counts,
        'step_up_required': step_up_required,
        'forced_aes256': forced_aes256,
    })

# File transfer listing
class TransferListView(LoginRequiredMixin, ListView):
    model = FileTransfer
    paginate_by = 50

    def get_queryset(self):
        return FileTransfer.objects.filter(
            Q(user=self.request.user) | Q(receiver_user=self.request.user)
        ).order_by('-date_created')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['now'] = timezone.now()
        return context

# File transfer creation
class TransferFileCreate(LoginRequiredMixin, TemplateView):
    template_name = 'cloudstorage/transferfile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Provide variables expected by the template: `file_list` and `user_list`.
        file_qs = UploadFile.objects.filter(user=self.request.user).order_by('-date_created')
        context['file_list'] = list(file_qs)
        from django.contrib.auth.models import User
        context['user_list'] = list(User.objects.exclude(id=self.request.user.id).order_by('username'))
        profile = get_profile(self.request.user)
        context['security_question'] = profile.security_question if profile else None
        return context

    def post(self, request, *args, **kwargs):
        # Template posts `file_id` — accept that name here for backward compatibility
        upload_id = request.POST.get('upload_id') or request.POST.get('file_id')
        receiver_id = request.POST.get('receiver_id')
        remarks = request.POST.get('remarks', '')
        try:
            upload_file = UploadFile.objects.get(id=upload_id, user=request.user)
        except UploadFile.DoesNotExist:
            messages.error(request, 'File not found.')
            return redirect('filetransfer')

        policy = get_crypto_policy(upload_file.sensitivity, user_risk_score=0.0)
        if upload_file.require_step_up and not has_recent_verification(request):
            request.session['step_up_next_url'] = reverse('filetransfer')
            question = start_security_challenge(request, request.user)
            if not question:
                messages.warning(request, 'This transfer requires step-up verification. Please set your security question in your profile.')
                return redirect('profile')
            messages.warning(request, 'This transfer requires step-up verification. Answer your security question to continue.')
            return redirect('step-up-otp')

        expires_at = timezone.now() + timedelta(hours=policy['max_share_duration_hours'])
        FileTransfer.objects.create(
            user=request.user,
            file_name=upload_file,
            receiver_user_id=receiver_id,
            remarks=remarks,
            expires_at=expires_at,
        )
        messages.success(request, 'File transfer created.')
        return redirect('filetransfer-list')

# Chat creation and listing
class ChatCreateListView(LoginRequiredMixin, FormMixin, ListView):
    model = Chat
    template_name = 'cloudstorage/chat_list.html'
    form_class = ChatForm
    success_url = reverse_lazy('chat')

    def get(self, request, *args, **kwargs):
        self.object_list = self.get_queryset()
        form = self.get_form()
        context = self.get_context_data(form=form)
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        self.object_list = self.get_queryset()
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        return self.form_invalid(form)

    def form_valid(self, form):
        form.instance.sender_user = self.request.user
        try:
            # Save explicitly so we can add messages and logging reliably
            self.object = form.save()
            # Resolve a display name for the current user without assuming `username` exists
            try:
                sender_name = getattr(self.request.user, 'username', None) or (
                    self.request.user.get_username() if hasattr(self.request.user, 'get_username') else str(self.request.user)
                )
            except Exception:
                sender_name = str(self.request.user)
            receiver_name = None
            try:
                receiver_name = getattr(self.object.receiver_user, 'username', None) or (
                    self.object.receiver_user.get_username() if hasattr(self.object.receiver_user, 'get_username') else str(self.object.receiver_user)
                )
            except Exception:
                receiver_name = str(self.object.receiver_user)
            logging.getLogger(__name__).info(
                "Chat saved: %s -> %s",
                sender_name,
                receiver_name,
            )
            messages.success(self.request, 'Message sent.')
            activity_log_function(
                user=self.request.user,
                activity="SendChat",
                event_request=self.request,
                description=self.object.message
            )
            return redirect(self.get_success_url())
        except Exception:
            logging.getLogger(__name__).exception('Failed to save chat message')
            messages.error(self.request, 'Unable to send message. Try again.')
            return redirect(self.get_success_url())

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        try:
            from django.contrib.auth.models import User
            # Limit receivers to other users (exclude self)
            form.fields['receiver_user'].queryset = User.objects.exclude(id=self.request.user.id).order_by('username')
        except Exception:
            pass
        return form

    def get_queryset(self):
        current_user = self.request.user
        return Chat.objects.filter(Q(sender_user=current_user) | Q(receiver_user=current_user))

# Chat deletion
@login_required
def delete_chat(request):
    chat_id = request.GET.get('id', None)
    chats = Chat.objects.filter(id=chat_id, sender_user=request.user)
    if chats.exists():
        first_chat = chats.first()
        if first_chat is None:
            return redirect('chat')
        delete_message = first_chat.message
        chats.delete()
        activity_log_function(
            user=request.user,
            activity="DeleteChat",
            event_request=request,
            description=delete_message
        )
    return redirect('chat')
