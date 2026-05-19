from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from .crypto_policy import SENSITIVITY_CHOICES

GENDER_CHOICES = (
    ('Male', 'Male'),
    ('Female', 'Female'),
)

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile = models.CharField(max_length=20, blank=True, null=True)
    # Security question for step-up authentication
    security_question = models.CharField(max_length=255, null=True, blank=True, help_text='Security question used for step-up verification.')
    security_answer_hash = models.CharField(max_length=128, null=True, blank=True, help_text='Salted password hash of the security answer.')
    # (TOTP fields removed — migration will drop the columns)
    # Backup (recovery) codes stored as list of {hash, used} entries
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    address = models.CharField(max_length=200, blank=True, null=True)
    city = models.CharField(max_length=200, blank=True, null=True)
    state = models.CharField(max_length=200, blank=True, null=True)
    pin = models.CharField(max_length=10, blank=True, null=True)
    country = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} Profile"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class Contact(models.Model):
    name = models.CharField(max_length=150)
    email = models.CharField(max_length=150)
    mobile = models.CharField(max_length=30)
    description = models.TextField(max_length=1050)
    status = models.PositiveSmallIntegerField(default=1)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.email})"

class UploadFile(models.Model):
    file_name = models.CharField(max_length=255)
    file_password = models.CharField(max_length=100, null=True, blank=True)
    file_path = models.FileField(upload_to='upload/', verbose_name="Upload File", null=True, blank=True)
    encrypted_data = models.BinaryField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    status = models.PositiveSmallIntegerField(default=1)
    file_name_with_ext = models.CharField(max_length=255, null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    # --- Context-Aware Cryptographic Engine fields ---
    sensitivity = models.CharField(
        max_length=10,
        choices=SENSITIVITY_CHOICES,
        default='medium',
        help_text="Auto-classified sensitivity level based on file type.",
    )
    # 12-byte GCM nonce stored alongside ciphertext; NULL for legacy ECB files
    nonce = models.BinaryField(null=True, blank=True)
    # Records which cipher was used so the download view can choose the right path
    cipher_used = models.CharField(max_length=20, default='AES-128-ECB')
    # True when the crypto policy requires a step-up confirmation before download
    require_step_up = models.BooleanField(default=False)

    # --- Adaptive Cryptographic Engine — ECC key-wrapping fields ---
    # Wrapped (ECC-encrypted) Data Encryption Key; NULL for legacy password-based files
    wrapped_dek = models.BinaryField(null=True, blank=True)
    # 12-byte nonce used when AES-GCM-wrapping the DEK
    wrap_nonce = models.BinaryField(null=True, blank=True)
    # PEM-encoded ephemeral EC public key needed to reconstruct the ECDH shared secret
    ephemeral_public_key = models.TextField(null=True, blank=True)
    # PBKDF2-SHA256 hash of the per-file password (for gate check before decryption)
    file_password_hash = models.CharField(max_length=128, null=True, blank=True)
    # Original plaintext file size — used by the adaptive engine for cipher selection
    file_size_bytes = models.PositiveIntegerField(
        null=True, blank=True,
        help_text="Plaintext file size in bytes (recorded at upload time)."
    )

    def __str__(self):
        return self.file_name

class ActivityLogs(models.Model):
    ACTIVITY_LOGS = (
        ('Login', 'Login'),
        ('Logout', 'Logout'),
        ('FileUpload', 'FileUpload'),
        ('DeleteFile', 'DeleteFile'),
        ('FileTransfer', 'FileTransfer'),
        ('UpdateProfile', 'UpdateProfile'),
        ('ChangePassword', 'ChangePassword'),
        ('SendChat', 'SendChat'),
        ('DeleteChat', 'DeleteChat'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="activity_log_user")
    activity_log = models.CharField(max_length=50, choices=ACTIVITY_LOGS)
    ip_address = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    description = models.TextField(max_length=1000, null=True, blank=True)
    event_context = models.JSONField(default=dict, blank=True)
    anomaly_score = models.FloatField(null=True, blank=True)
    anomaly_severity = models.CharField(max_length=20, null=True, blank=True)
    anomaly_action = models.CharField(max_length=50, null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.activity_log}"


class AnomalyEvent(models.Model):
    EVENT_TYPES = (
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('upload', 'Upload'),
        ('download', 'Download'),
        ('transfer', 'Transfer'),
        ('profile_update', 'Profile Update'),
        ('chat', 'Chat'),
        ('system', 'System'),
    )

    SEVERITY_LEVELS = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    actor_username = models.CharField(max_length=150, null=True, blank=True)
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    source_ip = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    risk_score = models.FloatField(default=0.0)
    anomaly_score = models.FloatField(default=0.0)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='low')
    recommended_action = models.CharField(max_length=50, default='monitor')
    action_taken = models.CharField(max_length=50, default='monitor')
    details = models.JSONField(default=dict, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        target = self.user.username if self.user else self.actor_username or 'anonymous'
        return f"{target} - {self.event_type} - {self.severity}"

class FileTransfer(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="file_sender_user")
    file_name = models.ForeignKey(UploadFile, on_delete=models.CASCADE)
    remarks = models.CharField(max_length=250)
    receiver_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="file_receiver_user")
    # Expiry enforced by the crypto policy (max_share_duration_hours).
    # NULL means no expiry (legacy transfers created before this feature).
    expires_at = models.DateTimeField(null=True, blank=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    def is_expired(self):
        if self.expires_at is None:
            return False
        from django.utils import timezone
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.user.username} to {self.receiver_user.username}"

class Chat(models.Model):
    sender_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="chat_sender_user")
    message = models.CharField(max_length=250)
    receiver_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="chat_receiver_user")
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender_user.username} to {self.receiver_user.username}"


class UserECCKey(models.Model):
    """
    Stores the SECP256R1 ECC key pair for each user.
    The private key is stored server-side (encrypted at rest by Django's
    database layer) so that ECC decryption can happen transparently during
    file downloads — the user only needs to supply their file password.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='ecc_key')
    public_key_pem = models.TextField(help_text="PEM-encoded SECP256R1 public key.")
    private_key_pem = models.TextField(
        help_text="PEM-encoded SECP256R1 private key (no passphrase).",
        blank=True, null=True,
    )
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} — ECC Key Pair"
