"""
Adaptive Cryptographic Engine
================================
Dynamically selects cipher, key size, and encryption mode based on multiple
factors computed automatically at upload time — no user sensitivity selection
required.

Classification factors
----------------------
1. File extension / content type   → base sensitivity signal
2. File size in bytes              → feasibility of ECIES-DIRECT mode
3. User risk score (0.0 – 1.0)    → derived from account age, activity burst,
                                    and sharing breadth
4. Device context                  → extracted from User-Agent string

Cipher modes selected
---------------------
ECIES-DIRECT  – File content encrypted directly via ECIES (tiny files ≤ 512 B
                with low/medium sensitivity and low risk). No AES step.
AES-128-GCM   – Small/medium files, low sensitivity, low risk, desktop clients.
AES-256-GCM   – Default for everything else (medium/high sensitivity, elevated
                risk, mobile devices, large files).
"""

import re
from datetime import timedelta
from django.utils import timezone


# ---------------------------------------------------------------------------
# Extension → sensitivity look-up tables
# ---------------------------------------------------------------------------

_HIGH_SENSITIVITY_EXTS = {
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'key', 'pem', 'crt', 'cer', 'p12', 'pfx',
    'csv', 'sql', 'db', 'sqlite', 'sqlite3',
    'py', 'js', 'ts', 'java', 'c', 'cpp', 'h',
    'env', 'cfg', 'ini', 'conf', 'config', 'yaml', 'yml', 'toml',
    'txt', 'md', 'log',
    'zip', 'tar', 'gz', 'rar', '7z',
}

_LOW_SENSITIVITY_EXTS = {
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico',
    'mp4', 'avi', 'mkv', 'mov', 'webm',
    'mp3', 'wav', 'ogg', 'flac', 'aac',
}

# ---------------------------------------------------------------------------
# Size thresholds
# ---------------------------------------------------------------------------

# Files at or below this size are candidates for ECIES-DIRECT mode
_ECIES_DIRECT_MAX_BYTES = 512
# Files above this size always use AES-256-GCM regardless of other factors
_AES128_MAX_BYTES = 10_485_760   # 10 MiB

# ---------------------------------------------------------------------------
# Mobile UA pattern
# ---------------------------------------------------------------------------

_MOBILE_UA_RE = re.compile(
    r'Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ext_sensitivity(file_name: str) -> str:
    """Return 'high', 'medium', or 'low' based solely on file extension."""
    ext = file_name.rsplit('.', 1)[-1].lower() if '.' in file_name else ''
    if ext in _HIGH_SENSITIVITY_EXTS:
        return 'high'
    if ext in _LOW_SENSITIVITY_EXTS:
        return 'low'
    return 'medium'


def _is_mobile(user_agent: str) -> bool:
    return bool(_MOBILE_UA_RE.search(user_agent))


# ---------------------------------------------------------------------------
# User risk score computation
# ---------------------------------------------------------------------------

def compute_user_risk_score(user) -> float:
    """
    Compute a 0.0 – 1.0 risk score for *user* from observable signals:

    Factor 1 — Account age
        Very new accounts carry more uncertainty (max +0.4).
    Factor 2 — Activity burst in the last 24 hours
        Unusually high activity volume raises the score (max +0.4).
    Factor 3 — Sharing breadth over the last 7 days
        Sending files to many distinct receivers raises the score (max +0.3).

    Returns
    -------
    float
        Clamped to [0.0, 1.0].
    """
    # Lazy imports to avoid circular dependency with models
    from cloudstorage.models import ActivityLogs, FileTransfer

    score = 0.0

    # ── Factor 1: Account age ─────────────────────────────────────────────
    age_days = (timezone.now() - user.date_joined).days
    if age_days < 1:
        score += 0.4
    elif age_days < 7:
        score += 0.2
    elif age_days < 30:
        score += 0.1

    # ── Factor 2: Activity burst in last 24 hours ─────────────────────────
    since_24h = timezone.now() - timedelta(hours=24)
    recent_count = ActivityLogs.objects.filter(
        user=user, date_created__gte=since_24h
    ).count()
    if recent_count > 50:
        score += 0.4
    elif recent_count > 20:
        score += 0.2
    elif recent_count > 10:
        score += 0.1

    # ── Factor 3: Sharing breadth in last 7 days ──────────────────────────
    since_7d = timezone.now() - timedelta(days=7)
    distinct_receivers = (
        FileTransfer.objects
        .filter(user=user, date_created__gte=since_7d)
        .values('receiver_user')
        .distinct()
        .count()
    )
    if distinct_receivers > 10:
        score += 0.3
    elif distinct_receivers > 5:
        score += 0.15

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Adaptive policy engine  (primary public interface)
# ---------------------------------------------------------------------------

def get_adaptive_policy(
    file_name: str,
    file_size_bytes: int,
    user,
    request,
) -> dict:
    """
    Adaptive policy engine — classifies and selects encryption parameters
    automatically from multiple signals.

    Returns
    -------
    dict with keys:
        cipher_mode              : 'ECIES-DIRECT' | 'AES-128-GCM' | 'AES-256-GCM'
        key_size                 : 16 or 32  (used only for AES modes)
        sensitivity              : 'low' | 'medium' | 'high'  (computed label)
        require_step_up          : bool
        max_share_duration_hours : int
        allow_public_link        : bool
        risk_score               : float
        device_type              : 'mobile' | 'desktop'
        factors                  : dict  (raw classification signals, for logging)
    """
    ua          = request.META.get('HTTP_USER_AGENT', '')
    device_type = 'mobile' if _is_mobile(ua) else 'desktop'
    ext_sens    = _ext_sensitivity(file_name)
    risk_score  = compute_user_risk_score(user)

    anomaly_risk_boost = 0.0
    force_aes_256 = False
    force_step_up = False
    if request is not None:
        anomaly_risk_boost = float(request.session.get('anomaly_last_score', 0.0) or 0.0)
        force_aes_256 = bool(request.session.get('anomaly_force_aes_256', False))
        force_step_up = bool(request.session.get('anomaly_force_step_up', False))
    risk_score = min(1.0, risk_score + anomaly_risk_boost)

    factors = {
        'ext_sensitivity' : ext_sens,
        'file_size_bytes' : file_size_bytes,
        'risk_score'      : round(risk_score, 3),
        'device_type'     : device_type,
    }

    # ── Step 1: Derive overall sensitivity label ──────────────────────────
    if ext_sens == 'high' or risk_score > 0.7:
        sensitivity = 'high'
    elif ext_sens == 'low' and risk_score < 0.4:
        sensitivity = 'low'
    else:
        sensitivity = 'medium'

    # ── Step 2: Select cipher mode ────────────────────────────────────────
    # ECIES-DIRECT: tiny files, low/medium sensitivity, low risk.
    # The raw file bytes become the ECIES DEM plaintext — no separate AES step.
    if (
        file_size_bytes <= _ECIES_DIRECT_MAX_BYTES
        and sensitivity != 'high'
        and risk_score < 0.4
    ):
        cipher_mode = 'ECIES-DIRECT'
        key_size    = 32   # not used for encryption; kept for record consistency

    # AES-128-GCM: small/medium files, low sensitivity, low risk, desktop only.
    elif (
        file_size_bytes <= _AES128_MAX_BYTES
        and sensitivity == 'low'
        and risk_score < 0.4
        and device_type == 'desktop'
        and not force_aes_256
    ):
        cipher_mode = 'AES-128-GCM'
        key_size    = 16

    # AES-256-GCM: everything else.
    else:
        cipher_mode = 'AES-256-GCM'
        key_size    = 32

    # ── Step 3: Access-control parameters from sensitivity ────────────────
    if sensitivity == 'high':
        require_step_up          = True
        max_share_duration_hours = 12
        allow_public_link        = False
    elif sensitivity == 'medium':
        require_step_up          = force_step_up
        max_share_duration_hours = 48
        allow_public_link        = True
    else:   # low
        require_step_up          = force_step_up
        max_share_duration_hours = 72
        allow_public_link        = True

    if force_aes_256 and cipher_mode == 'AES-128-GCM':
        cipher_mode = 'AES-256-GCM'
        key_size = 32

    if force_step_up:
        require_step_up = True

    if force_aes_256:
        max_share_duration_hours = min(max_share_duration_hours, 24)

    return {
        'cipher_mode'             : cipher_mode,
        'key_size'                : key_size,
        'sensitivity'             : sensitivity,
        'require_step_up'         : require_step_up,
        'max_share_duration_hours': max_share_duration_hours,
        'allow_public_link'       : allow_public_link,
        'risk_score'              : risk_score,
        'device_type'             : device_type,
        'factors'                 : factors,
    }


# ---------------------------------------------------------------------------
# Legacy interface — kept for backward compatibility with TransferFileCreate
# ---------------------------------------------------------------------------

def get_crypto_policy(sensitivity: str, user_risk_score: float = 0.0) -> dict:
    """
    Original tier-based policy lookup.
    Still used by TransferFileCreate for share-expiry enforcement on existing
    files where only the stored sensitivity label is available.
    """
    policy = {
        'cipher': 'AES-128',
        'key_size': 16,
        'require_step_up': False,
        'max_share_duration_hours': 72,
        'allow_public_link': True,
    }
    if sensitivity == 'high' or user_risk_score > 0.7:
        policy.update({
            'cipher': 'AES-256',
            'key_size': 32,
            'require_step_up': True,
            'max_share_duration_hours': 12,
            'allow_public_link': False,
        })
    elif sensitivity == 'medium' or user_risk_score > 0.4:
        policy.update({
            'cipher': 'AES-256',
            'key_size': 32,
            'require_step_up': False,
            'max_share_duration_hours': 48,
            'allow_public_link': True,
        })
    return policy


# ---------------------------------------------------------------------------
# Backward-compatible classification helper
# ---------------------------------------------------------------------------

def classify_file(file_name: str) -> str:
    """Extension-only classification. Kept for backward compatibility."""
    return _ext_sensitivity(file_name)


# ---------------------------------------------------------------------------
# Sensitivity metadata helpers (used by models + templates)
# ---------------------------------------------------------------------------

SENSITIVITY_CHOICES = [
    ('low',    'Low'),
    ('medium', 'Medium'),
    ('high',   'High'),
]

SENSITIVITY_LABELS = {
    'low':    'Low',
    'medium': 'Medium',
    'high':   'High',
}

SENSITIVITY_BADGE_CLASSES = {
    'low':    'sensitivity-low',
    'medium': 'sensitivity-medium',
    'high':   'sensitivity-high',
}
