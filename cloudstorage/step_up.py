from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
import hashlib

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from .models import Profile

# Session key for TTL of an already completed step-up
STEP_UP_VERIFIED_UNTIL_KEY = 'step_up_verified_until'


def has_recent_verification(request) -> bool:
    verified_until = request.session.get(STEP_UP_VERIFIED_UNTIL_KEY)
    if not verified_until:
        return False
    verified_until_dt = datetime.fromisoformat(verified_until)
    if timezone.is_naive(verified_until_dt):
        verified_until_dt = timezone.make_aware(verified_until_dt, dt_timezone.utc)
    return timezone.now() < verified_until_dt


def mark_verified(request, minutes: int | None = None) -> None:
    ttl_minutes = minutes or getattr(settings, 'STEP_UP_OTP_TTL_MINUTES', 10)
    verified_until = timezone.now() + timedelta(minutes=ttl_minutes)
    request.session[STEP_UP_VERIFIED_UNTIL_KEY] = verified_until.isoformat()


def start_security_challenge(request, user):
    """Return the user's configured security question (or None)."""
    profile = Profile.objects.filter(user=user).first()
    if not profile:
        return None
    return profile.security_question


def verify_security_answer_and_activate(request, user, submitted_answer: str) -> tuple[bool, str]:
    submitted = (submitted_answer or '').strip()
    if not submitted:
        return False, 'Enter the answer to your security question.'
    profile = Profile.objects.filter(user=user).first()
    if not profile or not profile.security_answer_hash:
        return False, 'No security question on record. Please set one in your profile.'
    stored_hash = profile.security_answer_hash
    verified = check_password(submitted, stored_hash)
    if not verified and len(stored_hash) == 64:
        legacy_hash = hashlib.sha256(submitted.encode('utf-8')).hexdigest()
        verified = legacy_hash == stored_hash
        if verified:
            profile.security_answer_hash = make_password(submitted)
            profile.save(update_fields=['security_answer_hash'])
    if verified:
        mark_verified(request)
        return True, ''
    return False, 'The answer is incorrect.'