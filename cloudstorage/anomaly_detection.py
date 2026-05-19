from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from django.contrib import messages
from django.utils import timezone


@dataclass(frozen=True)
class AnomalyDecision:
    score: float
    severity: str
    recommended_action: str
    action_taken: str
    notes: list[str] = field(default_factory=list)


def _clamp(value: float) -> float:
    return max(0.0, min(value, 1.0))


def _severity_from_score(score: float) -> str:
    if score >= 0.7:
        return 'high'
    if score >= 0.4:
        return 'medium'
    return 'low'


def _recommended_action(severity: str) -> str:
    if severity == 'high':
        return 'quarantine'
    if severity == 'medium':
        return 'step_up_auth'
    return 'monitor'


def evaluate_event(user, request, event_type: str, details: dict[str, Any] | None = None) -> AnomalyDecision:
    from .models import ActivityLogs, AnomalyEvent, FileTransfer

    details = details or {}
    now = timezone.now()
    source_ip = request.META.get('REMOTE_ADDR', '') if request else ''
    user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
    username = getattr(user, 'username', None) or details.get('actor_username')

    score = 0.0
    notes: list[str] = []

    recent_failed_window = now - timedelta(minutes=30)
    recent_activity_window = now - timedelta(hours=24)
    recent_share_window = now - timedelta(days=7)

    failed_filter = {
        'event_type': 'login_failed',
        'date_created__gte': recent_failed_window,
    }
    if user is not None:
        failed_filter['user'] = user
    elif username:
        failed_filter['actor_username'] = username

    failed_attempts = AnomalyEvent.objects.filter(**failed_filter).count()
    if failed_attempts >= 5:
        score += 0.45
        notes.append('Repeated failed logins detected.')
    elif failed_attempts >= 3:
        score += 0.3
        notes.append('Multiple failed logins detected.')
    elif failed_attempts >= 1 and event_type == 'login_success':
        score += 0.15
        notes.append('Recent failed login prior to success.')

    if user is not None:
        recent_activity_count = ActivityLogs.objects.filter(
            user=user,
            date_created__gte=recent_activity_window,
        ).count()
        if recent_activity_count >= 30:
            score += 0.2
            notes.append('Burst of recent activity observed.')

        share_count = FileTransfer.objects.filter(
            user=user,
            date_created__gte=recent_share_window,
        ).count()
        if share_count >= 8:
            score += 0.25
            notes.append('Unusual file-sharing burst detected.')
        elif share_count >= 4:
            score += 0.1

        recent_agents = list(
            ActivityLogs.objects.filter(
                user=user,
                user_agent__isnull=False,
            ).exclude(user_agent='').values_list('user_agent', flat=True).distinct()[:5]
        )
        if user_agent and recent_agents and user_agent not in recent_agents:
            score += 0.2
            notes.append('New user agent detected.')

        recent_ips = list(
            ActivityLogs.objects.filter(
                user=user,
                ip_address__isnull=False,
            ).exclude(ip_address='').values_list('ip_address', flat=True).distinct()[:5]
        )
        if source_ip and recent_ips and source_ip not in recent_ips:
            score += 0.15
            notes.append('New source IP detected.')

    if event_type == 'login_failed':
        score += 0.5
        if failed_attempts >= 1:
            score += 0.15
        if failed_attempts >= 3:
            score += 0.1
        notes.append('Failed login event.')
    elif event_type == 'transfer':
        score += 0.1
    elif event_type == 'download':
        score += 0.05

    if details.get('force_step_up'):
        score += 0.2
    if details.get('force_aes_256'):
        score += 0.2

    score = _clamp(score)
    severity = _severity_from_score(score)
    recommended_action = _recommended_action(severity)

    if severity == 'high':
        action_taken = 'force_step_up_and_quarantine'
    elif severity == 'medium':
        action_taken = 'force_step_up'
    else:
        action_taken = 'monitor'

    return AnomalyDecision(
        score=score,
        severity=severity,
        recommended_action=recommended_action,
        action_taken=action_taken,
        notes=notes,
    )


def persist_event(user, request, event_type: str, details: dict[str, Any] | None = None) -> AnomalyDecision:
    from .models import AnomalyEvent

    decision = evaluate_event(user, request, event_type, details)
    source_ip = request.META.get('REMOTE_ADDR', '') if request else ''
    user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
    details = details or {}
    actor_username = getattr(user, 'username', None) or details.get('actor_username')

    AnomalyEvent.objects.create(
        user=user,
        actor_username=actor_username,
        event_type=event_type,
        source_ip=source_ip,
        user_agent=user_agent,
        risk_score=float(details.get('risk_score', 0.0)),
        anomaly_score=decision.score,
        severity=decision.severity,
        recommended_action=decision.recommended_action,
        action_taken=decision.action_taken,
        details=details,
    )
    return decision


def apply_response(user, request, decision: AnomalyDecision, upload_files=None, transfers=None):
    upload_files = upload_files or []
    transfers = transfers or []
    notify_user = True
    if request is not None:
        notify_user = bool(request.session.get('anomaly_notify_user', True))

    if request is not None:
        request.session['anomaly_last_score'] = decision.score
        request.session['anomaly_severity'] = decision.severity

    if decision.severity == 'high' and request is not None:
        request.session['anomaly_force_aes_256'] = True
        request.session['anomaly_force_step_up'] = True
    elif decision.severity == 'medium' and request is not None:
        request.session['anomaly_force_step_up'] = True

    if decision.severity in {'medium', 'high'}:
        for upload_file in upload_files:
            if upload_file.require_step_up is False:
                upload_file.require_step_up = True
                upload_file.save(update_fields=['require_step_up', 'date_updated'])

        for transfer in transfers:
            if transfer.expires_at is not None:
                tightened = timezone.now() + timedelta(hours=6 if decision.severity == 'high' else 24)
                if tightened < transfer.expires_at:
                    transfer.expires_at = tightened
                    transfer.save(update_fields=['expires_at', 'date_updated'])

    if notify_user and request is not None and hasattr(request, '_messages'):
        if decision.severity == 'high':
            messages.error(request, 'Anomalous activity detected. Step-up authentication and tighter sharing controls were applied.')
        elif decision.severity == 'medium':
            messages.warning(request, 'Suspicious activity detected. Step-up authentication has been enabled for this session.')

    return decision


def record_and_apply(user, request, event_type: str, details: dict[str, Any] | None = None, upload_files=None, transfers=None):
    details = details or {}
    if request is not None and details.get('suppress_user_notification'):
        request.session['anomaly_notify_user'] = False
    decision = persist_event(user, request, event_type, details)
    response = apply_response(user, request, decision, upload_files=upload_files, transfers=transfers)
    if request is not None:
        request.session.pop('anomaly_notify_user', None)
    return response