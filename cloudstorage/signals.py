from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.contrib.auth.models import User
from datetime import timedelta
from django.utils import timezone

from .anomaly_detection import record_and_apply
from .models import ActivityLogs, AnomalyEvent


@receiver(user_logged_in)
def handle_user_logged_in(sender, request, user, **kwargs):
    source_ip = request.META.get('REMOTE_ADDR', '') if request else ''
    user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
    recent_window = timezone.now() - timedelta(minutes=30)

    recent_failed_attempts = AnomalyEvent.objects.filter(
        user=user,
        event_type='login_failed',
        date_created__gte=recent_window,
    ).count()

    recent_ips = list(
        ActivityLogs.objects.filter(user=user)
        .exclude(ip_address='')
        .values_list('ip_address', flat=True)
        .distinct()[:5]
    )
    ip_changed = bool(source_ip and recent_ips and source_ip not in recent_ips)

    ActivityLogs.objects.create(
        user=user,
        activity_log='Login',
        ip_address=source_ip,
        user_agent=user_agent,
        description='Successful login',
        event_context={'event_type': 'login_success'},
    )

    if recent_failed_attempts >= 3:
        request.session['anomaly_force_step_up'] = True
        request.session['login_step_up_required'] = True
        request.session['login_step_up_reason'] = 'multiple_failed_logins'
    if ip_changed:
        request.session['anomaly_force_step_up'] = True
        request.session['login_network_warning'] = True
        request.session['login_step_up_reason'] = 'new_ip_or_network'

    record_and_apply(
        user=user,
        request=request,
        event_type='login_success',
        details={
            'source': 'signal',
            'recent_failed_attempts': recent_failed_attempts,
            'ip_changed': ip_changed,
            'force_step_up': recent_failed_attempts >= 3 or ip_changed,
        },
    )


@receiver(user_login_failed)
def handle_user_login_failed(sender, credentials, request, **kwargs):
    username = credentials.get('username') if credentials else None
    matched_user = User.objects.filter(username=username).first() if username else None
    if matched_user is not None or username:
        if matched_user is not None and request is not None:
            ActivityLogs.objects.create(
                user=matched_user,
                activity_log='Login',
                ip_address=request.META.get('REMOTE_ADDR', ''),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                description='Failed login attempt',
                event_context={'event_type': 'login_failed', 'actor_username': username},
                anomaly_score=0.5,
                anomaly_severity='medium',
                anomaly_action='step_up_auth',
            )
        record_and_apply(
            user=matched_user,
            request=request,
            event_type='login_failed',
            details={
                'actor_username': username,
                'source': 'signal',
                'suppress_user_notification': True,
            },
        )


@receiver(user_logged_out)
def handle_user_logged_out(sender, request, user, **kwargs):
    if user is None or request is None:
        return
    ActivityLogs.objects.create(
        user=user,
        activity_log='Logout',
        ip_address=request.META.get('REMOTE_ADDR', ''),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        description='User logged out',
        event_context={'event_type': 'logout'},
    )