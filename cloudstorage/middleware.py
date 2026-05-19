from django.shortcuts import redirect
from django.urls import resolve

from .step_up import has_recent_verification


class StepUpRequiredMiddleware:
    """Redirect users to the step-up verification page when a step-up is required
    and the session does not have a recent verification. This prevents navigation
    to other parts of the app until step-up is completed.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Allow unauthenticated users to proceed
        if not getattr(request, 'user', None) or not request.user.is_authenticated:
            return self.get_response(request)

        # Allow safe paths that must remain accessible
        path = request.path
        allowed_prefixes = (
            '/static/',
            '/upload/',
            '/admin/',
        )
        allowed_exact = (
            '/step-up-otp/',
            '/login/',
            '/logout/',
            '/register/',
            '/password/',
            '/thanks/',
            '/contact/',
        )
        if any(path.startswith(p) for p in allowed_prefixes) or path in allowed_exact:
            return self.get_response(request)

        # If session indicates a step-up requirement (legacy flags or next_url) and
        # there is no recent verification, redirect to step-up page.
        session = request.session
        needs_step_up = bool(
            session.get('login_step_up_required')
            or session.get('anomaly_force_step_up')
            or session.get('login_network_warning')
            or session.get('step_up_next_url')
        )
        if needs_step_up and not has_recent_verification(request):
            # preserve original target if not already set
            if not session.get('step_up_return_url'):
                session['step_up_return_url'] = path
            return redirect('step-up-otp')

        return self.get_response(request)
