from datetime import timedelta

from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.middleware import SessionMiddleware
from django.core import mail
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase
from django.test.utils import override_settings
from django.utils import timezone

from .anomaly_detection import apply_response, evaluate_event
from .crypto_policy import get_adaptive_policy
from .models import ActivityLogs, AnomalyEvent, FileTransfer, UploadFile
from .signals import handle_user_login_failed, handle_user_logged_in
from .step_up import start_security_challenge, verify_security_answer_and_activate
from .models import Profile
import hashlib


def _attach_session(request):
    middleware = SessionMiddleware(lambda req: HttpResponse())
    middleware.process_request(request)
    request.session.save()
    return request


class AnomalyDetectionTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='alice', password='testpass123')

    def test_repeated_failed_logins_raise_severity(self):
        request = _attach_session(
            self.factory.get('/', REMOTE_ADDR='10.0.0.9', HTTP_USER_AGENT='TestAgent/1.0')
        )
        for _ in range(3):
            handle_user_login_failed(
                sender=None,
                credentials={'username': 'alice'},
                request=request,
            )

        self.assertEqual(
            AnomalyEvent.objects.filter(user=self.user, event_type='login_failed').count(),
            3,
        )

        decision = evaluate_event(
            self.user,
            request,
            'login_failed',
            {'actor_username': 'alice', 'source': 'signal'},
        )

        self.assertEqual(decision.severity, 'high')
        self.assertGreaterEqual(decision.score, 0.7)

    def test_successful_login_after_failures_sets_step_up_flag(self):
        request = _attach_session(
            self.factory.get('/', REMOTE_ADDR='10.0.0.9', HTTP_USER_AGENT='TestAgent/1.0')
        )
        for _ in range(3):
            handle_user_login_failed(
                sender=None,
                credentials={'username': 'alice'},
                request=request,
            )

        handle_user_logged_in(sender=None, request=request, user=self.user)

        self.assertTrue(request.session['anomaly_force_step_up'])
        self.assertTrue(request.session['login_step_up_required'])
        self.assertEqual(request.session['login_step_up_reason'], 'multiple_failed_logins')

    def test_successful_login_from_new_ip_sets_network_warning(self):
        old_request = _attach_session(
            self.factory.get('/', REMOTE_ADDR='10.0.0.1', HTTP_USER_AGENT='TestAgent/1.0')
        )
        ActivityLogs.objects.create(
            user=self.user,
            activity_log='Login',
            ip_address='10.0.0.1',
            user_agent='TestAgent/1.0',
            description='Successful login',
            event_context={'event_type': 'login_success'},
        )

        new_request = _attach_session(
            self.factory.get('/', REMOTE_ADDR='203.0.113.99', HTTP_USER_AGENT='TestAgent/1.0')
        )
        handle_user_logged_in(sender=None, request=new_request, user=self.user)

        self.assertTrue(new_request.session['login_network_warning'])
        self.assertEqual(new_request.session['login_step_up_reason'], 'new_ip_or_network')

    def test_apply_response_tightens_transfers_and_flags_session(self):
        request = _attach_session(
            self.factory.get('/', REMOTE_ADDR='10.0.0.10', HTTP_USER_AGENT='TestAgent/2.0')
        )

        upload = UploadFile.objects.create(
            file_name='secret.txt',
            user=self.user,
            file_name_with_ext='secret.txt',
            require_step_up=False,
        )
        transfer = FileTransfer.objects.create(
            user=self.user,
            file_name=upload,
            remarks='share',
            receiver_user=self.user,
            expires_at=timezone.now() + timedelta(days=2),
        )

        decision = evaluate_event(self.user, request, 'transfer', {'source': 'manual'})
        decision = decision.__class__(
            score=0.8,
            severity='high',
            recommended_action='quarantine',
            action_taken='force_step_up_and_quarantine',
            notes=['test'],
        )
        apply_response(self.user, request, decision, upload_files=[upload], transfers=[transfer])

        upload.refresh_from_db()
        transfer.refresh_from_db()

        self.assertTrue(request.session['anomaly_force_aes_256'])
        self.assertTrue(request.session['anomaly_force_step_up'])
        self.assertTrue(upload.require_step_up)
        self.assertIsNotNone(transfer.expires_at)
        self.assertLess(transfer.expires_at, timezone.now() + timedelta(days=2))

    def test_anomaly_forces_aes256_in_adaptive_policy(self):
        request = _attach_session(
            self.factory.get('/', REMOTE_ADDR='10.0.0.11', HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0)')
        )
        request.session['anomaly_force_aes_256'] = True
        request.session['anomaly_force_step_up'] = True
        request.session.save()

        policy = get_adaptive_policy('notes.txt', 100, self.user, request)

        self.assertEqual(policy['cipher_mode'], 'AES-256-GCM')
        self.assertTrue(policy['require_step_up'])


class StepUpFlowTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='bob',
            email='bob@example.com',
            password='testpass123',
        )

    def test_start_challenge_sends_code_and_verifies_code(self):
        request = _attach_session(self.factory.get('/'))
        # configure a security question on the profile
        profile, _ = Profile.objects.get_or_create(user=self.user)
        profile.security_question = 'What is your pet name?'
        profile.security_answer_hash = make_password('fluffy')
        profile.save()
        question = start_security_challenge(request, self.user)
        self.assertIsNotNone(question)
        # verify with correct answer
        verified, error_message = verify_security_answer_and_activate(request, self.user, 'fluffy')
        self.assertTrue(verified)
        self.assertEqual(error_message, '')

    def test_verify_challenge_rejects_incorrect_code(self):
        request = _attach_session(self.factory.get('/'))
        # configure a security question on the profile
        profile, _ = Profile.objects.get_or_create(user=self.user)
        profile.security_question = 'What is your pet name?'
        profile.security_answer_hash = make_password('fluffy')
        profile.save()
        verified, error_message = verify_security_answer_and_activate(request, self.user, 'wrong')
        self.assertFalse(verified)
        self.assertIn('incorrect', error_message.lower())


class ZeroKnowledgeUploadTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='carol',
            email='carol@example.com',
            password='testpass123',
        )
        profile, _ = Profile.objects.get_or_create(user=self.user)
        profile.security_question = 'Favorite color?'
        profile.security_answer_hash = make_password('blue')
        profile.save()
        self.client.login(username='carol', password='testpass123')
        session = self.client.session
        session['step_up_verified_until'] = (timezone.now() + timedelta(minutes=30)).isoformat()
        session.save()

    def test_upload_encrypts_and_prevents_plaintext_on_disk(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        payload = b"Top secret classified content 12345"
        uploaded_file = SimpleUploadedFile("secret.txt", payload, content_type="text/plain")

        response = self.client.post('/addfile/', {
            'file_name': 'Secret File',
            'file_path': uploaded_file,
            'file_password': 'testpassword123',
        }, follow=True)

        self.assertEqual(response.status_code, 200)

        upload_file = UploadFile.objects.filter(user=self.user, file_name='Secret File').first()
        self.assertIsNotNone(upload_file)

        # Architectural improvement check: plaintext was not stored on disk
        self.assertFalse(bool(upload_file.file_path))

        # Encrypted content or wrapped DEK is stored
        self.assertTrue(bool(upload_file.wrapped_dek))

        # Test download and decryption with correct password
        dl_response = self.client.post(f'/downloadfile/{upload_file.pk}', {
            'file_password': 'testpassword123',
        })
        self.assertEqual(dl_response.status_code, 200)
        self.assertEqual(dl_response.content, payload)

        # Test download with incorrect password fails
        bad_response = self.client.post(f'/downloadfile/{upload_file.pk}', {
            'file_password': 'wrongpassword',
        })
        self.assertEqual(bad_response.status_code, 200)
        self.assertNotEqual(bad_response.content, payload)