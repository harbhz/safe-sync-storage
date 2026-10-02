# SafeSync Storage

**SafeSync Storage** is a secure cloud storage and encrypted file synchronization platform built on Django. It implements dual-layer client/server cryptography, context-aware cipher selection, step-up authentication, and real-time anomaly detection.

---

## Key Features

* **Adaptive Cryptographic Engine:**
  * **Dual-Layer Protection:** Files are protected by a user-chosen password gate (PBKDF2-SHA256) and an asymmetric ECC SECP256R1 (P-256) ECIES key-wrapping layer.
  * **Zero-Knowledge Storage:** Plaintext files are never written to disk in media directories. Ciphertext and wrapped Data Encryption Keys (DEKs) are stored securely.
  * **Context-Aware Cipher Selection:** Uploads are dynamically evaluated using file type, file size, user risk metrics, and client device context to choose between AES-128-GCM, AES-256-GCM, or ECIES-Direct encryption.
* **Security & Adaptive Access:**
  * **Anomaly Detection Engine:** Analyzes login patterns, failed attempts, IP velocity, and sharing behavior to flag suspicious activities and adjust security enforcement.
  * **Step-Up Authentication:** Enforces security challenges before allowing sensitive actions (like downloading sensitive documents or responding to risk spikes).
  * **Secure User-to-User Transfers:** Files can be shared between registered users with policy-enforced expiration timestamps.
  * **Activity Logs & Anomaly Dashboard:** Audits user activities and system security events.

---

## Technology Stack

* **Backend:** Python 3.10+, Django 4.2 through 5.2
* **Cryptography:** `cryptography` (SECP256R1 ECC, ECDH, HKDF-SHA256, AES-GCM)
* **Database:** SQLite (default / development) or MySQL (production)
* **Frontend:** Responsive HTML5 / CSS3 / JavaScript (Skel framework)

---

## Getting Started

### 1. Prerequisites

* Python 3.10 or higher
* `pip` and `virtualenv`

### 2. Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/harbhz/safe-sync-storage.git
   cd safe-sync-storage
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to configure your `DJANGO_SECRET_KEY`, database credentials, and debug settings.

5. **Apply database migrations:**
   ```bash
   python manage.py migrate
   ```

6. **Create an administrative user:**
   ```bash
   python manage.py createsuperuser
   ```

7. **Collect static assets (production):**
   ```bash
   python manage.py collectstatic --noinput
   ```

8. **Start the development server:**
   ```bash
   python manage.py runserver
   ```
   Visit `http://127.0.0.1:8000/` in your browser.

---

## Running Tests

Execute the automated test suite with:

```bash
python manage.py test
```

## Deploying to Render

The repository includes [render.yaml](render.yaml) for a Render web service and
PostgreSQL database. Create a Blueprint from the repository, then set
`ALLOWED_HOSTS` to the Render hostname and `CSRF_TRUSTED_ORIGINS` to its HTTPS
origin, for example `https://safe-sync-storage.onrender.com`.

The web service runs migrations and collects static files during the build. Its
start command uses Gunicorn, and uploaded files are stored as encrypted database
content rather than on Render's ephemeral filesystem.

---

## Production Security Checklist

* Set `DJANGO_DEBUG=False` in `.env`.
* Set a unique, high-entropy `DJANGO_SECRET_KEY` in `.env`.
* Specify allowed domain names in `ALLOWED_HOSTS`.
* Configure an external database (e.g., MySQL or PostgreSQL).
* Serve static files via Nginx/Caddy or WhiteNoise.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
