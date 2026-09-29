e.js API provides appointment booking, consent-based donor profiles and preliminary matching, one-time medicine reminders, and patient health records. It is a development starter, **not a certified clinical system**.

## Run

Requires Node.js 22.5 or newer (uses the built-in `node:sqlite` module). Set a JWT secret (at least 32 bytes) and a 32-byte AES key written as 64 hexadecimal characters. Keep both out of source control:

```powershell
$env:JWT_SECRET = "replace-with-a-random-secret-of-at-least-32-bytes"
$env:RECORD_ENCRYPTION_KEY = "replace-with-64-hexadecimal-characters"
$env:DB_PATH = "healthcare.sqlite"
npm install
npm test
npm start
```

Generate a record key with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. Back up the encryption key securely; records cannot be decrypted without it. SQLite is created at `DB_PATH` (or `healthcare.sqlite` in this folder).

Public registration accepts patient and donor roles only. Clinician and coordinator accounts must be provisioned through a trusted administrative process. All `/api` endpoints except health check, registration, and login require a bearer token returned by login.

## Endpoints

- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/users/me`
- `POST /api/appointments`, `GET /api/appointments`, `PATCH /api/appointments/:id`
- `PUT /api/donor-profile`, `GET /api/donors/matches?type=blood&bloodGroup=A%2B`
- `POST /api/reminders`, `GET /api/reminders`, `PATCH /api/reminders/:id`
- `POST /api/records`, `GET /api/records`, `GET /api/records/:id`
- `POST /api/records/access`, `DELETE /api/records/access/:clinicianId`

Appointment times and reminder `scheduledAt` values must be valid date-time strings; use ISO 8601 with a timezone. A donor must explicitly set `consented: true` before appearing in matching results. Organ matching only filters by organ interest and ABO group; it is not a transplant match. Blood results are preliminary red-cell compatibility only.

Health-record bodies are encrypted at rest with AES-256-GCM; patient-granted clinicians can read them, and patients can revoke that access. Other identifying fields and the SQLite database are not encrypted by this application.

## Important deployment limits

This starter does not provide video calls, send reminder notifications, verify clinician credentials or donor consent, or integrate with a transplant registry. It does not implement appointment availability calendars, audit logging, key rotation, backups, or jurisdiction-specific healthcare compliance. Before handling real patient data, add those controls, secure transport and hosting, encrypted storage/backups, operational access controls, and clinical/legal review. Matching results must never be treated as medical advice or a substitute for clinical testing.
# Healthcare API starter

This Nod