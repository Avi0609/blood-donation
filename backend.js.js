
class SyncDatabase {
  constructor(filename) {
    this.connection = new DatabaseSync(filename);
  }

  pragma(statement) {
    this.connection.exec(`PRAGMA ${statement}`);
  }

  exec(statement) {
    this.connection.exec(statement);
  }

  prepare(statement) {
    return this.connection.prepare(statement);
  }

  transaction(callback) {
    const run = (beginStatement) => {
      this.connection.exec(beginStatement);
      try {
        const result = callback();
        this.connection.exec("COMMIT");
        return result;
      } catch (error) {
        this.connection.exec("ROLLBACK");
        throw error;
      }
    };
    const transaction = () => run("BEGIN");
    transaction.immediate = () => run("BEGIN IMMEDIATE");
    return transaction;
  }
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function requireEnvironment() {
  const jwtSecret = process.env.JWT_SECRET;
  const encryptionKey = process.env.RECORD_ENCRYPTION_KEY;

  if (!jwtSecret || Buffer.byteLength(jwtSecret) < 32) {
    throw new Error("JWT_SECRET must contain at least 32 bytes.");
  }
  if (!encryptionKey || !/^[0-9a-fA-F]{64}$/.test(encryptionKey)) {
    throw new Error("RECORD_ENCRYPTION_KEY must be a 64-character hexadecimal key.");
  }

  return { jwtSecret, encryptionKey: Buffer.from(encryptionKey, "hex") };
}

function createDatabase(filename = process.env.DB_PATH || path.join(__dirname, "healthcare.sqlite")) {
  const db = new SyncDatabase(filename);
  db.pragma("foreign_keys = ON");
  db.pragma("journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('patient', 'donor', 'clinician', 'coordinator')),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS appointments (
      id TEXT PRIMARY KEY,
      patient_id TEXT NOT NULL REFERENCES users(id),
      clinician_id TEXT NOT NULL REFERENCES users(id),
      starts_at TEXT NOT NULL,
      ends_at TEXT NOT NULL,
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'confirmed',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS appointments_clinician_time
      ON appointments(clinician_id, starts_at, ends_at);
    CREATE INDEX IF NOT EXISTS appointments_patient_time
      ON appointments(patient_id, starts_at);

    CREATE TABLE IF NOT EXISTS donor_profiles (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
      blood_group TEXT NOT NULL,
      donor_type TEXT NOT NULL CHECK (donor_type IN ('blood', 'organ', 'both')),
      organs_json TEXT NOT NULL DEFAULT '[]',
      available INTEGER NOT NULL DEFAULT 1,
      consented INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reminders (
      id TEXT PRIMARY KEY,
      patient_id TEXT NOT NULL REFERENCES users(id),
      medication TEXT NOT NULL,
      instructions TEXT NOT NULL DEFAULT '',
      scheduled_at TEXT NOT NULL,
      completed INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS reminders_patient_time
      ON reminders(patient_id, scheduled_at, completed);

    CREATE TABLE IF NOT EXISTS health_records (
      id TEXT PRIMARY KEY,
      patient_id TEXT NOT NULL REFERENCES users(id),
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      body_ciphertext TEXT NOT NULL,
      body_iv TEXT NOT NULL,
      body_tag TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS health_records_patient
      ON health_records(patient_id, updated_at);

    CREATE TABLE IF NOT EXISTS record_access (
      patient_id TEXT NOT NULL REFERENCES users(id),
      clinician_id TEXT NOT NULL REFERENCES users(id),
      granted_at TEXT NOT NULL,
      PRIMARY KEY (patient_id, clinician_id)
    );
  `);
  return db;
}

function encryptRecord(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    body_ciphertext: ciphertext.toString("base64"),
    body_iv: iv.toString("base64"),
    body_tag: cipher.getAuthTag().toString("base64"),
  };
}

function decryptRecord(record, key) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(record.body_iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(record.body_tag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(record.body_ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}

function isValidDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function bloodDonorCanDonate(donor, recipient) {
  const compatibleRecipients = {
    "O-": BLOOD_GROUPS,
    "O+": ["O+", "A+", "B+", "AB+"],
    "A-": ["A-", "A+", "AB-", "AB+"],
    "A+": ["A+", "AB+"],
    "B-": ["B-", "B+", "AB-", "AB+"],
    "B+": ["B+", "AB+"],
    "AB-": ["AB-", "AB+"],
    "AB+": ["AB+"],
  };
  return compatibleRecipients[donor]?.includes(recipient) ?? false;
}

function createApp({ db = createDatabase(), secrets = requireEnvironment() } = {}) {
  const app = express();
  const { jwtSecret, encryptionKey } = secrets;
  const now = () => new Date().toISOString();
  const asyncRoute = (handler) => (req, res, next) =>
    Promise.resolve(handler(req, res, next)).catch(next);

  app.locals.db = db;
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "256kb" }));

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  });

  function authenticate(req, res, next) {
    const match = /^Bearer (.+)$/.exec(req.get("authorization") || "");
    if (!match) return next(new HttpError(401, "Authentication required."));
    try {
      const payload = jwt.verify(match[1], jwtSecret);
      const user = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?")
        .get(payload.sub);
      if (!user) return next(new HttpError(401, "Invalid authentication token."));
      req.user = user;
      return next();
    } catch (error) {
      if (error instanceof HttpError) return next(error);
      return next(new HttpError(401, "Invalid authentication token."));
    }
  }

  function allowRoles(...roles) {
    return (req, res, next) => {
      if (!roles.includes(req.user.role)) return next(new HttpError(403, "Forbidden."));
      return next();
    };
  }

  function recordFor(id, user) {
    const record = db.prepare("SELECT * FROM health_records WHERE id = ?").get(id);
    if (!record) throw new HttpError(404, "Health record not found.");
    if (
      record.patient_id !== user.id &&
      !db.prepare("SELECT 1 FROM record_access WHERE patient_id = ? AND clinician_id = ?")
        .get(record.patient_id, user.id)
    ) {
      throw new HttpError(403, "You do not have access to this health record.");
    }
    return {
      id: record.id,
      patientId: record.patient_id,
      category: record.category,
      title: record.title,
      body: decryptRecord(record, encryptionKey),
      createdAt: record.created_at,
      updatedAt: record.updated_at,
    };
  }

  app.get("/api/health", (req, res) => res.json({ status: "ok" }));

  app.post("/api/auth/register", asyncRoute(async (req, res) => {
    const { name, email, password, role = "patient" } = req.body || {};
    if (
      typeof name !== "string" || !name.trim() || name.length > 120 ||
      typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      typeof password !== "string" || password.length < 12 || password.length > 128 ||
      !["patient", "donor"].includes(role)
    ) {
      throw new HttpError(
        400,
        "Provide a name, valid email, password of 12–128 characters, and role patient or donor.",
      );
    }
    const id = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 12);
    try {
      db.prepare(`
        INSERT INTO users (id, name, email, password_hash, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(id, name.trim(), email.trim().toLowerCase(), passwordHash, role, now());
    } catch (error) {
      if (error.message.includes("UNIQUE constraint failed: users.email")) {
        throw new HttpError(409, "An account with that email already exists.");
      }
      throw error;
    }
    res.status(201).json({ id, name: name.trim(), email: email.trim().toLowerCase(), role });
  }));

  app.post("/api/auth/login", loginLimiter, asyncRoute(async (req, res) => {
    const { email, password } = req.body || {};
    if (typeof email !== "string" || typeof password !== "string") {
      throw new HttpError(400, "Email and password are required.");
    }
    const user = db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE")
      .get(email.trim());
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      throw new HttpError(401, "Invalid email or password.");
    }
    const token = jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: "1h" });
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    });
  }));

  app.get("/api/users/me", authenticate, (req, res) => res.json({ user: req.user }));

  app.post(
    "/api/appointments",
    authenticate,
    allowRoles("patient"),
    (req, res, next) => {
      try {
        const { clinicianId, startsAt, endsAt, reason } = req.body || {};
        if (
          typeof clinicianId !== "string" ||
          !isValidDate(startsAt) ||
          !isValidDate(endsAt) ||
          Date.parse(endsAt) <= Date.parse(startsAt) ||
          typeof reason !== "string" ||
          !reason.trim() ||
          reason.length > 1000
        ) {
          throw new HttpError(400, "Provide a clinician, valid start/end times, and a reason (max 1000 characters).");
        }
        const clinician = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'clinician'")
          .get(clinicianId);
        if (!clinician) throw new HttpError(404, "Clinician not found.");
        const appointment = {
          id: crypto.randomUUID(),
          patientId: req.user.id,
          clinicianId,
          startsAt: new Date(startsAt).toISOString(),
          endsAt: new Date(endsAt).toISOString(),
          reason: reason.trim(),
          status: "confirmed",
          createdAt: now(),
        };
        const book = db.transaction(() => {
          const conflict = db.prepare(`
            SELECT 1 FROM appointments
            WHERE clinician_id = ? AND status != 'cancelled'
              AND starts_at < ? AND ends_at > ?
          `).get(clinicianId, appointment.endsAt, appointment.startsAt);
          if (conflict) throw new HttpError(409, "The clinician already has an appointment in that time slot.");
          db.prepare(`
            INSERT INTO appointments
              (id, patient_id, clinician_id, starts_at, ends_at, reason, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            appointment.id,
            appointment.patientId,
            appointment.clinicianId,
            appointment.startsAt,
            appointment.endsAt,
            appointment.reason,
            appointment.status,
            appointment.createdAt,
          );
        });
        book.immediate();
        res.status(201).json({ appointment });
      } catch (error) {
        next(error);
      }
    },
  );

  app.get("/api/appointments", authenticate, (req, res) => {
    const appointments = db.prepare(`
      SELECT a.id, a.patient_id AS patientId, p.name AS patientName,
             a.clinician_id AS clinicianId, c.name AS clinicianName,
             a.starts_at AS startsAt, a.ends_at AS endsAt, a.reason,
             a.status, a.created_at AS createdAt
      FROM appointments a
      JOIN users p ON p.id = a.patient_id
      JOIN users c ON c.id = a.clinician_id
      WHERE a.patient_id = ? OR a.clinician_id = ?
      ORDER BY a.starts_at
    `).all(req.user.id, req.user.id);
    res.json({ appointments });
  });

  app.patch("/api/appointments/:id", authenticate, (req, res) => {
    const appointment = db.prepare("SELECT * FROM appointments WHERE id = ?")
      .get(req.params.id);
    if (!appointment) throw new HttpError(404, "Appointment not found.");
    const { status } = req.body || {};
    if (!APPOINTMENT_STATUSES.includes(status)) {
      throw new HttpError(400, "Status must be confirmed, completed, or cancelled.");
    }
    if (req.user.role === "patient") {
      if (appointment.patient_id !== req.user.id || status !== "cancelled") {
        throw new HttpError(403, "Patients may only cancel their own appointments.");
      }
    } else if (req.user.role === "clinician") {
      if (appointment.clinician_id !== req.user.id) {
        throw new HttpError(403, "You may only update your own appointments.");
      }
    } else {
      throw new HttpError(403, "Forbidden.");
    }
    db.prepare("UPDATE appointments SET status = ? WHERE id = ?").run(status, appointment.id);
    res.json({ id: appointment.id, status });
  });

  app.put(
    "/api/donor-profile",
    authenticate,
    allowRoles("donor"),
    (req, res) => {
      const { bloodGroup, donorType, organs = [], available = true, consented } = req.body || {};
      if (
        !BLOOD_GROUPS.includes(bloodGroup) ||
        !["blood", "organ", "both"].includes(donorType) ||
        !Array.isArray(organs) ||
        organs.some((organ) => !ORGANS.includes(organ)) ||
        ((donorType === "organ" || donorType === "both") && organs.length === 0) ||
        typeof available !== "boolean" ||
        typeof consented !== "boolean"
      ) {
        throw new HttpError(400, "Provide a valid blood group, donor type, organ list, availability, and explicit consent.");
      }
      const id = crypto.randomUUID();
      db.prepare(`
        INSERT INTO donor_profiles
          (id, user_id, blood_group, donor_type, organs_json, available, consented, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          blood_group = excluded.blood_group,
          donor_type = excluded.donor_type,
          organs_json = excluded.organs_json,
          available = excluded.available,
          consented = excluded.consented,
          updated_at = excluded.updated_at
      `).run(
        id,
        req.user.id,
        bloodGroup,
        donorType,
        JSON.stringify([...new Set(organs)]),
        Number(available),
        Number(consented),
        now(),
      );
      const profile = db.prepare("SELECT id FROM donor_profiles WHERE user_id = ?")
        .get(req.user.id);
      res.json({ id: profile.id, consented, available });
    },
  );

  app.get(
    "/api/donors/matches",
    authenticate,
    allowRoles("patient", "clinician", "coordinator"),
    (req, res) => {
      const { type, bloodGroup, organ } = req.query;
      if (!["blood", "organ"].includes(type) || !BLOOD_GROUPS.includes(bloodGroup)) {
        throw new HttpError(400, "Provide type=blood|organ and a valid bloodGroup.");
      }
      let candidates;
      if (type === "blood") {
        candidates = db.prepare(`
          SELECT id, blood_group AS bloodGroup
          FROM donor_profiles
          WHERE donor_type IN ('blood', 'both') AND available = 1 AND consented = 1
        `).all().filter((donor) => bloodDonorCanDonate(donor.bloodGroup, bloodGroup));
      } else {
        if (!ORGANS.includes(organ)) throw new HttpError(400, "Provide a supported organ.");
        const recipientAbo = bloodGroup.replace(/[+-]/, "");
        candidates = db.prepare(`
          SELECT id, blood_group AS bloodGroup, organs_json
          FROM donor_profiles
          WHERE donor_type IN ('organ', 'both') AND available = 1 AND consented = 1
        `).all()
          .filter((donor) => donor.bloodGroup.replace(/[+-]/, "") === recipientAbo)
          .filter((donor) => JSON.parse(donor.organs_json).includes(organ))
          .map(({ id, bloodGroup: donorBloodGroup }) => ({ id, bloodGroup: donorBloodGroup }));
      }
      res.json({
        type,
        candidates,
        note: type === "blood"
          ? "Preliminary red-cell ABO/Rh compatibility only; a qualified clinician must confirm before transfusion."
          : "Preliminary ABO and organ-interest filter only; this is not a transplant match. A transplant team must assess consent, tissue type, tests, and eligibility.",
      });
    },
  );

  app.post("/api/reminders", authenticate, allowRoles("patient"), (req, res) => {
    const { medication, instructions = "", scheduledAt } = req.body || {};
    if (
      typeof medication !== "string" ||
      !medication.trim() ||
      medication.length > 200 ||
      typeof instructions !== "string" ||
      instructions.length > 1000 ||
      !isValidDate(scheduledAt)
    ) {
      throw new HttpError(400, "Provide a medication name, optional instructions, and a valid scheduledAt timestamp.");
    }
    const reminder = {
      id: crypto.randomUUID(),
      medication: medication.trim(),
      instructions: instructions.trim(),
      scheduledAt: new Date(scheduledAt).toISOString(),
      completed: false,
    };
    db.prepare(`
      INSERT INTO reminders
        (id, patient_id, medication, instructions, scheduled_at, completed, created_at)
      VALUES (?, ?, ?, ?, ?, 0, ?)
    `).run(
      reminder.id,
      req.user.id,
      reminder.medication,
      reminder.instructions,
      reminder.scheduledAt,
      now(),
    );
    res.status(201).json({ reminder });
  });

  app.get("/api/reminders", authenticate, allowRoles("patient"), (req, res) => {
    const reminders = db.prepare(`
      SELECT id, medication, instructions, scheduled_at AS scheduledAt,
             completed, created_at AS createdAt
      FROM reminders WHERE patient_id = ? ORDER BY scheduled_at
    `).all(req.user.id).map((reminder) => ({
      ...reminder,
      completed: Boolean(reminder.completed),
    }));
    res.json({ reminders });
  });

  app.patch("/api/reminders/:id", authenticate, allowRoles("patient"), (req, res) => {
    const { completed } = req.body || {};
    if (typeof completed !== "boolean") {
      throw new HttpError(400, "completed must be a boolean.");
    }
    const result = db.prepare(`
      UPDATE reminders SET completed = ?
      WHERE id = ? AND patient_id = ?
    `).run(Number(completed), req.params.id, req.user.id);
    if (!result.changes) throw new HttpError(404, "Reminder not found.");
    res.json({ id: req.params.id, completed });
  });

  app.post("/api/records/access", authenticate, allowRoles("patient"), (req, res) => {
    const { clinicianId } = req.body || {};
    if (typeof clinicianId !== "string") throw new HttpError(400, "clinicianId is required.");
    const clinician = db.prepare("SELECT id FROM users WHERE id = ? AND role = 'clinician'")
      .get(clinicianId);
    if (!clinician) throw new HttpError(404, "Clinician not found.");
    db.prepare(`
      INSERT INTO record_access (patient_id, clinician_id, granted_at)
      VALUES (?, ?, ?)
      ON CONFLICT(patient_id, clinician_id) DO NOTHING
    `).run(req.user.id, clinicianId, now());
    res.status(201).json({ patientId: req.user.id, clinicianId, access: "granted" });
  });

  app.delete("/api/records/access/:clinicianId", authenticate, allowRoles("patient"), (req, res) => {
    db.prepare("DELETE FROM record_access WHERE patient_id = ? AND clinician_id = ?")
      .run(req.user.id, req.params.clinicianId);
    res.status(204).end();
  });

  app.get("/api/records", authenticate, (req, res) => {
    const records = req.user.role === "patient"
      ? db.prepare("SELECT * FROM health_records WHERE patient_id = ? ORDER BY updated_at DESC")
        .all(req.user.id)
      : req.user.role === "clinician"
        ? db.prepare(`
            SELECT r.* FROM health_records r
            JOIN record_access a ON a.patient_id = r.patient_id
            WHERE a.clinician_id = ? ORDER BY r.updated_at DESC
          `).all(req.user.id)
        : [];
    res.json({ records: records.map((record) => recordFor(record.id, req.user)) });
  });

  app.post("/api/records", authenticate, allowRoles("patient"), (req, res) => {
    const { category, title, body } = req.body || {};
    if (
      typeof category !== "string" || !category.trim() || category.length > 100 ||
      typeof title !== "string" || !title.trim() || title.length > 200 ||
      typeof body !== "string" || !body.trim() || Buffer.byteLength(body, "utf8") > 100_000
    ) {
      throw new HttpError(400, "Provide a category, title, and record body (max 100 KB).");
    }
    const id = crypto.randomUUID();
    const timestamp = now();
    const encrypted = encryptRecord(body, encryptionKey);
    db.prepare(`
      INSERT INTO health_records
        (id, patient_id, category, title, body_ciphertext, body_iv, body_tag, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      req.user.id,
      category.trim(),
      title.trim(),
      encrypted.body_ciphertext,
      encrypted.body_iv,
      encrypted.body_tag,
      timestamp,
      timestamp,
    );
    res.status(201).json({ id, category: category.trim(), title: title.trim(), body, createdAt: timestamp });
  });

  app.get("/api/records/:id", authenticate, (req, res) => {
    res.json({ record: recordFor(req.params.id, req.user) });
  });

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof HttpError) {
      return res.status(err.status).json({ error: err.message });
    }
    if (err.type === "entity.parse.failed") {
      return res.status(400).json({ error: "Request body must be valid JSON." });
    }
    console.error("Unhandled API error:", err);
    return res.status(500).json({ error: "Internal server error." });
  });

  return app;
}

if (require.main === module) {
  try {
    const app = createApp();
    const port = Number(process.env.PORT || 3000);
    app.listen(port, () => console.log(`Healthcare API listening on port ${port}`));
  } catch (error) {
    console.error(`Unable to start healthcare API: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { createApp, createDatabase, bloodDonorCanDonate };
