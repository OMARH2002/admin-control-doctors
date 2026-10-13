import { db } from "hatchable";

export const access = "admin";
export const methods = ["GET", "POST", "PATCH"];

const PBKDF2_ITERATIONS = 210000;
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_";
function hex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}
function randomHex(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return hex(bytes);
}
function randomPassword() {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => ALPHABET[b % ALPHABET.length]).join("");
}
async function passwordHash(password, saltHex) {
  const salt = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < salt.length; i++) salt[i] = parseInt(saltHex.slice(i * 2, i * 2 + 2), 16);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  return hex(new Uint8Array(bits));
}
async function createUniqueId() {
  for (let i = 0; i < 8; i++) {
    const id = "LEC-" + randomHex(4).toUpperCase();
    const exists = await db.query("SELECT lecturer_id FROM lecturer_accounts WHERE lecturer_id = $1", [id]);
    if (!exists.rows.length) return id;
  }
  throw new Error("Could not generate a unique lecturer ID. Please retry.");
}
function cleanName(value, max) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

export default async function (req, res) {
  if (req.method === "GET") {
    const result = await db.query(
      "SELECT lecturer_id, full_name, department, active, must_change_password, created_at, updated_at FROM lecturer_accounts ORDER BY created_at DESC"
    );
    const resetRequests = await db.query(
      "SELECT r.request_id, r.lecturer_id, a.full_name, a.department, r.requested_at FROM lecturer_password_reset_requests r JOIN lecturer_accounts a ON a.lecturer_id = r.lecturer_id WHERE r.status = 'pending' ORDER BY r.requested_at ASC"
    );
    return res.json({ lecturers: result.rows, resetRequests: resetRequests.rows });
  }

  const body = req.body || {};
  if (req.method === "POST") {
    const fullName = cleanName(body.fullName, 160);
    const department = cleanName(body.department, 120);
    if (!fullName) return res.status(400).json({ error: "Lecturer full name is required." });
    const lecturerId = await createUniqueId();
    const password = randomPassword();
    const salt = randomHex(16);
    const hash = await passwordHash(password, salt);
    await db.query(
      "INSERT INTO lecturer_accounts (lecturer_id, full_name, department, password_salt, password_hash) VALUES ($1, $2, $3, $4, $5)",
      [lecturerId, fullName, department, salt, hash]
    );
    return res.status(201).json({
      ok: true,
      lecturer: { lecturerId, fullName, department, active: true },
      temporaryPassword: password,
      message: "Save this password now. It will not be shown again."
    });
  }

  const lecturerId = cleanName(body.lecturerId, 80).toUpperCase();
  const action = cleanName(body.action, 40);
  if (!lecturerId) return res.status(400).json({ error: "Lecturer ID is required." });
  const exists = await db.query("SELECT lecturer_id FROM lecturer_accounts WHERE lecturer_id = $1", [lecturerId]);
  if (!exists.rows.length) return res.status(404).json({ error: "Lecturer account not found." });

  if (action === "cancel-reset") {
    const requestId = cleanName(body.requestId, 100);
    const request = await db.query("SELECT request_id, lecturer_id FROM lecturer_password_reset_requests WHERE request_id = $1 AND status = 'pending'", [requestId]);
    if (!request.rows.length || request.rows[0].lecturer_id !== lecturerId) return res.status(404).json({ error: "Pending reset request not found." });
    await db.query("UPDATE lecturer_password_reset_requests SET status = 'cancelled', resolved_at = now() WHERE request_id = $1", [requestId]);
    return res.json({ ok: true, lecturerId, cancelled: true, message: "Password reset request cancelled. The lecturer's password was not changed." });
  }

  if (action === "resolve-reset") {
    const requestId = cleanName(body.requestId, 100);
    const request = await db.query("SELECT request_id, lecturer_id FROM lecturer_password_reset_requests WHERE request_id = $1 AND status = 'pending'", [requestId]);
    if (!request.rows.length || request.rows[0].lecturer_id !== lecturerId) return res.status(404).json({ error: "Pending reset request not found." });
    const password = randomPassword();
    const salt = randomHex(16);
    const hash = await passwordHash(password, salt);
    await db.query("UPDATE lecturer_accounts SET password_salt = $2, password_hash = $3, must_change_password = TRUE, updated_at = now() WHERE lecturer_id = $1", [lecturerId, salt, hash]);
    await db.query("DELETE FROM lecturer_sessions WHERE lecturer_id = $1", [lecturerId]);
    await db.query("UPDATE lecturer_password_reset_requests SET status = 'resolved', resolved_at = now() WHERE request_id = $1", [requestId]);
    return res.json({ ok: true, lecturerId, temporaryPassword: password, message: "Reset issued. Share this temporary password securely; the lecturer must change it at next sign-in." });
  }

  if (action === "reset-password") {
    const password = randomPassword();
    const salt = randomHex(16);
    const hash = await passwordHash(password, salt);
    await db.query(
      "UPDATE lecturer_accounts SET password_salt = $2, password_hash = $3, must_change_password = TRUE, updated_at = now() WHERE lecturer_id = $1",
      [lecturerId, salt, hash]
    );
    await db.query("DELETE FROM lecturer_sessions WHERE lecturer_id = $1", [lecturerId]);
    return res.json({ ok: true, lecturerId, temporaryPassword: password, message: "Save this new password now. Previous sessions have been revoked." });
  }

  if (action === "delete") {
    await db.query("DELETE FROM lecturer_sessions WHERE lecturer_id = $1", [lecturerId]);
    await db.query("DELETE FROM lecturer_accounts WHERE lecturer_id = $1", [lecturerId]);
    return res.json({ ok: true, lecturerId, deleted: true });
  }

  if (action === "disable" || action === "enable") {
    const active = action === "enable";
    await db.query("UPDATE lecturer_accounts SET active = $2, updated_at = now() WHERE lecturer_id = $1", [lecturerId, active]);
    if (!active) await db.query("DELETE FROM lecturer_sessions WHERE lecturer_id = $1", [lecturerId]);
    return res.json({ ok: true, lecturerId, active });
  }

  return res.status(400).json({ error: "Unsupported action." });
}