import { db } from "hatchable";

export const access = "public";
export const methods = ["GET", "POST", "OPTIONS"];

const ALLOWED_ORIGINS = new Set([
  "https://admin-lect.web.app",
  "https://lecturer-offline-qr.web.app"
]);
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 210000;

function cors(req, res) {
  const origin = req.headers?.origin || "";
  if (ALLOWED_ORIGINS.has(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Cache-Control", "no-store");
}
function hex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join(""); }
function randomHex(length) { const bytes = new Uint8Array(length); crypto.getRandomValues(bytes); return hex(bytes); }
function fromHex(value) { const out = new Uint8Array(value.length / 2); for (let i=0;i<out.length;i++) out[i]=parseInt(value.slice(i*2,i*2+2),16); return out; }
async function sha256(value) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))); }
async function passwordHash(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:fromHex(saltHex),iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},key,256);
  return hex(new Uint8Array(bits));
}
function safeEqual(a,b) { if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0; }
function bearer(req) { const h=req.headers?.authorization||"";return h.startsWith("Bearer ")?h.slice(7).trim():""; }
function validPassword(p) { return typeof p==="string" && p.length>=10 && p.length<=128; }

export default async function(req,res) {
  cors(req,res);
  if(req.method==="OPTIONS") return res.status(204).send("");
  if(req.method==="GET") {
    const token=bearer(req);
    if(!token||token.length>300)return res.status(401).json({error:"Sign-in required."});
    const tokenHash=await sha256(token);
    const result=await db.query("SELECT a.lecturer_id,a.full_name,a.department,a.active,a.must_change_password,s.expires_at_ms FROM lecturer_sessions s JOIN lecturer_accounts a ON a.lecturer_id=s.lecturer_id WHERE s.token_hash=$1 AND s.expires_at_ms>$2",[tokenHash,Date.now()]);
    if(!result.rows.length)return res.status(401).json({error:"Session expired. Sign in again."});
    const row=result.rows[0];
    if(!row.active)return res.status(403).json({error:"This lecturer account has been disabled."});
    return res.json({ok:true,mustChangePassword:!!row.must_change_password,lecturer:{lecturerId:row.lecturer_id,fullName:row.full_name,department:row.department},expiresAt:Number(row.expires_at_ms)});
  }

  const body=req.body||{};
  const action=String(body.action||"");
  const lecturerId=String(body.lecturerId||"").trim().toUpperCase();

  if(action==="request-reset") {
    if(!lecturerId||lecturerId.length>80)return res.status(400).json({error:"Enter your lecturer ID."});
    const found=await db.query("SELECT lecturer_id,active FROM lecturer_accounts WHERE lecturer_id=$1",[lecturerId]);
    if(found.rows.length&&found.rows[0].active) {
      const pending=await db.query("SELECT request_id FROM lecturer_password_reset_requests WHERE lecturer_id=$1 AND status='pending' LIMIT 1",[lecturerId]);
      if(!pending.rows.length) await db.query("INSERT INTO lecturer_password_reset_requests (request_id,lecturer_id) VALUES ($1,$2)",[randomHex(16),lecturerId]);
    }
    return res.json({ok:true,message:"If this lecturer ID is valid and active, the reset request has been sent to the administrator. Contact the administrator if you need help."});
  }

  if(action==="change-password") {
    const token=bearer(req),newPassword=String(body.newPassword||"");
    if(!token||token.length>300)return res.status(401).json({error:"Sign in again before changing your password."});
    if(!validPassword(newPassword))return res.status(400).json({error:"Choose a password between 10 and 128 characters."});
    const tokenHash=await sha256(token);
    const found=await db.query("SELECT a.lecturer_id,a.active FROM lecturer_sessions s JOIN lecturer_accounts a ON a.lecturer_id=s.lecturer_id WHERE s.token_hash=$1 AND s.expires_at_ms>$2",[tokenHash,Date.now()]);
    if(!found.rows.length)return res.status(401).json({error:"Your sign-in session expired. Sign in again."});
    if(!found.rows[0].active)return res.status(403).json({error:"This lecturer account has been disabled."});
    const salt=randomHex(16),hash=await passwordHash(newPassword,salt);
    await db.query("UPDATE lecturer_accounts SET password_salt=$2,password_hash=$3,must_change_password=FALSE,updated_at=now() WHERE lecturer_id=$1",[found.rows[0].lecturer_id,salt,hash]);
    return res.json({ok:true,message:"Password changed. You can use this password for future sign-ins."});
  }

  const password=String(body.password||"");
  if(!lecturerId||lecturerId.length>80||!password||password.length>256)return res.status(400).json({error:"Enter your lecturer ID and password."});
  const found=await db.query("SELECT lecturer_id,full_name,department,password_salt,password_hash,active,must_change_password FROM lecturer_accounts WHERE lecturer_id=$1",[lecturerId]);
  if(!found.rows.length){await passwordHash(password,"00112233445566778899aabbccddeeff");return res.status(401).json({error:"Lecturer ID or password is incorrect."});}
  const account=found.rows[0],candidate=await passwordHash(password,account.password_salt);
  if(!safeEqual(candidate,account.password_hash))return res.status(401).json({error:"Lecturer ID or password is incorrect."});
  if(!account.active)return res.status(403).json({error:"This lecturer account has been disabled. Contact the administrator."});
  const token=randomHex(32),tokenHash=await sha256(token),expiresAt=Date.now()+SESSION_DAYS*24*60*60*1000;
  await db.query("INSERT INTO lecturer_sessions (token_hash,lecturer_id,expires_at_ms) VALUES ($1,$2,$3)",[tokenHash,account.lecturer_id,expiresAt]);
  return res.json({ok:true,accessToken:token,expiresAt,mustChangePassword:!!account.must_change_password,lecturer:{lecturerId:account.lecturer_id,fullName:account.full_name,department:account.department}});
}
