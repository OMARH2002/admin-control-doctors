const ITERATIONS = 210000;
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_";
const ADMIN_ORIGINS = new Set([
  "https://admin-lect.web.app",
  "https://admin-lect.firebaseapp.com",
  "https://lecturer-attendance-admin.web.app",
  "https://lecturer-attendance-admin.firebaseapp.com"
]);
const LECTURER_ORIGINS = new Set([
  "https://offline-qr.hatchable.site",
  "https://lecturer-offline-qr.web.app"
]);
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
function randomHex(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return hex(b); }
function randomPassword() { const b = new Uint8Array(18); crypto.getRandomValues(b); return Array.from(b, x => ALPHABET[x % ALPHABET.length]).join(""); }
function fromHex(s) { const b = new Uint8Array(s.length / 2); for (let i=0;i<b.length;i++) b[i]=parseInt(s.slice(i*2,i*2+2),16); return b; }
async function digest(s) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))); }
async function passwordHash(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:fromHex(saltHex),iterations:ITERATIONS,hash:"SHA-256"},key,256);
  return hex(new Uint8Array(bits));
}
function equal(a,b) { if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0; }
function json(data,status=200,headers={}) { return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...headers}}); }
function corsHeaders(origin,allowed) {
  const h={"Vary":"Origin","Access-Control-Allow-Methods":"GET, POST, PATCH, OPTIONS","Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Max-Age":"86400"};
  if(allowed.has(origin)) h["Access-Control-Allow-Origin"]=origin;
  return h;
}
function response(data,status,headers) { return json(data,status,headers); }
async function bodyJson(req) { try { return await req.json(); } catch { return {}; } }
function clean(v,max) { return typeof v==="string"?v.trim().slice(0,max):""; }
async function adminUser(req,env) {
  const auth=req.headers.get("Authorization")||"";
  if(!auth.startsWith("Bearer ")) return {error:"Sign in required.",status:401};
  if(!env.FIREBASE_API_KEY || !env.ADMIN_EMAILS) return {error:"Administrator authentication is not configured on the API.",status:503};
  const token=auth.slice(7).trim();
  if(!token||token.length>5000) return {error:"Invalid sign-in token.",status:401};
  let result;
  try {
    const r=await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key="+encodeURIComponent(env.FIREBASE_API_KEY),{
      method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({idToken:token})
    });
    result=await r.json();
    if(!r.ok) return {error:"Your Firebase sign-in expired. Sign in again.",status:401};
  } catch { return {error:"Could not verify Firebase sign-in. Try again.",status:502}; }
  const user=result.users?.[0];
  if(!user?.email) return {error:"Firebase account has no email address.",status:401};
  const allowed=env.ADMIN_EMAILS.split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);
  if(!allowed.includes(user.email.toLowerCase())) return {error:"This email is not authorized to administer lecturer accounts.",status:403};
  return {email:user.email};
}
async function adminApi(req,env,headers) {
  const identity=await adminUser(req,env);
  if(identity.error) return response({error:identity.error},identity.status,headers);
  const db=env.DB;
  if(req.method==="GET") {
    const [a,r]=await Promise.all([
      db.prepare("SELECT lecturer_id,full_name,department,active,must_change_password,created_at,updated_at FROM lecturer_accounts ORDER BY created_at DESC").all(),
      db.prepare("SELECT r.request_id,r.lecturer_id,a.full_name,a.department,r.requested_at FROM lecturer_password_reset_requests r JOIN lecturer_accounts a ON a.lecturer_id=r.lecturer_id WHERE r.status='pending' ORDER BY r.requested_at ASC").all()
    ]);
    return response({lecturers:a.results||[],resetRequests:r.results||[]},200,headers);
  }
  const body=await bodyJson(req);
  if(req.method==="POST") {
    const fullName=clean(body.fullName,160), department=clean(body.department,120);
    if(!fullName) return response({error:"Lecturer full name is required."},400,headers);
    let lecturerId="";
    for(let i=0;i<8;i++) {
      const candidate="LEC-"+randomHex(4).toUpperCase();
      const found=await db.prepare("SELECT lecturer_id FROM lecturer_accounts WHERE lecturer_id=?").bind(candidate).first();
      if(!found){lecturerId=candidate;break;}
    }
    if(!lecturerId) return response({error:"Could not generate a unique lecturer ID. Please retry."},500,headers);
    const password=randomPassword(),salt=randomHex(16),hash=await passwordHash(password,salt);
    await db.prepare("INSERT INTO lecturer_accounts (lecturer_id,full_name,department,password_salt,password_hash) VALUES (?,?,?,?,?)").bind(lecturerId,fullName,department,salt,hash).run();
    return response({ok:true,lecturer:{lecturerId,fullName,department,active:true},temporaryPassword:password,message:"Save this password now. It will not be shown again."},201,headers);
  }
  if(req.method!=="PATCH") return response({error:"Method not allowed."},405,headers);
  const lecturerId=clean(body.lecturerId,80).toUpperCase(), action=clean(body.action,40);
  if(!lecturerId) return response({error:"Lecturer ID is required."},400,headers);
  const account=await db.prepare("SELECT lecturer_id FROM lecturer_accounts WHERE lecturer_id=?").bind(lecturerId).first();
  if(!account) return response({error:"Lecturer account not found."},404,headers);
  const now=new Date().toISOString();
  if(action==="cancel-reset"||action==="resolve-reset") {
    const requestId=clean(body.requestId,100);
    const request=await db.prepare("SELECT request_id,lecturer_id FROM lecturer_password_reset_requests WHERE request_id=? AND status='pending'").bind(requestId).first();
    if(!request||request.lecturer_id!==lecturerId) return response({error:"Pending reset request not found."},404,headers);
    if(action==="cancel-reset") {
      await db.prepare("UPDATE lecturer_password_reset_requests SET status='cancelled',resolved_at=? WHERE request_id=?").bind(now,requestId).run();
      return response({ok:true,lecturerId,cancelled:true,message:"Password reset request cancelled. The lecturer's password was not changed."},200,headers);
    }
    const password=randomPassword(),salt=randomHex(16),hash=await passwordHash(password,salt);
    await db.batch([
      db.prepare("UPDATE lecturer_accounts SET password_salt=?,password_hash=?,must_change_password=1,updated_at=? WHERE lecturer_id=?").bind(salt,hash,now,lecturerId),
      db.prepare("DELETE FROM lecturer_sessions WHERE lecturer_id=?").bind(lecturerId),
      db.prepare("UPDATE lecturer_password_reset_requests SET status='resolved',resolved_at=? WHERE request_id=?").bind(now,requestId)
    ]);
    return response({ok:true,lecturerId,temporaryPassword:password,message:"Reset issued. Share this temporary password securely; the lecturer must change it at next sign-in."},200,headers);
  }
  if(action==="reset-password") {
    const password=randomPassword(),salt=randomHex(16),hash=await passwordHash(password,salt);
    await db.batch([
      db.prepare("UPDATE lecturer_accounts SET password_salt=?,password_hash=?,must_change_password=1,updated_at=? WHERE lecturer_id=?").bind(salt,hash,now,lecturerId),
      db.prepare("DELETE FROM lecturer_sessions WHERE lecturer_id=?").bind(lecturerId)
    ]);
    return response({ok:true,lecturerId,temporaryPassword:password,message:"Save this new password now. Previous sessions have been revoked."},200,headers);
  }
  if(action==="delete") {
    await db.batch([
      db.prepare("DELETE FROM lecturer_sessions WHERE lecturer_id=?").bind(lecturerId),
      db.prepare("DELETE FROM lecturer_accounts WHERE lecturer_id=?").bind(lecturerId)
    ]);
    return response({ok:true,lecturerId,deleted:true},200,headers);
  }
  if(action==="disable"||action==="enable") {
    const active=action==="enable"?1:0;
    await db.prepare("UPDATE lecturer_accounts SET active=?,updated_at=? WHERE lecturer_id=?").bind(active,now,lecturerId).run();
    if(!active) await db.prepare("DELETE FROM lecturer_sessions WHERE lecturer_id=?").bind(lecturerId).run();
    return response({ok:true,lecturerId,active:!!active},200,headers);
  }
  return response({error:"Unsupported action."},400,headers);
}
async function lecturerApi(req,env,headers) {
  const db=env.DB;
  if(req.method==="GET") {
    const token=(req.headers.get("Authorization")||"").startsWith("Bearer ")?req.headers.get("Authorization").slice(7).trim():"";
    if(!token||token.length>300) return response({error:"Sign-in required."},401,headers);
    const tokenHash=await digest(token);
    const row=await db.prepare("SELECT a.lecturer_id,a.full_name,a.department,a.active,a.must_change_password,s.expires_at_ms FROM lecturer_sessions s JOIN lecturer_accounts a ON a.lecturer_id=s.lecturer_id WHERE s.token_hash=? AND s.expires_at_ms>?").bind(tokenHash,Date.now()).first();
    if(!row) return response({error:"Session expired. Sign in again."},401,headers);
    if(!row.active) return response({error:"This lecturer account has been disabled."},403,headers);
    return response({ok:true,mustChangePassword:!!row.must_change_password,lecturer:{lecturerId:row.lecturer_id,fullName:row.full_name,department:row.department},expiresAt:Number(row.expires_at_ms)},200,headers);
  }
  const body=await bodyJson(req),action=String(body.action||""),lecturerId=clean(body.lecturerId,80).toUpperCase();
  if(action==="request-reset") {
    if(!lecturerId) return response({error:"Enter your lecturer ID."},400,headers);
    const found=await db.prepare("SELECT lecturer_id,active FROM lecturer_accounts WHERE lecturer_id=?").bind(lecturerId).first();
    if(found&&found.active) {
      const pending=await db.prepare("SELECT request_id FROM lecturer_password_reset_requests WHERE lecturer_id=? AND status='pending' LIMIT 1").bind(lecturerId).first();
      if(!pending) await db.prepare("INSERT INTO lecturer_password_reset_requests (request_id,lecturer_id) VALUES (?,?)").bind(randomHex(16),lecturerId).run();
    }
    return response({ok:true,message:"If this lecturer ID is valid and active, the reset request has been sent to the administrator."},200,headers);
  }
  if(action==="change-password") {
    const token=(req.headers.get("Authorization")||"").startsWith("Bearer ")?req.headers.get("Authorization").slice(7).trim():"";
    const newPassword=String(body.newPassword||"");
    if(!token||token.length>300) return response({error:"Sign in again before changing your password."},401,headers);
    if(newPassword.length<10||newPassword.length>128) return response({error:"Choose a password between 10 and 128 characters."},400,headers);
    const tokenHash=await digest(token);
    const found=await db.prepare("SELECT a.lecturer_id,a.active FROM lecturer_sessions s JOIN lecturer_accounts a ON a.lecturer_id=s.lecturer_id WHERE s.token_hash=? AND s.expires_at_ms>?").bind(tokenHash,Date.now()).first();
    if(!found) return response({error:"Your sign-in session expired. Sign in again."},401,headers);
    if(!found.active) return response({error:"This lecturer account has been disabled."},403,headers);
    const salt=randomHex(16),hash=await passwordHash(newPassword,salt);
    await db.prepare("UPDATE lecturer_accounts SET password_salt=?,password_hash=?,must_change_password=0,updated_at=? WHERE lecturer_id=?").bind(salt,hash,new Date().toISOString(),found.lecturer_id).run();
    return response({ok:true,message:"Password changed. You can use this password for future sign-ins."},200,headers);
  }
  const password=String(body.password||"");
  if(!lecturerId||!password||password.length>256) return response({error:"Enter your lecturer ID and password."},400,headers);
  const account=await db.prepare("SELECT lecturer_id,full_name,department,password_salt,password_hash,active,must_change_password FROM lecturer_accounts WHERE lecturer_id=?").bind(lecturerId).first();
  if(!account) { await passwordHash(password,"00112233445566778899aabbccddeeff"); return response({error:"Lecturer ID or password is incorrect."},401,headers); }
  const candidate=await passwordHash(password,account.password_salt);
  if(!equal(candidate,account.password_hash)) return response({error:"Lecturer ID or password is incorrect."},401,headers);
  if(!account.active) return response({error:"This lecturer account has been disabled. Contact the administrator."},403,headers);
  const token=randomHex(32),tokenHash=await digest(token),expiresAt=Date.now()+30*24*60*60*1000;
  await db.prepare("INSERT INTO lecturer_sessions (token_hash,lecturer_id,expires_at_ms) VALUES (?,?,?)").bind(tokenHash,account.lecturer_id,expiresAt).run();
  return response({ok:true,accessToken:token,expiresAt,mustChangePassword:!!account.must_change_password,lecturer:{lecturerId:account.lecturer_id,fullName:account.full_name,department:account.department}},200,headers);
}
export default {
  async fetch(req,env) {
    const url=new URL(req.url),origin=req.headers.get("Origin")||"";
    const isAdmin=url.pathname==="/api/admin/lecturers";
    const isLecturer=url.pathname==="/api/lecturer-auth";
    const allowed=isAdmin?ADMIN_ORIGINS:LECTURER_ORIGINS;
    const headers=corsHeaders(origin,allowed);
    if(req.method==="OPTIONS") return new Response(null,{status:204,headers});
    if(!isAdmin&&!isLecturer) return response({error:"Not found."},404,headers);
    if(!env.DB) return response({error:"D1 database binding DB is missing."},500,headers);
    if(isAdmin && !["GET","POST","PATCH"].includes(req.method)) return response({error:"Method not allowed."},405,headers);
    if(isLecturer && !["GET","POST"].includes(req.method)) return response({error:"Method not allowed."},405,headers);
    try { return isAdmin?await adminApi(req,env,headers):await lecturerApi(req,env,headers); }
    catch(e) { return response({error:"Internal API error.",detail:env.ENVIRONMENT==="development"?String(e):undefined},500,headers); }
  }
};