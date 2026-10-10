/* =====================================================================
   كلمات المرور — تُخزَّن مشفّرة (SHA-256) في passwords.json داخل المستودع.
   يغيّرها المعلم من لوحته (الإعدادات ← كلمات المرور) فتُنشر لجميع الطلاب.
   ===================================================================== */
const AUTH = { ready: null };

async function sha256Hex(str){
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf), b=>b.toString(16).padStart(2,"0")).join("");
}
/* كلمة مرور الطلاب غير حساسة لحالة الأحرف */
function hashPassword(kind, value){
  value = String(value).trim();
  return sha256Hex("jhz5|" + kind + "|" + (kind==="exam" ? value.toUpperCase() : value));
}

AUTH.load = function(){
  AUTH.ready = fetch("passwords.json?t=" + Date.now(), { cache:"no-store" })
    .then(r=>r.ok ? r.json() : null)
    .then(d=>{
      if(d && d.examHash && d.adminHash){
        CONFIG.examPasswordHash = d.examHash;
        CONFIG.adminPasswordHash = d.adminHash;
      }
    })
    .catch(()=>{});     // عند تعذّر التحميل تُستخدم القيم المضمّنة في config.js
  return AUTH.ready;
};
AUTH.check = async function(kind, value){
  await AUTH.ready;
  const want = kind==="exam" ? CONFIG.examPasswordHash : CONFIG.adminPasswordHash;
  return (await hashPassword(kind, value)) === want;
};

/* نشر كلمات مرور جديدة إلى passwords.json في المستودع (يلزم رمز GitHub الخاص بالمعلم) */
AUTH.publish = async function(token, newExam, newAdmin){
  const examHash  = newExam  ? await hashPassword("exam", newExam)   : CONFIG.examPasswordHash;
  const adminHash = newAdmin ? await hashPassword("admin", newAdmin) : CONFIG.adminPasswordHash;
  const api = "https://api.github.com/repos/" + CONFIG.repoOwner + "/" + CONFIG.repoName + "/contents/passwords.json";
  const headers = { "Authorization":"Bearer "+token, "Accept":"application/vnd.github+json" };
  let sha;
  const cur = await fetch(api + "?ref=" + CONFIG.repoBranch, { headers });
  if(cur.ok) sha = (await cur.json()).sha;
  else if(cur.status === 401 || cur.status === 403) throw new Error("الرمز غير صالح أو لا يملك صلاحية Contents (قراءة وكتابة).");
  else if(cur.status !== 404) throw new Error("تعذّر الاتصال بـ GitHub (" + cur.status + ").");
  const body = JSON.stringify({ examHash, adminHash, updated:new Date().toISOString() }, null, 2) + "\n";
  const put = await fetch(api, {
    method:"PUT", headers,
    body: JSON.stringify({
      message: "Update access passwords",
      content: btoa(body), branch: CONFIG.repoBranch, sha
    })
  });
  if(!put.ok) throw new Error("فشل النشر (" + put.status + "): " + ((await put.json().catch(()=>({}))).message || ""));
  CONFIG.examPasswordHash = examHash; CONFIG.adminPasswordHash = adminHash;
};
AUTH.load();
