const $=id=>document.getElementById(id);
$("getKey").onclick=async()=>{
  $("msg").textContent="正在获取...";
  const r=await fetch("/api/key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:$("username").value,robloxUserId:$("userid").value})});
  const d=await r.json(); $("msg").textContent=d.error||"";
  if(d.ok){$("result").classList.remove("hidden");$("result").textContent=d.key+"（有效至 "+new Date(d.expiresAt).toLocaleString()+"）";}
};
$("adminBtn").onclick=()=>{$("adminModal").classList.remove("hidden")};
$("closeAdmin").onclick=()=>{$("adminModal").classList.add("hidden")};
$("adminLogin").onclick=async()=>{
 const r=await fetch("/api/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:$("adminPass").value})});
 const d=await r.json(); if(!d.ok)return $("adminMsg").textContent=d.error;
 sessionStorage.setItem("starAdminToken",d.token); location.href="/admin.html";
};
