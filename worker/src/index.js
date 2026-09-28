const OWNER_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const REPO_RE = /^[A-Za-z0-9_.-]{1,100}$/;

function cors(headers={}) {
  return {"access-control-allow-origin":"*","access-control-allow-methods":"GET,POST,OPTIONS","access-control-allow-headers":"content-type",...headers};
}
function json(data,status=200,extra={}) {
  return new Response(JSON.stringify(data,null,2),{status,headers:cors({"content-type":"application/json; charset=utf-8",...extra})});
}
function parseGithubUrl(value) {
  if (typeof value !== "string" || value.length > 500) throw new Error("URL is empty or too long");
  let u; try { u=new URL(value.trim()); } catch { throw new Error("Invalid URL"); }
  if (u.protocol!=="https:" || u.hostname!=="github.com" || u.port || u.username || u.password) throw new Error("Only https://github.com/<owner>/<repo> is accepted");
  if (u.search || u.hash) throw new Error("Query strings and fragments are not allowed");
  const p=u.pathname.split("/").filter(Boolean);
  if (![2,4].includes(p.length) || (p.length===4 && p[2]!=="tree")) throw new Error("Use https://github.com/<owner>/<repo> or /tree/<branch-or-tag>");
  const owner=p[0], repo=p[1].replace(/\.git$/,""), ref=p.length===4?p[3]:null;
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo)) throw new Error("Invalid owner/repository name");
  if (ref && !/^[A-Za-z0-9._/@-]{1,200}$/.test(ref)) throw new Error("Invalid branch/tag reference");
  return {owner,repo,ref,canonical:"https://github.com/"+owner+"/"+repo+(ref?"/tree/"+ref:"")};
}
async function githubJson(url,env,authenticated=false) {
  const headers={"accept":"application/vnd.github+json","user-agent":"RepoGuard/1.0","x-github-api-version":"2026-03-10"};
  if (authenticated) headers.authorization="Bearer "+env.GITHUB_REPO_TOKEN;
  const r=await fetch(url,{redirect:"error",headers});
  if (!r.ok) throw new Error("GitHub API "+r.status);
  return {data:await r.json(),headers:r.headers};
}
async function resolveTarget(target,env) {
  const base="https://api.github.com/repos/"+encodeURIComponent(target.owner)+"/"+encodeURIComponent(target.repo);
  const repoResp=await githubJson(base,env,false);
  if (repoResp.data.private) throw new Error("Private repositories are not accepted");
  const ref=target.ref || repoResp.data.default_branch;
  const commitResp=await githubJson(base+"/commits/"+encodeURIComponent(ref),env,false);
  return {base,repo:repoResp.data,ref,sha:commitResp.data.sha};
}
function dayKey(){ return new Date().toISOString().slice(0,10); }
async function sha256Hex(value){
  const data=new TextEncoder().encode(value);
  const hash=await crypto.subtle.digest("SHA-256",data);
  return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function incrementCap(env,key,cap){
  const raw=await env.REPOGUARD_KV.get(key); const n=Number(raw||0);
  if(n>=cap) return false;
  await env.REPOGUARD_KV.put(key,String(n+1),{expirationTtl:172800}); return true;
}
async function reputation(targetInfo,env){
  try{
    const contrib=await githubJson(targetInfo.base+"/contributors?per_page=100&anon=true",env,false);
    const stars=await githubJson(targetInfo.base+"/stargazers?per_page=100",env,false);
    const commits=await githubJson(targetInfo.base+"/commits?per_page=30",env,false);
    return {
      status:"observed",
      account_created_at:targetInfo.repo.owner?.created_at ?? null,
      repo_created_at:targetInfo.repo.created_at ?? null,
      current_stars:targetInfo.repo.stargazers_count ?? null,
      contributor_count_observed:Array.isArray(contrib.data)?contrib.data.length:null,
      recent_star_sample:Array.isArray(stars.data)?stars.data.length:0,
      recent_commit_sample:Array.isArray(commits.data)?commits.data.length:0,
      force_push_history_rewrite:"not directly observable from a single public API snapshot; marked as not measured",
      star_growth_spike:"not directly observable from a single public API snapshot; marked as not measured"
    };
  }catch(e){ return {status:"error",reason:String(e)}; }
}
async function triggerWorkflow(scan,env){
  const url="https://api.github.com/repos/"+env.REPO_OWNER+"/"+env.REPO_NAME+"/actions/workflows/scan.yml/dispatches";
  const body={ref:env.REPORT_BRANCH,inputs:{scan_id:scan.scan_id,scan_url:scan.target.canonical,expected_sha:scan.sha,expected_ref:scan.ref,reputation_json:JSON.stringify(scan.reputation)}};
  const r=await fetch(url,{method:"POST",redirect:"error",headers:{"accept":"application/vnd.github+json","authorization":"Bearer "+env.GITHUB_REPO_TOKEN,"content-type":"application/json","user-agent":"RepoGuard/1.0","x-github-api-version":"2026-03-10"},body:JSON.stringify(body)});
  if(!r.ok) throw new Error("workflow dispatch failed: "+r.status);
}
async function getReport(scanId,env){
  if(!/^[0-9a-f-]{10,80}$/i.test(scanId)) return json({error:"invalid scan id"},400);
  let report=await env.REPOGUARD_KV.get("report:"+scanId,{type:"json"});
  if(!report){
    try{
      const path="reports/"+encodeURIComponent(scanId)+".json";
      const url="https://api.github.com/repos/"+env.REPO_OWNER+"/"+env.REPO_NAME+"/contents/"+path+"?ref="+encodeURIComponent(env.REPORT_BRANCH);
      const got=await githubJson(url,env,true), data=got.data;
      if(!data.content) return json({error:"report not ready"},202);
      report=JSON.parse(atob(data.content.replace(/\n/g,"")));
    }catch(e){ return json({error:"report not ready"},202); }
  }
  const target=parseGithubUrl(report.repo_url);
  try{
    const current=await resolveTarget(target,env);
    report.outdated=current.sha!==report.commit_sha; report.current_head_sha=current.sha;
  }catch(e){ report.outdated=true; report.current_head_sha=null; report.outdated_reason=String(e); }
  return json(report,200,{"cache-control":"no-store"});
}
export default {
  async fetch(request,env){
    if(request.method==="OPTIONS") return new Response(null,{status:204,headers:cors()});
    const url=new URL(request.url);
    if(url.pathname==="/health") return json({service:"RepoGuard API",status:"ok"});
    if(url.pathname==="/report" && request.method==="GET"){
      const id=url.searchParams.get("id"); if(!id) return json({error:"missing id"},400);
      return getReport(id,env);
    }
    if(url.pathname==="/scan" && request.method==="POST"){
      let body; try{body=await request.json();}catch{return json({error:"invalid JSON"},400);}
      let target; try{target=parseGithubUrl(body.url);}catch(e){return json({verdict:"REJECTED",error:String(e)},400);}
      const ip=request.headers.get("CF-Connecting-IP")||"unknown", day=dayKey();
      if(!(await incrementCap(env,"daily:"+day,Number(env.DAILY_SCAN_CAP||8)))) return json({verdict:"REJECTED",error:"daily scan cap reached"},429);
      const ipHash=await sha256Hex(ip);
      if(!(await incrementCap(env,"ip:"+day+":"+ipHash,Number(env.PER_IP_DAILY_CAP||2)))) return json({verdict:"REJECTED",error:"per-IP daily scan cap reached"},429);
      let scan=null;
      try{
        const targetInfo=await resolveTarget(target,env), rep=await reputation(targetInfo,env);
        scan={scan_id:crypto.randomUUID(),target,ref:targetInfo.ref,sha:targetInfo.sha,reputation:rep};
        await triggerWorkflow(scan,env);
        console.log(JSON.stringify({event:"scan_submitted",url:target.canonical,sha:targetInfo.sha,scan_id:scan.scan_id}));
        return json({scan_id:scan.scan_id,repo_url:target.canonical,commit_sha:targetInfo.sha,status:"queued"},202);
      }catch(e){
        const rejected={scan_id:scan?.scan_id||crypto.randomUUID(),repo_url:target.canonical,commit_sha:scan?.sha||null,scan_time:new Date().toISOString(),verdict:"REJECTED",mode:"hosted-static-analysis",files_analyzed:"0 of 0",checks:[],findings:[],rejection_reasons:[String(e)],disclaimer:"No scanner can guarantee the absence of all threats."};
        await env.REPOGUARD_KV.put("report:"+rejected.scan_id,JSON.stringify(rejected),{expirationTtl:604800});
        return json({verdict:"REJECTED",scan_id:rejected.scan_id,error:String(e)},502);
      }
    }
    return json({service:"RepoGuard API",routes:["POST /scan","GET /report?id=...","GET /health"]});
  }
};
