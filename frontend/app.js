// SecureVault UI. The demo uses browser storage so the interface can be explored.
// Connect these helpers to the FastAPI endpoints before production use.
const $ = (id) => document.getElementById(id);
const records = [];
let activeView = "records";
function toast(message){const el=$("toast");el.textContent=message;el.style.display="block";setTimeout(()=>el.style.display="none",2600)}
function openModal(){ $("modal").hidden=false; $("title").focus() }
function closeModal(){ $("modal").hidden=true; $("form-error").textContent=""; $("record-form").reset() }
function render(){
  const query=$("search").value.trim().toLowerCase();
  const filtered=records.filter(r=>(r.title+" "+r.body).toLowerCase().includes(query));
  $("record-count").textContent=`${filtered.length} ${filtered.length===1?"item":"items"}`;
  $("record-list").innerHTML=filtered.map(r=>`<article class="record-card" data-id="${r.id}"><div class="card-top"><span class="doc-icon">▤</span><span class="private-tag">Private</span></div><h3>${escapeHtml(r.title)}</h3><p>${escapeHtml(r.body)}</p></article>`).join("");
  $("empty").style.display=records.length===0?"block":"none";
  $("record-list").style.display=records.length===0?"none":"grid";
  document.querySelectorAll(".record-card").forEach(card=>card.addEventListener("click",()=>{const r=records.find(x=>x.id===Number(card.dataset.id));toast(`${r.title}: ${r.body}`)}));
}
function escapeHtml(value){return value.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
$("new-record").addEventListener("click",openModal);$("empty-create").addEventListener("click",openModal);
$("close-modal").addEventListener("click",closeModal);$("cancel").addEventListener("click",closeModal);
$("search").addEventListener("input",render);
$("record-form").addEventListener("submit",e=>{e.preventDefault();const title=$("title").value.trim(),body=$("body").value.trim();if(!title||!body){$("form-error").textContent="Please add both a title and details.";return}records.unshift({id:Date.now(),title,body});closeModal();render();toast("Record added to your workspace.")});
document.querySelectorAll(".nav-item").forEach(btn=>btn.addEventListener("click",()=>{activeView=btn.dataset.view;document.querySelectorAll(".nav-item").forEach(x=>x.classList.toggle("active",x===btn));$("records-view").hidden=activeView!=="records";$("security-view").hidden=activeView!=="security";$("page-title").textContent=activeView==="records"?"My records":"Security"}));
$("logout").addEventListener("click",()=>toast("Connect sign-out to the API session endpoint."));
render();
