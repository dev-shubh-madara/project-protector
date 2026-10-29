"""Self-contained animated HTML report (no external files, no network, no JS libraries)."""
from __future__ import annotations

import json

from .report import to_dict

TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CipherBloom Guardian report</title>
<style>
:root{--bg:#07040f;--card:#120a22cc;--line:#2a1b4d;--txt:#efe9ff;--dim:#9f92c4;--pink:#ff4fd8;--vio:#8b5cff;--cyan:#36e2ff;
--critical:#ff2e63;--high:#ff7a3d;--medium:#ffd23f;--low:#36e2ff;--info:#8b8fa8}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--txt);font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;overflow-x:hidden}
.aurora{position:fixed;inset:-20%;z-index:-2;background:
radial-gradient(40% 40% at 20% 20%,#8b5cff55,transparent 70%),radial-gradient(35% 35% at 80% 30%,#ff4fd855,transparent 70%),
radial-gradient(40% 40% at 50% 90%,#36e2ff33,transparent 70%);filter:blur(30px);animation:drift 18s ease-in-out infinite alternate}
@keyframes drift{to{transform:translate3d(4%,3%,0) rotate(6deg) scale(1.1)}}
.petals{position:fixed;inset:0;z-index:-1;pointer-events:none;overflow:hidden}
.petal{position:absolute;top:-30px;width:10px;height:14px;border-radius:70% 0 70% 0;background:linear-gradient(135deg,var(--pink),var(--vio));opacity:.55;animation:fall linear infinite}
@keyframes fall{to{transform:translate3d(var(--dx),110vh,0) rotate(540deg)}}
.wrap{max-width:980px;margin:0 auto;padding:40px 18px 80px}
header{text-align:center;padding:30px 0 10px}
h1{margin:0;font-size:clamp(30px,6vw,56px);letter-spacing:-1px;background:linear-gradient(90deg,var(--pink),var(--vio),var(--cyan),var(--pink));background-size:300% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:shine 6s linear infinite}
@keyframes shine{to{background-position:300% 0}}
.sub{color:var(--dim);margin:6px 0 0}
.hero{display:grid;grid-template-columns:220px 1fr;gap:26px;align-items:center;margin:34px 0;padding:26px;border:1px solid var(--line);border-radius:22px;background:var(--card);backdrop-filter:blur(10px);animation:rise .8s both}
@media(max-width:640px){.hero{grid-template-columns:1fr;justify-items:center;text-align:center}}
.ring{position:relative;width:200px;height:200px}
.ring svg{transform:rotate(-90deg)}
.ring .bg{stroke:#2a1b4d}
.ring .fg{stroke:url(#g);stroke-linecap:round;stroke-dasharray:565;stroke-dashoffset:565;animation:fill 1.8s .3s cubic-bezier(.2,.8,.2,1) forwards;filter:drop-shadow(0 0 8px var(--pink))}
@keyframes fill{to{stroke-dashoffset:var(--off)}}
.ring b{position:absolute;inset:0;display:grid;place-items:center;font-size:52px;font-weight:800}
.ring small{position:absolute;left:0;right:0;bottom:46px;text-align:center;color:var(--dim);font-size:12px;letter-spacing:2px}
.chips{display:flex;flex-wrap:wrap;gap:10px}
.chip{padding:8px 14px;border-radius:999px;border:1px solid var(--line);cursor:pointer;user-select:none;transition:.25s;background:#0d0719}
.chip:hover{transform:translateY(-3px) scale(1.04);border-color:var(--pink)}
.chip.on{box-shadow:0 0 0 2px var(--pink),0 0 18px #ff4fd855}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:middle}
.meta{color:var(--dim);font-size:14px;margin-top:14px;word-break:break-all}
.list{display:grid;gap:14px;margin-top:10px}
.item{border:1px solid var(--line);border-left:5px solid var(--c);border-radius:16px;background:var(--card);backdrop-filter:blur(8px);padding:16px 18px;opacity:0;transform:translateY(24px);animation:rise .6s forwards;transition:transform .25s,box-shadow .25s}
.item:hover{transform:translateY(-4px);box-shadow:0 12px 40px -12px var(--c)}
@keyframes rise{to{opacity:1;transform:none}}
.top{display:flex;gap:10px;align-items:center;flex-wrap:wrap;cursor:pointer}
.sev{font-size:11px;font-weight:800;letter-spacing:1.5px;padding:3px 9px;border-radius:999px;background:var(--c);color:#12001f}
.t{font-weight:700;flex:1;min-width:200px}
.loc{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:var(--cyan);background:#0d0719;padding:3px 8px;border-radius:8px}
.body{display:none;margin-top:12px;color:#d9d0f3}
.item.open .body{display:block;animation:rise .4s both}
.body p{margin:8px 0}.body b{color:var(--pink)}
code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0d0719;padding:2px 6px;border-radius:6px}
button{margin-top:6px;background:linear-gradient(90deg,var(--vio),var(--pink));color:#fff;border:0;padding:7px 14px;border-radius:10px;font-weight:700;cursor:pointer;transition:.2s}
button:hover{filter:brightness(1.2);transform:scale(1.05)}
.ok{text-align:center;padding:50px;border:1px dashed var(--line);border-radius:20px;color:var(--dim)}
.ok h2{color:#7dffb2;font-size:30px;margin:0 0 8px;animation:pulse 2s infinite}
@keyframes pulse{50%{text-shadow:0 0 22px #7dffb2}}
footer{text-align:center;color:var(--dim);font-size:13px;margin-top:40px}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;animation-iteration-count:1!important}}
</style></head><body>
<div class="aurora"></div><div class="petals" id="petals"></div>
<div class="wrap">
<header><h1>CipherBloom Guardian</h1><p class="sub">Local security report &middot; no AI &middot; no API key &middot; your data never left this computer</p></header>
<section class="hero">
 <div class="ring"><svg width="200" height="200" viewBox="0 0 200 200"><defs><linearGradient id="g" x1="0" x2="1"><stop offset="0" stop-color="#ff4fd8"/><stop offset="1" stop-color="#36e2ff"/></linearGradient></defs>
 <circle class="bg" cx="100" cy="100" r="90" fill="none" stroke-width="14"/><circle class="fg" id="fg" cx="100" cy="100" r="90" fill="none" stroke-width="14"/></svg>
 <b id="num">0</b><small>HEALTH</small></div>
 <div><div class="chips" id="chips"></div><div class="meta" id="meta"></div></div>
</section>
<section class="list" id="list"></section>
<footer>Passing these checks does not guarantee a project is secure. Rotate any exposed secret immediately.</footer>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent);
var COL={critical:'--critical',high:'--high',medium:'--medium',low:'--low',info:'--info'};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
var P=document.getElementById('petals');
for(var i=0;i<26;i++){var p=el('i','petal');p.style.left=Math.random()*100+'%';p.style.setProperty('--dx',(Math.random()*160-80)+'px');
p.style.animationDuration=(9+Math.random()*12)+'s';p.style.animationDelay=(-Math.random()*20)+'s';p.style.opacity=.25+Math.random()*.45;P.appendChild(p)}
var fg=document.getElementById('fg');fg.style.setProperty('--off',565-565*D.score/100);
var n=document.getElementById('num'),t0=null;(function tick(ts){t0=t0||ts;var k=Math.min(1,(ts-t0)/1800);n.textContent=Math.round(D.score*(1-Math.pow(1-k,3)));if(k<1)requestAnimationFrame(tick)})(performance.now());
document.getElementById('meta').textContent='Target: '+D.target+'  |  '+D.generated+'  |  v'+D.version+'  |  Checks: '+D.checks.join(', ');
var active=null,chips=document.getElementById('chips'),list=document.getElementById('list');
['critical','high','medium','low','info'].forEach(function(s){
 var c=el('span','chip');var d=el('span','dot');d.style.background='var('+COL[s]+')';c.appendChild(d);c.appendChild(document.createTextNode(s+' '+(D.counts[s]||0)));
 c.onclick=function(){active=(active===s)?null:s;[].forEach.call(chips.children,function(x){x.classList.remove('on')});if(active)c.classList.add('on');render()};chips.appendChild(c)});
function render(){list.textContent='';var shown=D.findings.filter(function(f){return !active||f.severity===active});
 if(!D.findings.length){var o=el('div','ok');o.appendChild(el('h2',null,'All clear'));o.appendChild(el('p',null,'No issues found by these checks. Keep your keys rotated and your .env ignored.'));list.appendChild(o);return}
 shown.forEach(function(f,i){var it=el('div','item');it.style.setProperty('--c','var('+COL[f.severity]+')');it.style.animationDelay=(i*70)+'ms';
  var top=el('div','top');top.appendChild(el('span','sev',f.severity.toUpperCase()));top.appendChild(el('span','t',f.title));
  if(f.file)top.appendChild(el('span','loc',f.file+(f.line?':'+f.line:'')));it.appendChild(top);
  var b=el('div','body');
  if(f.snippet){var p=el('p');p.appendChild(el('b',null,'Found: '));p.appendChild(el('code',null,f.snippet));b.appendChild(p)}
  if(f.why){var p2=el('p');p2.appendChild(el('b',null,'Why it matters: '));p2.appendChild(document.createTextNode(f.why));b.appendChild(p2)}
  if(f.fix){var p3=el('p');p3.appendChild(el('b',null,'How to fix: '));p3.appendChild(document.createTextNode(f.fix));b.appendChild(p3);
   var btn=el('button',null,'Copy fix');btn.onclick=function(e){e.stopPropagation();try{navigator.clipboard.writeText(f.fix);btn.textContent='Copied!'}catch(x){btn.textContent='Select & copy manually'}};b.appendChild(btn)}
  it.appendChild(b);top.onclick=function(){it.classList.toggle('open')};list.appendChild(it)})}
render();
})();
</script></body></html>
"""


def write_html(path, findings, target, checks):
    data = json.dumps(to_dict(findings, target, checks)).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(TEMPLATE.replace("__DATA__", data))
