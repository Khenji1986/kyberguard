'use strict';
window.addEventListener('load', function(){ initNetCanvas(); initHeroCanvas(); initThreatTicker(); initStatsCountUp(); initLifeEnhancements(); initLiveStats(); });

/* === THREAT TICKER === */
function initThreatTicker(){
    var inner=document.getElementById('ticker-inner');
    if(!inner)return;
    var fallback=[
        {tag:'block',tagLabel:'SHIELD AKTIV',text:'Angriffsoberfläche wird in Echtzeit überwacht',time:'LIVE'},
        {tag:'cve',tagLabel:'CISA-RADAR',text:'Known-Exploited CVEs werden kontinuierlich aktualisiert',time:'LIVE'},
        {tag:'darkweb',tagLabel:'RANSOMWARE',text:'Ransomware-Gruppen und Opfer werden verfolgt',time:'LIVE'},
        {tag:'block',tagLabel:'MALWARE',text:'Malware-URLs aus abuse.ch URLhaus täglich aktuell',time:'LIVE'},
        {tag:'ok',tagLabel:'NIS2',text:'NIS2-konforme Überwachung und Compliance-Reports',time:'24/7'},
        {tag:'cve',tagLabel:'CVE-RADAR',text:'Kritische Schwachstellen — CVSS ≥9.0 täglich geprüft',time:'LIVE'},
        {tag:'block',tagLabel:'C2-AKTIV',text:'Botnet-C2-Server via Feodo Tracker überwacht',time:'LIVE'},
        {tag:'ok',tagLabel:'SHIELD OK',text:'kyberguard.de TLS 1.3 aktiv — Verbindung gesichert',time:'LIVE'}
    ];
    function buildSet(items){
        items.forEach(function(ev){
            var item=document.createElement('span');item.className='ticker-item';
            var tag=document.createElement('span');tag.className='ti-tag '+ev.tag;tag.textContent=ev.tagLabel;
            var arrow=document.createElement('span');arrow.className='ti-arrow';arrow.textContent='◄';
            var text=document.createElement('span');text.textContent=ev.text;
            var time=document.createElement('span');time.className='ti-time';time.textContent=ev.time;
            item.appendChild(tag);item.appendChild(arrow);item.appendChild(text);item.appendChild(time);
            inner.appendChild(item);
        });
    }
    buildSet(fallback);buildSet(fallback);
}

/* === MAGNETIC CURSOR === */
(function(){
    var orb=document.getElementById('cursor-orb');
    if(!orb)return;
    var cx=window.innerWidth/2,cy=window.innerHeight/2,tx=cx,ty=cy;
    document.addEventListener('mousemove',function(e){tx=e.clientX;ty=e.clientY;});
    function lerp(a,b,t){return a+(b-a)*t;}
    function upd(){cx=lerp(cx,tx,.2);cy=lerp(cy,ty,.2);orb.style.transform='translate('+cx+'px,'+cy+'px) translate(-50%,-50%)';requestAnimationFrame(upd);}
    upd();
    document.querySelectorAll('a,button,.pricing-card,.holo-card').forEach(function(el){
        el.addEventListener('mouseenter',function(){orb.classList.add('big');});
        el.addEventListener('mouseleave',function(){orb.classList.remove('big');});
    });
})();

/* === NAV SCROLL === */
(function(){
    var nav=document.getElementById('main-nav');
    if(!nav)return;
    window.addEventListener('scroll',function(){nav.classList.toggle('scrolled',window.scrollY>60);},{passive:true});
})();

/* === HAMBURGER MOBILE MENU === */
(function(){
    var btn=document.getElementById('nav-hamburger');
    var panel=document.getElementById('nav-mobile');
    if(!btn||!panel)return;
    btn.addEventListener('click',function(e){
        e.stopPropagation();
        var open=btn.classList.toggle('open');
        panel.classList.toggle('open',open);
        btn.setAttribute('aria-label',open?'Menü schließen':'Menü öffnen');
    });
    panel.querySelectorAll('a').forEach(function(a){
        a.addEventListener('click',function(){btn.classList.remove('open');panel.classList.remove('open');});
    });
    document.addEventListener('click',function(e){
        if(!btn.contains(e.target)&&!panel.contains(e.target)){btn.classList.remove('open');panel.classList.remove('open');}
    });
})();

/* === HOLOGRAPHIC CARDS === */
(function(){
    document.querySelectorAll('.holo-card,.pricing-card').forEach(function(c){
        var tx=0,ty=0,cx=0,cy=0,raf=null,inside=false;
        function lerp(a,b,t){return a+(b-a)*t;}
        function tick(){
            cx=lerp(cx,tx,.12);cy=lerp(cy,ty,.12);
            c.style.transform='perspective(900px) rotateX('+cy+'deg) rotateY('+cx+'deg) translateZ(8px)';
            if(Math.abs(cx-tx)<.01&&Math.abs(cy-ty)<.01&&!inside){c.style.transform='';raf=null;return;}
            raf=requestAnimationFrame(tick);
        }
        c.addEventListener('mousemove',function(e){
            var r=c.getBoundingClientRect();
            var nx=(e.clientX-r.left)/r.width-0.5,ny=(e.clientY-r.top)/r.height-0.5;
            tx=nx*12;ty=ny*-12;
            c.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');
            c.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%');
            c.style.setProperty('--shimmer','1');
            if(!raf)raf=requestAnimationFrame(tick);
        });
        c.addEventListener('mouseenter',function(){inside=true;});
        c.addEventListener('mouseleave',function(){
            inside=false;tx=0;ty=0;
            c.style.setProperty('--shimmer','0');
            if(!raf)raf=requestAnimationFrame(tick);
        });
    });
})();

/* === ATTACK COUNTER — Wert kommt von initLiveStats via HYDRA-EYE === */
(function(){
    var el=document.getElementById('attack-counter');
    if(el)el.textContent='...';
})();

/* === STATS COUNT-UP === */
function initStatsCountUp(){
    var items=document.querySelectorAll('.stat-num[data-count]');
    if(!items.length)return;
    if(!('IntersectionObserver' in window)){
        items.forEach(function(el){el.textContent=Number(el.dataset.count).toLocaleString('de-DE');});
        return;
    }
    var obs=new IntersectionObserver(function(entries){
        entries.forEach(function(e){
            if(!e.isIntersecting)return;
            obs.unobserve(e.target);
            var target=parseInt(e.target.dataset.count);
            var duration=1800,start=performance.now();
            function tick(now){
                var p=Math.min((now-start)/duration,1);
                var eased=1-Math.pow(1-p,3);
                e.target.textContent=Math.floor(eased*target).toLocaleString('de-DE');
                if(p<1)requestAnimationFrame(tick);
                else e.target.textContent=target.toLocaleString('de-DE');
            }
            requestAnimationFrame(tick);
        });
    },{threshold:.3});
    items.forEach(function(el){obs.observe(el);});
}

/* === REVEAL === */
(function(){
    var items=document.querySelectorAll('.reveal');
    if(!('IntersectionObserver' in window)){items.forEach(function(el){el.classList.add('visible');});return;}
    var obs=new IntersectionObserver(function(entries){entries.forEach(function(e){if(e.isIntersecting){e.target.classList.add('visible');obs.unobserve(e.target);}});},{threshold:.1});
    items.forEach(function(el){obs.observe(el);});
})();

/* === PRICING TOGGLE === */
(function(){
    var toggle=document.getElementById('billing-toggle');
    var lblM=document.getElementById('lbl-monthly');
    var lblY=document.getElementById('lbl-yearly');
    if(!toggle)return;
    var prices={personal:{monthly:'4,99 €',yearly:'4,16 €'},family:{monthly:'9,99 €',yearly:'8,33 €'},pro:{monthly:'34,99 €',yearly:'29,16 €'},business:{monthly:'99,99 €',yearly:'83,33 €'},enterprise:{monthly:'299 €',yearly:'249 €'}};
    var periods={monthly:'pro Monat, monatlich kündbar',yearly:'pro Monat, jährlich abgerechnet'};
    function upd(){
        var y=toggle.checked;var m=y?'yearly':'monthly';
        lblM.classList.toggle('active',!y);lblY.classList.toggle('active',y);
        ['personal','family','pro','business','enterprise'].forEach(function(p){
            var pe=document.getElementById('price-'+p);var pr=document.getElementById('period-'+p);
            if(!pe||!pr)return;
            var v=prices[p][m];var parts=v.split(',');
            pe.textContent='';pe.appendChild(document.createTextNode(parts[0]));
            var sp=document.createElement('span');sp.textContent=parts.length===2?','+parts[1]:' /M';pe.appendChild(sp);
            pr.textContent=p==='enterprise'?(y?'pro Monat, jährlich, auf Anfrage':'pro Monat, auf Anfrage'):periods[m];
        });
    }
    toggle.addEventListener('change',upd);
})();

/* === FAQ === */
(function(){
    document.querySelectorAll('.faq-item').forEach(function(item){
        item.querySelector('.faq-q').addEventListener('click',function(){
            var wasOpen=item.classList.contains('open');
            document.querySelectorAll('.faq-item').forEach(function(i){i.classList.remove('open');});
            if(!wasOpen)item.classList.add('open');
        });
    });
})();

/* === DOMAIN SCAN === */
(function(){
    var DOMAIN_RE=/^(?!-)[A-Za-z0-9\-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9\-]{1,63}(?<!-))*\.[A-Za-z]{2,}$/;
    var API='/api/public/quick-scan';
    var input=document.getElementById('domain-input');
    var btn=document.getElementById('scan-btn');
    var btnText=document.getElementById('scan-btn-text');
    var spinner=document.getElementById('scan-spinner');
    var resultsEl=document.getElementById('scan-results');
    var errorEl=document.getElementById('scan-error');
    var findingsList=document.getElementById('scan-findings-list');
    var scanBox=document.querySelector('.scan-box');
    if(!input||!btn)return;
    function san(s){var d=document.createElement('div');d.textContent=s;return d.textContent;}
    function setLoad(a){
        btn.disabled=a;spinner.style.display=a?'block':'none';
        btnText.textContent=a?'Analysiere...':'Kostenloser Scan';
        if(scanBox)scanBox.classList.toggle('scan-active',a);
    }
    function showErr(m){errorEl.textContent=san(m);errorEl.style.display='block';resultsEl.style.display='none';}
    function hideErr(){errorEl.style.display='none';}
    function riskColor(s){return s>=7?'var(--red)':s>=4?'var(--amber)':'var(--green)';}
    function riskLabel(s){return s>=7?{t:'Hohes Risiko',c:'risk-high'}:s>=4?{t:'Mittleres Risiko',c:'risk-medium'}:{t:'Niedriges Risiko',c:'risk-low'};}
    function renderResults(domain,data){
        var score=Math.min(10,Math.max(0,parseFloat(data.risk_score)||5));
        var circ=251,offset=circ-(score/10)*circ;
        document.getElementById('risk-arc').style.strokeDashoffset=offset;
        document.getElementById('risk-arc').style.stroke=riskColor(score);
        document.getElementById('risk-score-num').textContent=score.toFixed(1);
        document.getElementById('risk-score-num').style.color=riskColor(score);
        var rl=riskLabel(score);
        document.getElementById('risk-label').textContent=rl.t;
        document.getElementById('risk-label').className='scan-risk-label '+rl.c;
        document.getElementById('result-domain').textContent=san(domain);
        var mf=document.getElementById('more-findings-text');
        if(data.more_findings)mf.textContent=san(data.more_findings)+' weitere Findings';
        findingsList.innerHTML='';
        var findings=Array.isArray(data.findings)?data.findings.slice(0,4):[];
        var iconMap={ok:'✅',warning:'⚠️',critical:'❌',info:'ℹ️'};
        var sevMap={ok:'sev-ok',warning:'sev-warning',critical:'sev-critical',info:'sev-ok'};
        var sevLbl={ok:'OK',warning:'Warnung',critical:'Kritisch',info:'Info'};
        findings.forEach(function(f,i){
            var sev=['ok','warning','critical','info'].indexOf(f.severity)>=0?f.severity:'warning';
            var item=document.createElement('div');item.className='finding-item';item.style.animationDelay=(i*.12)+'s';
            var ic=document.createElement('span');ic.className='finding-icon';ic.textContent=iconMap[sev];
            var tx=document.createElement('span');tx.className='finding-text';tx.textContent=san(f.text||'');
            var sv=document.createElement('span');sv.className='finding-severity '+sevMap[sev];sv.textContent=sevLbl[sev];
            item.appendChild(ic);item.appendChild(tx);item.appendChild(sv);findingsList.appendChild(item);
        });
        resultsEl.style.display='block';
        resultsEl.scrollIntoView({behavior:'smooth',block:'nearest'});
    }
    function doScan(){
        hideErr();
        var cb=document.getElementById('scan-consent-cb');
        if(cb&&!cb.checked){showErr('Bitte bestätigen Sie, dass Sie Inhaber dieser Domain sind oder eine Einwilligung des Inhabers vorliegt.');input.focus();return;}
        var raw=input.value.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/$/,'');
        if(!raw){showErr('Bitte geben Sie eine Domain ein, z. B. meinefirma.de');input.focus();return;}
        if(!DOMAIN_RE.test(raw)){showErr('Ungültige Domain. Bitte Format prüfen: meinefirma.de');input.focus();return;}
        setLoad(true);resultsEl.style.display='none';
        fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:raw})})
        .then(function(r){if(!r.ok)throw new Error('HTTP-'+r.status);return r.json();})
        .then(function(data){
            setLoad(false);
            var sec=typeof data.security_score==='number'?data.security_score:5;
            var risk=Math.max(0,10-sec);
            var findings=[];var em=data.email_security||{};var hdr=data.headers||{};var ssl=data.ssl||{};
            if(ssl.valid===false)findings.push({severity:'critical',text:'SSL-Zertifikat ungültig oder fehlt'});
            if(ssl.valid&&ssl.days_remaining<30)findings.push({severity:'warning',text:'SSL läuft in '+ssl.days_remaining+' Tagen ab'});
            if(!em.dmarc)findings.push({severity:'critical',text:'DMARC fehlt — E-Mail-Spoofing möglich'});
            if(!em.spf)findings.push({severity:'critical',text:'SPF fehlt — gefälschte Mails in Ihrem Namen möglich'});
            if(!hdr.hsts)findings.push({severity:'warning',text:'HSTS fehlt — Downgrade-Angriffe möglich'});
            if(!hdr.csp)findings.push({severity:'warning',text:'Content-Security-Policy fehlt — XSS-Risiko'});
            if(!hdr.x_frame)findings.push({severity:'warning',text:'X-Frame-Options fehlt — Clickjacking möglich'});
            if(ssl.valid&&ssl.days_remaining>=30)findings.push({severity:'ok',text:'SSL gültig ('+ssl.days_remaining+' Tage)'});
            if(em.dmarc&&em.dmarc_policy==='reject')findings.push({severity:'ok',text:'DMARC aktiv mit Policy „reject“'});
            if(em.spf)findings.push({severity:'ok',text:'SPF-Eintrag vorhanden'});
            renderResults(raw,{risk_score:risk,more_findings:Math.max(0,findings.length-4),findings:findings});
        })
        .catch(function(e){setLoad(false);showErr('Scan-Fehler: '+(e&&e.message?e.message:String(e)));});
    }
    btn.addEventListener('click',doScan);
    input.addEventListener('keydown',function(e){if(e.key==='Enter')doScan();});
})();

/* === TERMINAL ANIMATION === */
(function(){
    var terminal=document.getElementById('terminal-body');
    if(!terminal)return;
    var lines=[
        {type:'prompt',text:'> Sicherheitsanalyse für musterfirma.de'},
        {type:'scanning',text:'█ Scanne externe Angriffsfläche...',delay:400},
        {type:'scanning',text:'█ Durchsuche 45 Dark-Web-Quellen nach Ihren Daten...',delay:900},
        {type:'scanning',text:'█ Prüfe bekannte Sicherheitslücken...',delay:1400},
        {type:'scanning',text:'█ Analysiere E-Mail-Schutz und offene Zugänge...',delay:1900},
        {type:'ok',text:'✓ Verbindung verschlüsselt — Ihre Website ist abhörsicher',delay:2600},
        {type:'warn',text:'⚠ 2 Firmen-E-Mails im Darknet — Passwörter in fremden Händen',delay:3100},
        {type:'critical',text:'✗ Kritisch: Angreifer können E-Mails in Ihrem Firmennamen versenden',delay:3700},
        {type:'critical',text:'✗ Webserver seit 18 Monaten ungepatcht — aktiv ausgenutzte Lücke',delay:4300},
        {type:'warn',text:'⚠ Interner Dienst versehentlich öffentlich erreichbar',delay:4900},
        {type:'result',text:'→ Risiko-Score: 72 / 100 — Sofortiger Handlungsbedarf',delay:5600},
        {type:'result',text:'→ NIS2-Konformität: 41 % — Bußgeld-Risiko bis 2 Mio. €',delay:6100}
    ];
    var classMap={prompt:'t-prompt',scanning:'t-scanning',ok:'t-ok',warn:'t-warn',critical:'t-critical',result:'t-result'};
    var cursor=document.createElement('span');cursor.className='t-cursor';
    var started=false;
    var obs=new IntersectionObserver(function(entries){if(entries[0].isIntersecting&&!started){started=true;obs.disconnect();run();}},{threshold:.3});
    obs.observe(terminal);
    function run(){
        terminal.innerHTML='';terminal.appendChild(cursor);
        var idx=0;
        function typeLine(ld,done){
            var sp=document.createElement('span');sp.className=classMap[ld.type]||'';
            terminal.insertBefore(sp,cursor);
            var ci=0,speed=ld.type==='prompt'?42:18;
            function tc(){if(ci<ld.text.length){sp.textContent+=ld.text[ci++];setTimeout(tc,speed+Math.random()*14);}else{terminal.insertBefore(document.createElement('br'),cursor);done();}}
            tc();
        }
        function next(){
            if(idx>=lines.length){cursor.style.display='none';return;}
            var ln=lines[idx++];
            var delay=idx===1?0:(ln.delay-(lines[idx-2].delay||0));
            setTimeout(function(){typeLine(ln,next);},Math.max(0,delay));
        }
        next();
    }
})();

/* === PHONE CHECK — URL relativ, funktioniert auf jeder Domain === */
(function(){
    var inp=document.getElementById('phone-input');
    var btn=document.getElementById('phone-btn');
    var errEl=document.getElementById('phone-error');
    var resEl=document.getElementById('phone-result');
    if(!inp||!btn)return;
    var ALLOWED_RISK_CLASSES=['pr-risk-high','pr-risk-mid','pr-risk-low'];
    function row(l,v,c){
        var div=document.createElement('div');div.className='pr-row';
        var lbl=document.createElement('span');lbl.className='pr-label';lbl.textContent=String(l);
        var val=document.createElement('span');
        val.className='pr-val'+(ALLOWED_RISK_CLASSES.indexOf(c)>=0?' '+c:'');
        val.textContent=String(v);
        div.appendChild(lbl);div.appendChild(val);return div;
    }
    var PHONE_RE=/^\+?[\d\s\-().]{7,20}$/;
    async function doCheck(){
        var ph=inp.value.trim();if(!ph)return;
        if(!PHONE_RE.test(ph)){errEl.textContent='Ungültige Telefonnummer. Format: +49 123 456789';return;}
        errEl.textContent='';resEl.style.display='none';btn.disabled=true;btn.textContent='...';
        try{
            /* Relative URL — kein CORS-Problem, funktioniert auf kyberguard.de */
            var resp=await fetch('/api/public/phone-check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:ph})});
            var data=await resp.json();
            if(!resp.ok){errEl.textContent=String(data.error||'Fehler beim Abruf.').slice(0,120);}
            else{
                var rc=data.risk_level==='hoch'?'pr-risk-high':data.risk_level==='mittel'?'pr-risk-mid':'pr-risk-low';
                var rl=data.risk_level==='hoch'?'⚠ Hoch':data.risk_level==='mittel'?'~ Mittel':'✓ Niedrig';
                resEl.textContent='';
                [row('Gültig',data.valid?'✓ Ja':'✗ Nein'),
                 row('Format',data.formatted||'—'),
                 row('Land',data.region||'—'),
                 row('Typ',data.line_type||'—'),
                 row('Carrier',data.carrier||'—'),
                 row('Risiko',rl,rc)
                ].forEach(function(el){resEl.appendChild(el);});
                if(data.risk_flags&&data.risk_flags.length){
                    var flags=document.createElement('div');flags.className='pr-flags';
                    data.risk_flags.forEach(function(f){
                        var sp=document.createElement('span');sp.textContent='⚠ '+String(f);
                        flags.appendChild(sp);flags.appendChild(document.createElement('br'));
                    });
                    resEl.appendChild(flags);
                }
                resEl.style.display='block';
            }
        }catch(e){errEl.textContent='Verbindungsfehler. Bitte erneut versuchen.';}
        btn.disabled=false;btn.textContent='Prüfen';
    }
    btn.addEventListener('click',doCheck);
    inp.addEventListener('keydown',function(e){if(e.key==='Enter')doCheck();});
})();

/* === KYBERASSIST CHAT === */
(function(){
    var inp=document.getElementById('kyberassist-input');
    var snd=document.getElementById('kyberassist-send');
    var term=document.getElementById('terminal-body');
    if(!inp||!snd||!term)return;
    var EP='/n8n/webhook/landing-kyberassist';
    var SK='kyberassist_session';
    function getSid(){var s=sessionStorage.getItem(SK);if(!s){s=crypto.randomUUID();sessionStorage.setItem(SK,s);}return s;}
    function addLine(cls,txt){var sp=document.createElement('span');sp.className=cls;sp.textContent=txt;var br=document.createElement('br');term.appendChild(sp);term.appendChild(br);term.scrollTop=term.scrollHeight;}
    function san(s){var d=document.createElement('div');d.textContent=s;return d.textContent;}
    function setLoad(a){snd.disabled=a;inp.disabled=a;}
    async function send(){
        var msg=inp.value.trim();if(!msg||snd.disabled)return;
        inp.value='';addLine('t-user','> '+san(msg.slice(0,120)));setLoad(true);
        var th=document.createElement('span');th.className='t-thinking';th.textContent='▌ KyberAssist analysiert...';
        term.appendChild(th);term.appendChild(document.createElement('br'));term.scrollTop=term.scrollHeight;
        try{
            var resp=await fetch(EP,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:getSid(),message:msg.slice(0,500)})});
            th.remove();
            if(resp.status===429){addLine('t-warn','⚠ Rate-Limit erreicht. Bitte kurz warten.');}
            else if(!resp.ok){addLine('t-warn','⚠ KyberAssist aktuell nicht erreichbar.');}
            else{
                var data=await resp.json();
                var ans=data.message||data.response||'Keine Antwort erhalten.';
                ans.split('\n').forEach(function(l){if(l.trim())addLine('t-ai',san(l));});
                if(data.cta&&data.cta.text)addLine('t-result','→ '+san(data.cta.text)+': kyberguard.de/register');
            }
        }catch(e){th.remove();addLine('t-warn','⚠ Verbindungsfehler.');}
        setLoad(false);inp.focus();
    }
    snd.addEventListener('click',send);
    inp.addEventListener('keydown',function(e){if(e.key==='Enter')send();});
})();

/* === NETZWERK-CANVAS — 3 Farben: Cyan (normal), Grün (protected), Rot (threat) === */
function initNetCanvas(){
    var c=document.getElementById('net-canvas');
    if(!c)return;
    var ctx=c.getContext('2d');
    var W=c.width=window.innerWidth,H=c.height=window.innerHeight;

    var N=60,DIST=175,PDIST=145;
    var nodes=[];
    for(var i=0;i<N;i++){
        var isThreat=Math.random()<0.18;
        /* Von den nicht-Bedrohungs-Knoten sind ~30% grün (protected) */
        var isProtected=!isThreat&&Math.random()<0.30;
        nodes.push({
            x:Math.random()*W, y:Math.random()*H,
            /* LANGSAM: war 0.22, jetzt 0.07 */
            vx:(Math.random()-.5)*0.07, vy:(Math.random()-.5)*0.07,
            r:isThreat?1.4+Math.random()*1.6 : (isProtected?1.1+Math.random()*1.2 : 0.8+Math.random()*1.2),
            pulse:Math.random()*Math.PI*2,
            type:isThreat?'threat':(isProtected?'protected':'normal'),
            blockTimer:0
        });
    }

    var packets=[],lastPkt=0,lastBlock=0;
    function addPkt(){
        var a=Math.floor(Math.random()*N),b=Math.floor(Math.random()*N);
        if(a!==b){
            var dx=nodes[a].x-nodes[b].x,dy=nodes[a].y-nodes[b].y;
            if(Math.sqrt(dx*dx+dy*dy)<PDIST)
                packets.push({a:nodes[a],b:nodes[b],t:0,s:.004+Math.random()*.004});
        }
    }
    function triggerBlock(){
        var threats=[];
        for(var ii=0;ii<N;ii++)if(nodes[ii].type==='threat'&&nodes[ii].blockTimer<=0)threats.push(ii);
        if(threats.length){
            var idx=threats[Math.floor(Math.random()*threats.length)];
            nodes[idx].blockTimer=120; /* ~2.7s — länger sichtbar als vorher */
        }
    }

    var lastF=0;
    function draw(ts){
        requestAnimationFrame(draw);
        if(ts-lastF<22)return;
        lastF=ts;
        if(ts-lastPkt>900){addPkt();if(packets.length>20)packets.shift();lastPkt=ts;}
        if(ts-lastBlock>3200){triggerBlock();lastBlock=ts;}
        ctx.clearRect(0,0,W,H);

        nodes.forEach(function(n){
            n.x+=n.vx;n.y+=n.vy;n.pulse+=.018;
            if(n.blockTimer>0)n.blockTimer--;
            if(n.x<0||n.x>W)n.vx*=-1;
            if(n.y<0||n.y>H)n.vy*=-1;
        });

        /* Verbindungen */
        for(var i=0;i<N;i++){
            for(var j=i+1;j<N;j++){
                var dx=nodes[i].x-nodes[j].x,dy=nodes[i].y-nodes[j].y,d=Math.sqrt(dx*dx+dy*dy);
                if(d<DIST){
                    var op=(1-d/DIST)*.12;
                    var iT=(nodes[i].type==='threat'&&nodes[i].blockTimer<=0);
                    var jT=(nodes[j].type==='threat'&&nodes[j].blockTimer<=0);
                    var iP=(nodes[i].type==='protected'||(nodes[i].type==='threat'&&nodes[i].blockTimer>0));
                    var jP=(nodes[j].type==='protected'||(nodes[j].type==='threat'&&nodes[j].blockTimer>0));
                    var col;
                    if(iT||jT)col='rgba(255,0,80,'+op+')';
                    else if(iP||jP)col='rgba(0,255,136,'+op+')';
                    else col='rgba(0,240,255,'+op+')';
                    ctx.strokeStyle=col;ctx.lineWidth=.5;
                    ctx.beginPath();ctx.moveTo(nodes[i].x,nodes[i].y);ctx.lineTo(nodes[j].x,nodes[j].y);ctx.stroke();
                }
            }
        }

        /* Knoten */
        nodes.forEach(function(n){
            var glow,color;
            if(n.blockTimer>0){
                /* Geblockt — leuchtet grün */
                glow=.45+.3*Math.sin(n.pulse*2.2);color='0,255,136';
                ctx.beginPath();ctx.arc(n.x,n.y,n.r+4+Math.sin(n.pulse*3)*2,0,Math.PI*2);
                ctx.strokeStyle='rgba(0,255,136,'+(n.blockTimer/120*.45)+')';
                ctx.lineWidth=1.2;ctx.stroke();
            } else if(n.type==='threat'){
                /* Bedrohung — rot, stärker pulsierend */
                glow=.38+.28*Math.sin(n.pulse*2);color='255,0,80';
            } else if(n.type==='protected'){
                /* Geschützt — grün */
                glow=.25+.12*Math.sin(n.pulse*1.5);color='0,255,136';
            } else {
                /* Normal — cyan */
                glow=.18+.08*Math.sin(n.pulse);color='0,240,255';
            }
            ctx.beginPath();ctx.arc(n.x,n.y,n.r,0,Math.PI*2);
            ctx.fillStyle='rgba('+color+','+glow+')';ctx.fill();
        });

        /* Datenpakete */
        packets=packets.filter(function(p){
            p.t+=p.s;if(p.t>=1)return false;
            var x=p.a.x+(p.b.x-p.a.x)*p.t,y=p.a.y+(p.b.y-p.a.y)*p.t;
            var isEvil=p.a.type==='threat'&&p.a.blockTimer<=0;
            var col=isEvil?'255,0,80':'0,255,136';
            ctx.beginPath();ctx.arc(x,y,2.2,0,Math.PI*2);
            ctx.fillStyle='rgba('+col+',.9)';ctx.fill();
            ctx.beginPath();ctx.arc(x,y,4.5,0,Math.PI*2);
            ctx.fillStyle='rgba('+col+',.12)';ctx.fill();
            return true;
        });
    }
    requestAnimationFrame(draw);
    window.addEventListener('resize',function(){W=c.width=window.innerWidth;H=c.height=window.innerHeight;},{passive:true});
}

/* === THREE.JS CYBER GLOBE 3D/4D === */
function initHeroCanvas(){
    var canvas=document.getElementById('hero-canvas');
    if(!canvas||typeof THREE==='undefined')return;
    var W=window.innerWidth,H=window.innerHeight;
    var isMob=W<768;

    var renderer=new THREE.WebGLRenderer({canvas:canvas,antialias:!isMob,alpha:true,powerPreference:'default'});
    renderer.setPixelRatio(Math.min(window.devicePixelRatio,1.5));
    renderer.setSize(W,H);renderer.setClearColor(0x000000,0);
    var scene=new THREE.Scene();
    var camera=new THREE.PerspectiveCamera(50,W/H,0.1,200);
    camera.position.set(0,0,9);

    var R=2.8; // Globus-Radius
    var globeGrp=new THREE.Group();
    scene.add(globeGrp);

    /* Hilfsfunktion Lat/Lon → Vector3 */
    function ll2v(lat,lon,r){
        var phi=(90-lat)*Math.PI/180,theta=lon*Math.PI/180;
        return new THREE.Vector3(r*Math.sin(phi)*Math.cos(theta),r*Math.cos(phi),r*Math.sin(phi)*Math.sin(theta));
    }

    /* --- Sternfeld (dreifarbig) --- */
    var sN=900,sPos=new Float32Array(sN*3),sCol=new Float32Array(sN*3);
    for(var i=0;i<sN;i++){
        var rr=65+Math.random()*110,th2=Math.random()*Math.PI*2,ph2=Math.acos(-1+2*Math.random());
        sPos[i*3]=rr*Math.sin(ph2)*Math.cos(th2);sPos[i*3+1]=rr*Math.sin(ph2)*Math.sin(th2);sPos[i*3+2]=rr*Math.cos(ph2);
        var t=Math.random();
        if(t<.55){sCol[i*3]=0;sCol[i*3+1]=.94;sCol[i*3+2]=1;}
        else if(t<.78){sCol[i*3]=1;sCol[i*3+1]=1;sCol[i*3+2]=1;}
        else{sCol[i*3]=.63;sCol[i*3+1]=.13;sCol[i*3+2]=1;}
    }
    var sGeo=new THREE.BufferGeometry();
    sGeo.setAttribute('position',new THREE.Float32BufferAttribute(sPos,3));
    sGeo.setAttribute('color',new THREE.Float32BufferAttribute(sCol,3));
    scene.add(new THREE.Points(sGeo,new THREE.PointsMaterial({size:.075,transparent:true,opacity:.5,vertexColors:true})));

    /* --- Atmosphären-Glow (Halo) --- */
    var atmMat=new THREE.MeshBasicMaterial({color:0x0088FF,transparent:true,opacity:.042,side:THREE.BackSide});
    globeGrp.add(new THREE.Mesh(new THREE.SphereGeometry(R+.3,32,32),atmMat));

    /* --- Lat/Lon-Gitter --- */
    var gridMat=new THREE.LineBasicMaterial({color:0x00F0FF,transparent:true,opacity:.09});
    var gridMatEq=new THREE.LineBasicMaterial({color:0x00F0FF,transparent:true,opacity:.18}); // Äquator heller
    [-60,-30,0,30,60].forEach(function(lat){
        var pts=[],phi=(90-lat)*Math.PI/180,mat=lat===0?gridMatEq:gridMat;
        for(var a=0;a<=361;a+=3){var th=a*Math.PI/180;pts.push(new THREE.Vector3(R*Math.sin(phi)*Math.cos(th),R*Math.cos(phi),R*Math.sin(phi)*Math.sin(th)));}
        globeGrp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),mat));
    });
    for(var lon=0;lon<360;lon+=30){
        var pts=[],th=lon*Math.PI/180;
        for(var la=-90;la<=90;la+=3){var phi=(90-la)*Math.PI/180;pts.push(new THREE.Vector3(R*Math.sin(phi)*Math.cos(th),R*Math.cos(phi),R*Math.sin(phi)*Math.sin(th)));}
        globeGrp.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),gridMat));
    }

    /* --- Globus-Kern (Quantenfeld-Punkte) --- */
    var cN=900,cPos=new Float32Array(cN*3);
    for(var j=0;j<cN;j++){var phi=Math.acos(-1+(2*j)/cN),th=Math.sqrt(cN*Math.PI)*phi;cPos[j*3]=R*.97*Math.cos(th)*Math.sin(phi);cPos[j*3+1]=R*.97*Math.sin(th)*Math.sin(phi);cPos[j*3+2]=R*.97*Math.cos(phi);}
    var cGeo=new THREE.BufferGeometry();cGeo.setAttribute('position',new THREE.Float32BufferAttribute(cPos,3));
    var cMat=new THREE.PointsMaterial({color:0x0070FF,size:.026,transparent:true,opacity:.42});
    globeGrp.add(new THREE.Points(cGeo,cMat));

    /* --- Städte-Nodes [lat, lon, istAngriff, istDE] --- */
    var cities=[
        [51.2,10.5,false,true],    // Deutschland — Schutzknoten
        [40.7,-74.0,true,false],   // New York
        [34.1,-118.2,true,false],  // Los Angeles
        [35.7,139.7,true,false],   // Tokyo
        [31.2,121.5,true,false],   // Shanghai
        [55.8,37.6,true,false],    // Moskau
        [19.1,72.9,true,false],    // Mumbai
        [30.1,31.2,true,false],    // Kairo
        [6.5,3.4,true,false],      // Lagos
        [-33.9,151.2,true,false],  // Sydney
        [41.0,28.9,true,false],    // Istanbul
        [48.9,2.3,false,false],    // Paris
        [51.5,-0.1,false,false],   // London
        [52.5,13.4,false,false],   // Berlin
        [22.3,114.2,true,false],   // Hong Kong
        [-23.5,-46.6,true,false],  // São Paulo
        [37.6,127.0,true,false],   // Seoul
        [1.4,103.8,false,false],   // Singapur
        [59.3,18.1,false,false],   // Stockholm
        [43.7,-79.4,false,false],  // Toronto
        [25.2,55.3,true,false],    // Dubai
        [39.9,116.4,true,false],   // Beijing
        [28.6,77.2,true,false],    // Delhi
        [19.4,-99.1,true,false],   // Mexico City
        [-26.2,28.0,false,false],  // Johannesburg
        [50.8,4.4,false,false],    // Brüssel
        [47.4,8.5,false,false]     // Zürich
    ];

    var cityPos=[];
    var dotMats=[];
    cities.forEach(function(c){
        var pos=ll2v(c[0],c[1],R);
        cityPos.push(pos);
        var isDE=c[3],isAtk=c[2];
        var col=isDE?0x00F0FF:(isAtk?0xFF0050:0x00FF88);
        var sz=isDE?.075:.036;

        var dMat=new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:isDE?1:.82});
        var dot=new THREE.Mesh(new THREE.SphereGeometry(sz,8,8),dMat);
        dot.position.copy(pos);globeGrp.add(dot);

        var rMat=new THREE.MeshBasicMaterial({color:col,transparent:true,opacity:isDE?.4:.15});
        var ring=new THREE.Mesh(new THREE.TorusGeometry(sz+.09,.007,8,24),rMat);
        ring.position.copy(pos);ring.lookAt(pos.clone().multiplyScalar(2));
        globeGrp.add(ring);

        dotMats.push({dMat:dMat,rMat:rMat,isDE:isDE,isAtk:isAtk,ph:Math.random()*Math.PI*2});
    });

    var dePos=cityPos[0]; // Deutschland-Position

    /* --- Angriffs-Bögen (QuadraticBezierCurve3) --- */
    var atkIdx=[1,2,3,4,5,6,7,8,9,10,14,15,16,20,21,22,23];
    var arcs=[];
    atkIdx.forEach(function(ai,arcI){
        var src=cityPos[ai];
        var midH=R+1.6+Math.random()*1.6;
        var mid=src.clone().add(dePos.clone()).normalize().multiplyScalar(midH);
        var curve=new THREE.QuadraticBezierCurve3(src.clone(),mid,dePos.clone());
        var pts=curve.getPoints(80);
        var lMat=new THREE.LineBasicMaterial({color:0xFF1A33,transparent:true,opacity:0});
        var line=new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),lMat);
        globeGrp.add(line);

        /* Kopf-Partikel des Bogens */
        var pArr=new Float32Array(3);
        var pGeo=new THREE.BufferGeometry();
        pGeo.setAttribute('position',new THREE.BufferAttribute(pArr,3));
        var pMat=new THREE.PointsMaterial({color:0xFF4466,size:.22,transparent:true,opacity:0});
        var pPts=new THREE.Points(pGeo,pMat);
        globeGrp.add(pPts);

        /* Glow-Halo um den Kopf-Partikel */
        var hArr=new Float32Array(3);
        var hGeo=new THREE.BufferGeometry();
        hGeo.setAttribute('position',new THREE.BufferAttribute(hArr,3));
        var hMat=new THREE.PointsMaterial({color:0xFF0044,size:.55,transparent:true,opacity:0});
        var hPts=new THREE.Points(hGeo,hMat);
        globeGrp.add(hPts);

        /* Versetzt starten damit viele Bögen gleichzeitig sichtbar sind */
        var initialDelay=(arcI/(atkIdx.length))*14;

        arcs.push({curve:curve,line:line,pPts:pPts,pGeo:pGeo,pMat:pMat,lMat:lMat,
            hPts:hPts,hGeo:hGeo,hMat:hMat,
            t:0,active:false,timer:initialDelay});
    });

    /* --- Schutz-Schild (Icosahedron Wireframe) --- */
    var shMat=new THREE.MeshBasicMaterial({color:0x00F0FF,wireframe:true,transparent:true,opacity:.06});
    var shield=new THREE.Mesh(new THREE.IcosahedronGeometry(R+.72,2),shMat);
    globeGrp.add(shield);
    var sh2Mat=new THREE.MeshBasicMaterial({color:0xA020FF,wireframe:true,transparent:true,opacity:.033});
    var shield2=new THREE.Mesh(new THREE.IcosahedronGeometry(R+1.18,1),sh2Mat);
    globeGrp.add(shield2);

    /* --- Orbit-Ringe --- */
    var or1Mat=new THREE.MeshBasicMaterial({color:0x00F0FF,transparent:true,opacity:.17});
    var or1=new THREE.Mesh(new THREE.TorusGeometry(R+.98,.011,6,80),or1Mat);scene.add(or1);
    var or2Mat=new THREE.MeshBasicMaterial({color:0xA020FF,transparent:true,opacity:.10});
    var or2=new THREE.Mesh(new THREE.TorusGeometry(R+.44,.009,6,60),or2Mat);or2.rotation.x=Math.PI/3;scene.add(or2);
    var or3Mat=new THREE.MeshBasicMaterial({color:0x00FF88,transparent:true,opacity:.065});
    var or3=new THREE.Mesh(new THREE.TorusGeometry(R+1.48,.008,6,50),or3Mat);or3.rotation.x=Math.PI/5;or3.rotation.z=Math.PI/4;scene.add(or3);

    /* --- 4D Datenstrom-Partikel (entlang Meridianen, Zeitdimension) --- */
    var stN=isMob?55:115;
    var stArr=new Float32Array(stN*3);
    var stData=[];
    for(var i=0;i<stN;i++){
        var sLon=Math.floor(Math.random()*12)*30;
        var sLat=Math.random()*160-80;
        var sp2=ll2v(sLat,sLon,R+.06);
        stArr[i*3]=sp2.x;stArr[i*3+1]=sp2.y;stArr[i*3+2]=sp2.z;
        stData.push({lon:sLon,lat:sLat,spd:.55+Math.random()*1.45,dir:Math.random()<.5?1:-1});
    }
    var stGeo=new THREE.BufferGeometry();
    stGeo.setAttribute('position',new THREE.BufferAttribute(stArr,3));
    var stMat=new THREE.PointsMaterial({color:0x00FF88,size:.021,transparent:true,opacity:.38});
    globeGrp.add(new THREE.Points(stGeo,stMat));

    /* --- Energie-Pulse-Ringe um Deutschland (drei Schichten) --- */
    var pulseRing=new THREE.Mesh(
        new THREE.TorusGeometry(.28,.012,8,32),
        new THREE.MeshBasicMaterial({color:0x00F0FF,transparent:true,opacity:.55})
    );
    pulseRing.position.copy(dePos);
    pulseRing.lookAt(dePos.clone().multiplyScalar(2));
    globeGrp.add(pulseRing);

    /* Zweiter Pulse-Ring — langsam expandierend (DE-Schutzfeld) */
    var pulseRing2=new THREE.Mesh(
        new THREE.TorusGeometry(.45,.007,8,32),
        new THREE.MeshBasicMaterial({color:0x00F0FF,transparent:true,opacity:.25})
    );
    pulseRing2.position.copy(dePos);
    pulseRing2.lookAt(dePos.clone().multiplyScalar(2));
    globeGrp.add(pulseRing2);

    /* Dritter Ring — sehr groß, minimal opak (Ausbreitungs-Welle) */
    var pulseRing3=new THREE.Mesh(
        new THREE.TorusGeometry(.65,.005,8,32),
        new THREE.MeshBasicMaterial({color:0x00F0FF,transparent:true,opacity:.08})
    );
    pulseRing3.position.copy(dePos);
    pulseRing3.lookAt(dePos.clone().multiplyScalar(2));
    globeGrp.add(pulseRing3);

    /* Deutschland-Kern-Glow (Sphere) */
    var deGlow=new THREE.Mesh(
        new THREE.SphereGeometry(.15,16,16),
        new THREE.MeshBasicMaterial({color:0x00CCFF,transparent:true,opacity:.18,side:THREE.BackSide})
    );
    deGlow.position.copy(dePos);
    globeGrp.add(deGlow);

    var clock=new THREE.Clock();
    var mouse={x:0,y:0};
    var shieldFlash=0;
    document.addEventListener('mousemove',function(e){mouse.x=(e.clientX/window.innerWidth-.5)*2;mouse.y=-(e.clientY/window.innerHeight-.5)*2;},{passive:true});

    var lastF=0;
    function animate(ts){
        requestAnimationFrame(animate);
        if(ts-lastF<33)return;lastF=ts;
        var el=clock.getElapsedTime();

        /* Globus dreht sich, Deutschland startet frontal */
        globeGrp.rotation.y=-Math.PI/2+.18+el*.055;
        globeGrp.rotation.x=Math.sin(el*.018)*.06;

        /* Schild */
        shield.rotation.x=el*.068;shield.rotation.y=-el*.088;
        shMat.opacity=.05+.04*Math.sin(el*1.2)+(shieldFlash>.0?shieldFlash*.5:0);
        if(shieldFlash>0)shieldFlash=Math.max(0,shieldFlash-.035);
        shield2.rotation.x=el*.038;shield2.rotation.y=el*.055;

        /* Orbit-Ringe */
        or1.rotation.z=el*.042;or1.rotation.x=el*.022;
        or2.rotation.y=el*.058;
        or3.rotation.x=el*.026;or3.rotation.z=-el*.038;

        /* Atmosphäre */
        atmMat.opacity=.032+.014*Math.sin(el*1.5);

        /* Kamera-Maus */
        camera.position.x+=(mouse.x*1.45-camera.position.x)*.017;
        camera.position.y+=(mouse.y*.9-camera.position.y)*.017;
        camera.lookAt(0,0,0);

        /* 4D Datenstrom-Partikel */
        var sa=stGeo.attributes.position.array;
        for(var i=0;i<stN;i++){
            stData[i].lat+=stData[i].spd*stData[i].dir*.018;
            if(stData[i].lat>83){stData[i].lat=-83;stData[i].lon=Math.floor(Math.random()*12)*30;}
            if(stData[i].lat<-83){stData[i].lat=83;stData[i].lon=Math.floor(Math.random()*12)*30;}
            var sp3=ll2v(stData[i].lat,stData[i].lon,R+.065);
            sa[i*3]=sp3.x;sa[i*3+1]=sp3.y;sa[i*3+2]=sp3.z;
        }
        stGeo.attributes.position.needsUpdate=true;
        stMat.opacity=.28+.14*Math.sin(el*.85);

        /* Städte-Pulsieren */
        dotMats.forEach(function(dm){
            dm.ph+=.022;
            if(dm.isDE){dm.dMat.opacity=.82+.18*Math.sin(dm.ph*2.1);dm.rMat.opacity=.2+.2*Math.sin(dm.ph*1.6);}
            else if(dm.isAtk){dm.dMat.opacity=.55+.3*Math.sin(dm.ph*1.9);}
        });

        /* Deutschland Pulse-Ringe — drei Schichten */
        pulseRing.scale.setScalar(1+.14*Math.sin(el*2.6));
        pulseRing.material.opacity=.45+.25*Math.sin(el*2.6);
        pulseRing2.scale.setScalar(1+.09*Math.sin(el*2.6+1.2));
        pulseRing2.material.opacity=.18+.12*Math.sin(el*1.8+0.8);
        pulseRing3.scale.setScalar(1+.06*Math.sin(el*1.9+2.1));
        pulseRing3.material.opacity=.06+.05*Math.sin(el*1.4+1.5);
        /* Deutschland-Kern-Glow pulsiert mit Angriffen */
        deGlow.material.opacity=.12+.10*Math.sin(el*2.2)+(shieldFlash*0.3);

        /* Angriffs-Bögen animieren — schneller und dramatischer */
        arcs.forEach(function(arc){
            if(!arc.active){
                arc.timer-=.033;
                if(arc.timer<=0){arc.active=true;arc.t=0;arc.lMat.opacity=0;arc.pMat.opacity=0;arc.hMat.opacity=0;}
                return;
            }
            /* Schneller: 0.0065 → 0.0085, mehr Angriffs-Dynamik */
            arc.t+=.0085+Math.random()*.004;
            var prog=Math.min(arc.t,1);
            /* Fade-Kurve: schnell einblenden, dann Plateau, dann abblenden */
            var fade=Math.min(prog*5,.78)*(1-Math.max(0,(prog-.75)/.25));
            arc.lMat.opacity=fade*.58;
            arc.pMat.opacity=Math.min(fade*1.2,1);
            /* Glow-Halo ebenfalls animieren */
            arc.hMat.opacity=fade*.35;
            var pt=arc.curve.getPointAt(prog);
            var pa2=arc.pGeo.attributes.position.array;
            pa2[0]=pt.x;pa2[1]=pt.y;pa2[2]=pt.z;
            arc.pGeo.attributes.position.needsUpdate=true;
            var ha=arc.hGeo.attributes.position.array;
            ha[0]=pt.x;ha[1]=pt.y;ha[2]=pt.z;
            arc.hGeo.attributes.position.needsUpdate=true;
            if(prog>=1){
                arc.active=false;
                /* Schnellerer Reset: 3-8s statt 5-14s → mehr Bögen gleichzeitig */
                arc.timer=3+Math.random()*5;
                arc.lMat.opacity=0;arc.pMat.opacity=0;arc.hMat.opacity=0;
                shieldFlash=1;
            }
        });

        /* Quantenfeld */
        cMat.opacity=.36+.12*Math.sin(el*1.55);

        renderer.render(scene,camera);
    }
    requestAnimationFrame(animate);

    window.addEventListener('resize',function(){
        W=window.innerWidth;H=window.innerHeight;isMob=W<768;
        camera.aspect=W/H;camera.updateProjectionMatrix();
        renderer.setPixelRatio(Math.min(window.devicePixelRatio,1.5));
        renderer.setSize(W,H);
    },{passive:true});
}

/* === LIFE ENHANCEMENTS === */
function initLifeEnhancements(){
    _initTypingHero();
    _initStaggerDelays();
    _initHoloScanLines();
    _initGlowingDividers();
    _initScanProgress();
}

function _initTypingHero(){
    var el=document.querySelector('.hero-sub');
    if(!el)return;
    var fullText=el.textContent;
    el.style.minHeight=el.getBoundingClientRect().height+'px';
    el.textContent='';
    var i=0;
    function typeNext(){
        if(i>=fullText.length)return;
        el.textContent+=fullText[i];
        var ch=fullText[i];
        i++;
        var delay=ch===','?120:ch===':'?150:ch==='.'?200:22;
        setTimeout(typeNext,delay);
    }
    setTimeout(typeNext,1100);
}

function _initStaggerDelays(){
    document.querySelectorAll('.warning-cards .warning-card').forEach(function(el,i){
        el.style.transitionDelay=(i*0.09)+'s';
    });
    document.querySelectorAll('.how-steps .how-step').forEach(function(el,i){
        el.style.transitionDelay=(i*0.11)+'s';
    });
    /* stat-items: eigener Observer — kein .reveal (würde items dauerhaft verstecken) */
    var statsSection=document.getElementById('statistiken');
    if(!statsSection||!('IntersectionObserver' in window))return;
    var statItems=document.querySelectorAll('.stat-item');
    statItems.forEach(function(el){
        el.style.opacity='0';
        el.style.transform='translateY(18px)';
        el.style.transition='opacity .55s ease, transform .55s ease';
    });
    var obs=new IntersectionObserver(function(entries){
        entries.forEach(function(e){
            if(!e.isIntersecting)return;
            statItems.forEach(function(el,i){
                el.style.transitionDelay=(i*0.1)+'s';
                el.style.opacity='1';
                el.style.transform='translateY(0)';
            });
            obs.unobserve(e.target);
        });
    },{threshold:0.2});
    obs.observe(statsSection);
}

function _initHoloScanLines(){
    document.querySelectorAll('.holo-card').forEach(function(card){
        var scan=document.createElement('div');
        scan.className='holo-scan';
        card.appendChild(scan);
    });
}

function _initGlowingDividers(){
    if(!('IntersectionObserver' in window))return;
    var obs=new IntersectionObserver(function(entries){
        entries.forEach(function(e){
            if(e.isIntersecting){
                e.target.classList.add('lit');
                obs.unobserve(e.target);
            }
        });
    },{threshold:0.6});
    document.querySelectorAll('.cyber-divider').forEach(function(d){obs.observe(d);});
}

function _initScanProgress(){
    var scanBox=document.querySelector('.scan-box');
    var scanNote=document.querySelector('.scan-box .scan-note');
    if(!scanBox||!scanNote)return;

    var phases=['SSL/TLS-Prüfung','DMARC/SPF-Check','Header-Analyse','Dark-Web-Abfrage','Risiko-Score'];
    var progWrap=document.createElement('div');
    progWrap.className='scan-progress';
    progWrap.innerHTML='<div class="scan-pb"><div class="scan-pb-fill" id="spb-fill"></div></div>'
        +'<div class="scan-steps">'
        +phases.map(function(p){return '<span class="scan-step">'+p+'</span>';}).join('')
        +'</div>';
    scanBox.insertBefore(progWrap,scanNote);

    var fill=document.getElementById('spb-fill');
    var steps=progWrap.querySelectorAll('.scan-step');
    var timer=null;
    var phase=0;

    function resetProgress(){
        progWrap.style.display='none';
        fill.style.width='0';
        steps.forEach(function(s){s.className='scan-step';});
        phase=0;
    }

    function advancePhase(){
        if(phase>0) steps[phase-1].className='scan-step s-done';
        if(phase<steps.length){
            steps[phase].className='scan-step s-active';
            fill.style.width=Math.round(((phase+1)/steps.length)*100)+'%';
            phase++;
            timer=setTimeout(advancePhase,850);
        }
    }

    function completeAll(){
        clearTimeout(timer);
        steps.forEach(function(s){s.className='scan-step s-done';});
        fill.style.width='100%';
        setTimeout(resetProgress,1800);
    }

    var obs=new MutationObserver(function(){
        var active=scanBox.classList.contains('scan-active');
        if(active&&phase===0){
            progWrap.style.display='block';
            advancePhase();
        } else if(!active&&phase>0){
            completeAll();
        }
    });
    obs.observe(scanBox,{attributes:true,attributeFilter:['class']});
}

/* === LIVE STATS — HYDRA-EYE verdrahten (echte Daten, kein Fake) === */
function initLiveStats(){
    var STATS='/api/public/stats';
    var STREAM='/api/public/stream';

    function fmt(v){
        return(v===null||v===undefined)?'—':Math.round(v).toLocaleString('de-DE');
    }

    function applyMetrics(data){
        var m=data&&data.metrics;if(!m)return;

        // HUD Attack-Counter
        var ac=document.getElementById('attack-counter');
        var cs=m.crowdsec_blocked;
        if(ac&&cs&&cs.status!=='unavailable'&&cs.value!==null)ac.textContent=fmt(cs.value);

        // Hero CVE-Stat
        var hc=document.getElementById('hero-cve-count');
        var kev=m.cisa_kev;
        if(hc&&kev&&kev.status!=='unavailable'&&kev.value!==null)hc.textContent=fmt(kev.value);

        // Stats-Section
        [['stat-threats',m.crowdsec_blocked],['stat-cisa-kev',m.cisa_kev],['stat-urlhaus',m.urlhaus_24h]].forEach(function(p){
            var el=document.getElementById(p[0]);var met=p[1];if(!el||!met)return;
            el.textContent=(met.status==='unavailable'||met.value===null)?'—':fmt(met.value);
        });

        rebuildLiveTicker(m);
    }

    function rebuildLiveTicker(m){
        var inner=document.getElementById('ticker-inner');if(!inner)return;
        var items=[];

        var cs=m.crowdsec_blocked;
        if(cs&&cs.status==='ok'&&cs.value!==null){
            var sc=cs.extra&&cs.extra.top_scenarios||[];
            items.push({tag:'block',tagLabel:'IP GEBLOCKT',text:fmt(cs.value)+' IPs heute blockiert',time:'JETZT LIVE'});
            if(sc[0])items.push({tag:'block',tagLabel:sc[0][0].replace(/[^a-zA-Z0-9:\-]/g,'').slice(0,12).toUpperCase(),
                text:fmt(sc[0][1])+' '+sc[0][0]+'-Angriffe blockiert',time:'LIVE'});
        }
        var uh=m.urlhaus_24h;
        if(uh&&uh.status==='ok'&&uh.value!==null)
            items.push({tag:'block',tagLabel:'MALWARE',text:fmt(uh.value)+' neue Malware-URLs (24h) — abuse.ch',time:'LIVE'});
        var kev=m.cisa_kev;
        if(kev&&kev.status==='ok'&&kev.value!==null)
            items.push({tag:'cve',tagLabel:'CISA-RADAR',text:fmt(kev.value)+' Known-Exploited CVEs gelistet',time:'LIVE'});
        var rw=m.ransomware_30d;
        if(rw&&rw.status==='ok'&&rw.value!==null){
            var grp=rw.extra&&rw.extra.top_groups||[];
            items.push({tag:'darkweb',tagLabel:'RANSOMWARE',text:fmt(rw.value)+' Opfer / 30 Tage',time:'LIVE'});
            if(grp[0]&&grp[1])items.push({tag:'darkweb',tagLabel:'RANSOMWARE',
                text:'Top: '+grp[0][0]+' ('+fmt(grp[0][1])+'), '+grp[1][0]+' ('+fmt(grp[1][1])+')',time:'LIVE'});
        }
        var cve=m.nvd_cves_today||m.cve_critical_today;
        if(cve&&cve.status==='ok'&&cve.value!==null)
            items.push({tag:'cve',tagLabel:'CVE-RADAR',text:fmt(cve.value)+' kritische CVEs heute (CVSS ≥9.0)',time:'LIVE'});
        var fe=m.feodo_active_botnets;
        if(fe&&fe.status==='ok'&&fe.value!==null)
            items.push({tag:'block',tagLabel:'C2-AKTIV',text:fmt(fe.value)+' aktive C2-Server — Feodo Tracker',time:'LIVE'});

        if(items.length<3)return;

        inner.innerHTML='';
        function addSet(){
            items.forEach(function(ev){
                var item=document.createElement('span');item.className='ticker-item';
                var tag=document.createElement('span');tag.className='ti-tag '+ev.tag;tag.textContent=ev.tagLabel;
                var arrow=document.createElement('span');arrow.className='ti-arrow';arrow.textContent='◄';
                var txt=document.createElement('span');txt.textContent=ev.text;
                var time=document.createElement('span');time.className='ti-time';time.textContent=ev.time;
                item.appendChild(tag);item.appendChild(arrow);item.appendChild(txt);item.appendChild(time);
                inner.appendChild(item);
            });
        }
        addSet();addSet();
    }

    function doFetch(){
        fetch(STATS)
            .then(function(r){if(!r.ok)throw 0;return r.json();})
            .then(applyMetrics)
            .catch(function(){});
    }

    if(typeof EventSource==='undefined'){setInterval(doFetch,60000);doFetch();return;}
    var es=new EventSource(STREAM);
    es.addEventListener('stats',function(e){try{applyMetrics(JSON.parse(e.data));}catch(ex){}});
    es.onerror=function(){es.close();setTimeout(initLiveStats,15000);};
    doFetch();
}
