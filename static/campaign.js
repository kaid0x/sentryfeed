/* Evidence stays in memory. No report requests, analytics, or automatic persistence. */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const limits = {report: 200000, mappings: 300, evidence: 10000, title: 200, source: 2000, rationale: 4000};
  let catalogue, byId, mappings = [], captured = null, dirty = false;
  function status(message) { $('status').textContent = message; }
  function node(tag, text, parent) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (parent) parent.append(el); return el; }
  function button(text, parent, action) { const el = node('button', text, parent); el.type = 'button'; el.addEventListener('click', action); return el; }
  function safeURL(value) {
    if (!value) return '';
    try { const u = new URL(value); return ['https:', 'http:'].includes(u.protocol) && !u.username && !u.password ? u.href : null; } catch { return null; }
  }
  function project() { return {format:'sentryfeed-campaign', schema:1, attackVersion:catalogue.version, attackCommit:catalogue.commit, title:$('project-title').value, source:$('source').value, report:$('report').value, mappings:mappings.map(m => ({...m}))}; }
  function download(data, name) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'}));
    const a = node('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function validSpan(m, report) { return Number.isInteger(m.start) && Number.isInteger(m.end) && m.start >= 0 && m.end > m.start && m.end <= report.length && report.slice(m.start,m.end) === m.evidence; }
  function validateProject(p) {
    if (!p || p.format !== 'sentryfeed-campaign' || p.schema !== 1 || p.attackVersion !== catalogue.version || p.attackCommit !== catalogue.commit) throw Error('This file uses a different project format or ATT&CK snapshot. Your current work was kept.');
    for (const key of ['title','source','report']) if (typeof p[key] !== 'string' || p[key].length > limits[key]) throw Error('Invalid or oversized project field.');
    if (safeURL(p.source) === null || !Array.isArray(p.mappings) || p.mappings.length > limits.mappings) throw Error('Invalid source or mapping list.');
    const clean = p.mappings.map(m => {
      if (!m || !byId.has(m.technique) || !byId.get(m.technique).tactics.includes(m.tactic) || !['draft','reviewed'].includes(m.state) || typeof m.rationale !== 'string' || m.rationale.length > limits.rationale || typeof m.evidence !== 'string' || m.evidence.length > limits.evidence || !validSpan(m,p.report) || typeof m.source !== 'string' || m.source.length > limits.source || safeURL(m.source) === null || (m.state === 'reviewed' && !m.rationale.trim())) throw Error('A mapping is invalid, unsupported or missing its evidence. Your current work was kept.');
      return {technique:m.technique, tactic:m.tactic, start:m.start, end:m.end, evidence:m.evidence, source:m.source, rationale:m.rationale, state:m.state};
    });
    return {...p, mappings:clean};
  }
  function add(id, span = captured, silent = false) {
    if (!span || !validSpan(span,$('report').value)) { status('Select a passage in the report and use it as evidence first.'); return; }
    if (mappings.length >= limits.mappings) { status('This project supports up to 300 mappings.'); return; }
    const source = safeURL($('source').value.trim());
    if (source === null) { status('Use an HTTP or HTTPS source URL, or leave it empty.'); return; }
    if (mappings.some(m => m.technique === id && m.start === span.start && m.end === span.end)) { status('That technique is already mapped to this passage.'); return; }
    mappings.push({technique:id, tactic:catalogue.tactics.find(t=>byId.get(id).tactics.includes(t.id)).id, ...span, source, rationale:'', state:'draft'}); dirty = true; if (!silent) { renderMappings(); status('Draft added. Explain the mapping, then mark it reviewed.'); }
  }
  function renderResults() {
    const q = $('search').value.trim().toLowerCase(), tactic = $('tactic-filter').value;
    const terms = q.split(/\s+/).filter(Boolean);
    const matches = catalogue.techniques.filter(t => (!tactic || t.tactics.includes(tactic)) && terms.every(term => `${t.id} ${t.name} ${t.description}`.toLowerCase().includes(term)));
    $('results').replaceChildren(); $('result-count').textContent = `${matches.length} matches. Showing ${Math.min(matches.length,25)}. Narrow your search for more.`;
    for (const t of matches.slice(0,25)) {
      const row = node('article',undefined,$('results')); row.className = 'result'; node('h3',`${t.id} · ${t.name}`,row);
      node('p',t.description.slice(0,420) + (t.description.length > 420 ? '…' : ''),row);
      node('small',`${t.tactics.join(', ')} · ${t.platforms.join(', ')}`,row);
      const link = node('a','Read full technique',row); link.href = t.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
      button('Map to selected evidence',row,() => add(t.id));
    }
  }
  function renderMappings() {
    if (!catalogue) return;
    $('mappings').replaceChildren();
    const reviewed = mappings.filter(m => m.state === 'reviewed').length;
    $('summary').textContent = `${mappings.length} evidence mappings · ${reviewed} reviewed · ${mappings.length-reviewed} drafts. Displayed by tactic, not attack sequence.`;
    $('navigator').disabled = !reviewed;
    for (const tactic of catalogue.tactics) {
      const rows = mappings.map((m,i) => ({m,i})).filter(({m}) => m.tactic === tactic.id);
      if (!rows.length) continue;
      node('h3',tactic.name,$('mappings'));
      for (const {m,i} of rows) {
        const t = byId.get(m.technique), row = node('article',undefined,$('mappings')); row.className = 'mapping';
        const heading=node('h3',`${t.id} · ${t.name} · ${m.state}`,row); node('small','ATT&CK objectives: '+t.tactics.join(', '),row); const tacticLabel=node('label','Objective supported by this evidence',row), tacticSelect=node('select',undefined,row); tacticSelect.id='objective-'+i; tacticLabel.htmlFor=tacticSelect.id; for(const objective of catalogue.tactics.filter(x=>t.tactics.includes(x.id))){const option=node('option',objective.name,tacticSelect);option.value=objective.id;} tacticSelect.value=m.tactic; tacticSelect.addEventListener('change',()=>{m.tactic=tacticSelect.value;m.state='draft';dirty=true;renderMappings();}); node('blockquote',m.evidence,row);
        if (m.source) { const a = node('a','Report source',row); a.href = safeURL(m.source); a.target='_blank'; a.rel='noopener noreferrer'; }
        const label = node('label','Why does this evidence support the technique?',row), text = node('textarea',undefined,row);
        const printedReason=node('p',m.rationale,row);printedReason.className='print-only';
        text.spellcheck=false; text.autocomplete='off'; text.id=`rationale-${tactic.id}-${i}`; label.htmlFor=text.id; text.value=m.rationale; text.maxLength=limits.rationale; text.rows=3;
        text.addEventListener('input',() => { m.rationale=text.value; printedReason.textContent=m.rationale; m.state='draft'; dirty=true; heading.textContent=`${t.id} · ${t.name} · draft`; reviewButton.textContent='Mark reviewed'; const count=mappings.filter(x=>x.state==='reviewed').length; $('summary').textContent=`${mappings.length} evidence mappings · ${count} reviewed · ${mappings.length-count} drafts.`; $('navigator').disabled=!count; });
        const actions=node('div',undefined,row); actions.className='actions no-print';
        const reviewButton=button(m.state === 'reviewed' ? 'Return to draft' : 'Mark reviewed',actions,() => {
          if (!m.rationale.trim() || !validSpan(m,$('report').value)) {status('A reviewed mapping needs matching report evidence and an explanation.'); return;}
          m.state=m.state==='reviewed'?'draft':'reviewed';dirty=true;renderMappings();status(m.state==='reviewed'?'Mapping marked reviewed by you.':'Mapping returned to draft.');
        });
        button('Remove mapping',actions,() => {mappings.splice(i,1);dirty=true;renderMappings();});
      }
    }
  }
  function capture() {
    const report=$('report'), start=report.selectionStart, end=report.selectionEnd;
    if (end<=start || end-start>limits.evidence) { status('Select 1–10,000 characters in the report.'); return; }
    captured={start,end,evidence:report.value.slice(start,end)}; $('evidence').value=captured.evidence; status('Passage selected. Search for the behaviour it describes.');
  }
  $('capture').addEventListener('click',capture);
  $('report').addEventListener('input',() => {
    captured=null;$('evidence').value='';mappings=mappings.filter(m=>validSpan(m,$('report').value)).map(m=>({...m,state:'draft'}));dirty=true;renderMappings();status('Report changed. Mappings with changed evidence were removed; retained mappings need review.');
  });
  for (const id of ['project-title','source']) $(id).addEventListener('input',()=>{dirty=true;});
  $('search').addEventListener('input',()=>{if(catalogue) renderResults();});
  $('tactic-filter').addEventListener('change',()=>{if(catalogue) renderResults();});
  $('save').addEventListener('click',()=>{
    try { const p=validateProject(project());download(p,'sentryfeed-campaign.json');dirty=false;status('Project download requested. Keep this file to reopen your report and mappings.'); } catch(e){status(e.message);}
  });
  $('import').addEventListener('change',async event=>{
    const file=event.target.files[0];event.target.value='';if(!file)return;
    if(!catalogue){status('Wait for the catalogue before opening a project.');return;}
    if(file.size>25000000){status('Project files must be under 25 MB.');return;}
    try {
      const p=validateProject(JSON.parse(await file.text()));
      if(dirty&&!confirm('Replace unsaved work with this project?'))return;
      $('project-title').value=p.title;$('source').value=p.source;$('report').value=p.report;mappings=p.mappings;captured=null;$('evidence').value='';dirty=false;renderMappings();status('Project opened. Reviewed labels are the file author’s assessments.');
    } catch(e){status(e instanceof SyntaxError?'This file is not valid JSON. Your work was kept.':e.message);}
  });
  $('navigator').addEventListener('click',()=>{
    const reviewed=mappings.filter(m=>m.state==='reviewed'&&validSpan(m,$('report').value));
    if(!reviewed.length)return;
    const keys=[...new Set(reviewed.map(m=>m.technique+'|'+m.tactic))];
    const techniques=keys.map(key=>{const [id,tactic]=key.split('|');return {techniqueID:id,tactic,enabled:true,color:'#82b2f5',comment:reviewed.filter(m=>m.technique===id&&m.tactic===tactic).map(m=>`Evidence: ${m.evidence}\nReason: ${m.rationale}\nSource: ${m.source||'not provided'}`).join('\n\n')};});
    download({name:$('project-title').value||'Campaign analysis',versions:{attack:catalogue.version,navigator:'4.9.0',layer:'4.5'},domain:'enterprise-attack',description:'Analyst-reviewed evidence mappings from SentryFeed. Not attribution, attack order, or detection coverage.',techniques,metadata:[{name:'ATT&CK source commit',value:catalogue.commit}],selectTechniquesAcrossTactics:false},'sentryfeed-navigator.json');status('Navigator layer downloaded. Comments include your evidence and source URLs.');
  });
  $('find-ids').addEventListener('click',()=>{
    if(!catalogue){status('Wait for the catalogue to load.');return;}
    const report=$('report').value;const found=[...report.matchAll(/\bT\d{4}(?:\.\d{3})?\b/gi)];let count=0;const unknown=new Set();
    for(const match of found.slice(0,1000)){if(mappings.length>=limits.mappings)break;const id=match[0].toUpperCase();if(!byId.has(id)){unknown.add(id);continue;}
      const start=Math.max(0,report.lastIndexOf('\n',match.index)+1), next=report.indexOf('\n',match.index), end=Math.min(next<0?report.length:next,start+limits.evidence);
      if(match.index+match[0].length>end)continue;
      const before=mappings.length;add(id,{start,end,evidence:report.slice(start,end)},true);count+=mappings.length-before;
    }
    renderMappings();
    status(`${count} draft mappings added from explicit IDs. Review their context.${found.length>1000?' Only the first 1,000 ID occurrences were considered.':''}${unknown.size?' Unknown or inactive IDs skipped: '+[...unknown].slice(0,10).join(', '):''}`);
  });
  function replaceAllowed(){return !dirty||confirm('Discard unsaved work? Save a project first if you want to keep it.');}
  $('sample').addEventListener('click',()=>{
    if(!replaceAllowed())return;
    $('project-title').value='Fictional campaign exercise';$('source').value='';$('report').value='Fictional exercise, not a real campaign or attribution.\nAn attacker emailed a link to a counterfeit sign-in page to employees (T1566.002).\nAfter obtaining credentials, the attacker used a valid account to access the environment (T1078).\nThe attacker ran PowerShell commands to inspect the host (T1059.001).\nThe report does not establish persistence, exfiltration, or a named threat actor.';
    mappings=[];captured=null;$('evidence').value='';dirty=true;renderMappings();status('Fictional example loaded. Select evidence or find its explicit IDs.');
  });
  $('clear').addEventListener('click',()=>{if(!replaceAllowed())return;for(const id of ['project-title','source','report','evidence'])$(id).value='';mappings=[];captured=null;dirty=false;renderMappings();status('Work cleared from this tab. Downloaded files are unaffected.');});
  $('print').addEventListener('click',()=>{$('print-title').textContent=$('project-title').value||'Untitled campaign analysis';window.print();});
  window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
  fetch('/static/attack-catalogue.json').then(r=>{if(!r.ok)throw Error();return r.json();}).then(data=>{
    catalogue=data;byId=new Map(data.techniques.map(t=>[t.id,t]));
    for(const t of data.tactics){const option=node('option',t.name,$('tactic-filter'));option.value=t.id;}
    $('search').disabled=false;$('save').disabled=false;$('catalogue-meta').textContent=`Enterprise ATT&CK ${data.version} · ${data.techniques.length} active techniques and sub-techniques · source ${data.commit.slice(0,12)}. Inactive techniques are excluded.`;
    renderResults();status('Ready. Paste a report or try the fictional example.');
  }).catch(()=>status('The local ATT&CK catalogue could not load. Reload before mapping; your report has not been sent.'));
})();
