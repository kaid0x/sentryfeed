/* Format inspection only: no password hashing, guessing, verification or network requests. */
'use strict';
(function(root) {
  const MAX_ROWS=10000, MAX_CHARS=5000000, MAX_CELL=4096;
  const levels={floor:'Cost floor observed',review:'Review needed',legacy:'Legacy format',unknown:'Not identified',invalid:'Malformed record',empty:'Empty or disabled'};
  function fail(message){throw new Error(message);}
  function integer(s){return /^\d{1,10}$/.test(s)&&Number.isSafeInteger(Number(s))?Number(s):null;}
  function base64(s){
    if(!/^[A-Za-z0-9+/]+={0,2}$/.test(s)||s.replace(/=+$/,'').length%4===1)return null;
    try{const unpadded=s.replace(/=+$/,'');const decoded=atob(unpadded+'='.repeat((4-unpadded.length%4)%4));return btoa(decoded).replace(/=+$/,'')===unpadded?decoded:null;}catch{return null;}
  }
  function result(format,level,note,params='',salt=null){return {format,level,note,params,salt};}
  function inspect(value){
    if(value===null||value===undefined||value==='')return result('Empty', 'empty','Check whether this account should have password authentication.');
    if(typeof value!=='string'||value.length>MAX_CELL)return result('Unusable value','invalid','Expected a stored string of at most 4,096 characters.');
    if(/^!/.test(value)||value==='*')return result('Disabled marker','empty','May indicate a disabled password; verify framework behaviour.');
    if(value!==value.trim())return result('Unrecognised value','unknown','Leading or trailing whitespace prevents reliable format recognition.');
    let v=value,wrapped='';
    if(v.startsWith('argon2$')){wrapped='Django ';v=v.slice(6);}
    if(/^\$argon2(?:id|i|d)\$/.test(v)){
      const m=v.match(/^\$(argon2id|argon2i|argon2d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/);
      if(!m)return result('Argon2','invalid','The version, parameters, salt or digest is malformed.');
      const [version,memory,time,parallel]=m.slice(2,6).map(integer),salt=base64(m[6]),digest=base64(m[7]);
      if([version,memory,time,parallel].includes(null)||!time||!parallel||parallel>16777215||memory<8*parallel||!salt||salt.length<8||!digest||digest.length<4)return result('Argon2','invalid','Invalid parameters or encoded salt/digest length.');
      const params=`v=${version}, m=${memory} KiB, t=${time}, p=${parallel}`;
      const floor=[[47104,1],[19456,2],[12288,3],[9216,4],[7168,5]].some(([m,t])=>memory>=m&&time>=t);
      const level=m[1]!=='argon2id'?'review':version===19&&floor&&parallel===1&&salt.length>=16&&digest.length>=16?'floor':'review';
      return result(wrapped+m[1],level,level==='floor'?'Listed cost floor observed; this is not a security certification.':'Review variant, version, lengths and cost settings against the linked guidance. Other parameter combinations need manual assessment.',params,'argon2:'+btoa(salt));
    }
    if(wrapped)return result('Django Argon2','invalid','Unrecognised Argon2 record.');
    if(v.startsWith('bcrypt_sha256$')){wrapped='Django bcrypt-SHA256 ';v=v.slice(14);}
    else if(v.startsWith('bcrypt$')){wrapped='Django ';v=v.slice(7);}
    if(/^\$2[abxy]\$/.test(v)){
      const m=v.match(/^\$2([abxy])\$(\d{2})\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$/),cost=m?integer(m[2]):null;
      if(!m||cost<4||cost>31)return result('bcrypt','invalid','Malformed bcrypt length or cost.');
      const level=m[1]==='x'?'review':'legacy';
      return result(wrapped+'bcrypt',level,cost<10?'Cost is below the referenced bcrypt floor.':'Legacy-use cost floor observed. Prefer Argon2id for new systems; verify input-length handling.',`cost=${cost}`,'bcrypt:'+m[3]);
    }
    if(wrapped)return result('Django bcrypt','invalid','Unrecognised bcrypt record.');
    let m=v.match(/^(pbkdf2_sha256|pbkdf2_sha1)\$(\d+)\$([^$]+)\$([^$]+)$/);
    if(m){
      const digest=base64(m[4]),count=integer(m[2]),sha=m[1]==='pbkdf2_sha256'?'sha256':'sha1';
      if(!count||!digest||digest.length!==(sha==='sha256'?32:20))return result('Django PBKDF2','invalid','Invalid iteration count or digest length.');
      return pbkdf('Django PBKDF2',sha,count,m[3]);
    }
    m=v.match(/^pbkdf2:(sha256|sha512|sha1):(\d+)\$([^$]+)\$([a-fA-F0-9]+)$/);
    if(m){const count=integer(m[2]),length={sha256:64,sha512:128,sha1:40}[m[1]];
      if(!count||m[4].length!==length)return result('Werkzeug PBKDF2','invalid','Invalid iteration count or digest length.');
      return pbkdf('Werkzeug PBKDF2',m[1],count,m[3]);}
    m=v.match(/^scrypt\$(\d+)\$([^$]+)\$(\d+)\$(\d+)\$([^$]+)$/);
    if(m){const digest=base64(m[5]);if(!digest||digest.length!==64)return result('Django scrypt','invalid','Invalid encoded digest.');return scrypt('Django scrypt',m[1],m[3],m[4],m[2]);}
    m=v.match(/^scrypt:(\d+):(\d+):(\d+)\$([^$]+)\$([a-fA-F0-9]{128})$/);
    if(m)return scrypt('Werkzeug scrypt',m[1],m[2],m[3],m[4]);
    if(/^(?:pbkdf2|scrypt|\$argon2|\$2[abxy])/.test(v))return result('Unsupported or malformed record','invalid','A familiar prefix is present, but this supported layout could not be validated.');
    if(/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(v))return result('Unlabelled hexadecimal','unknown','Length alone does not identify a hash algorithm, salt use or encryption. Inspect the application code.');
    return result('Unrecognised value','unknown','Could be another format, encrypted data or plaintext. Check the application; this tool cannot determine which.');
  }
  function pbkdf(format,sha,count,salt){
    const floor={sha256:600000,sha512:220000,sha1:1400000}[sha];
    const level=sha==='sha1'?'legacy':count>=floor&&new TextEncoder().encode(salt).length>=8?'floor':'review';
    return result(`${format} ${sha}`,level,count<floor?'Iteration count is below the referenced floor.':new TextEncoder().encode(salt).length<8?'Salt field is short; review its generation and length.':sha==='sha1'?'Legacy PRF; review migration options.':'Listed iteration floor observed. Verify salt generation and implementation.',`iterations=${count}`,'pbkdf2:'+salt);
  }
  function scrypt(format,N,r,p,salt){
    [N,r,p]=[N,r,p].map(integer);
    if(!N||!r||!p||N<2||!Number.isInteger(Math.log2(N))||r*p>=1073741824)return result(format,'invalid','Invalid scrypt parameter values.');
    const floor=r===8&&[[131072,1],[65536,2],[32768,3],[16384,5],[8192,10]].some(([n,parallel])=>N>=n&&p>=parallel);
    return result(format,floor&&new TextEncoder().encode(salt).length>=8?'floor':'review',new TextEncoder().encode(salt).length<8?'Salt field is short; review its generation and length.':floor?'Listed cost floor observed. Verify salt generation and implementation.':'Settings need manual comparison with the linked scrypt profiles.',`N=${N}, r=${r}, p=${p}`,'scrypt:'+salt);
  }
  function csv(text){
    const rows=[];let row=[],cell='',quoted=false,closed=false;
    function field(){row.push(cell);cell='';closed=false;if(row.length>100)fail('CSV has more than 100 columns.');}
    function record(){const present=cell!==''||row.length>0||closed;field();if(present)rows.push(row);row=[];if(rows.length>MAX_ROWS+1)fail('Use at most 10,000 data rows.');}
    for(let i=0;i<text.length;i++){
      const c=text[i];
      if(quoted){if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;}
      else if(c==='"'){if(cell||closed)fail('Malformed CSV quoting.');quoted=true;}
      else if(c===',')field();else if(c==='\n'||c==='\r'){if(c==='\r'&&text[i+1]==='\n')i++;record();}
      else {if(closed)fail('Unexpected text after a quoted CSV field.');cell+=c;}
      if(cell.length>MAX_CELL)fail('A field exceeds 4,096 characters. Export only the needed columns.');
    }
    if(quoted)fail('CSV has an unclosed quote.');if(cell||row.length||closed)record();
    if(rows.length<2)fail('CSV needs a header and at least one data row.');
    const headers=rows.shift();if(headers.some(h=>!h.trim())||new Set(headers).size!==headers.length)fail('Use unique, non-empty column headers.');
    if(rows.some(r=>r.length!==headers.length))fail('CSV rows have inconsistent column counts.');
    return {headers,rows};
  }
  function parse(text){
    if(typeof text!=='string'||text.length>MAX_CHARS)fail('Use a UTF-8 export under 5 MB.');text=text.replace(/^\uFEFF/,'');
    if(!text.trim())fail('Choose a non-empty CSV or JSON export.');
    if(text.trimStart()[0]!=='[')return csv(text);
    let values;try{values=JSON.parse(text);}catch{fail('Invalid JSON. Use an array of row objects.');}
    if(!Array.isArray(values)||!values.length||values.length>MAX_ROWS)fail('JSON needs 1–10,000 row objects.');
    const headers=[];for(const row of values){if(!row||typeof row!=='object'||Array.isArray(row))fail('JSON must contain row objects.');for(const k of Object.keys(row)){if(!k.trim()||k.length>MAX_CELL)fail('Invalid JSON column name.');if(!headers.includes(k))headers.push(k);if(headers.length>100)fail('Use at most 100 columns.');}}
    if(!headers.length)fail('JSON rows have no columns.');
    return {headers,rows:values.map(r=>headers.map(k=>{const v=Object.hasOwn(r,k)?r[k]:null;if(v!==null&&typeof v!=='string')fail('Export column values as strings or null.');if(v&&v.length>MAX_CELL)fail('A field exceeds 4,096 characters.');return v;}))};
  }
  function audit(data,column,saltColumn=-1){
    if(!Number.isInteger(column)||column<0||column>=data.headers.length||!Number.isInteger(saltColumn)||saltColumn< -1||saltColumn>=data.headers.length||saltColumn===column)fail('Choose different stored-password and optional salt columns.');
    const groups=new Map(),salts=new Map(),counts=Object.fromEntries(Object.keys(levels).map(k=>[k,0]));let embedded=0,separate=0,unobserved=0;
    for(const row of data.rows){
      const r=inspect(row[column]);counts[r.level]++;
      const key=JSON.stringify([r.format,r.level,r.params,r.note]);groups.set(key,(groups.get(key)||0)+1);
      if(r.salt){embedded++;salts.set(r.salt,(salts.get(r.salt)||0)+1);}
      else if(saltColumn>=0&&typeof row[saltColumn]==='string'&&row[saltColumn].length){separate++;const key='separate:'+row[saltColumn];salts.set(key,(salts.get(key)||0)+1);}
      else unobserved++;
    }
    return {schema:1,guidanceReviewed:'2026-10-20',rows:data.rows.length,counts,groups:Array.from(groups,([key,count])=>{const [format,level,params,note]=JSON.parse(key);return {format,level,params,note,count};}),salt:{embedded,separate,unobserved,repeatedGroups:[...salts.values()].filter(n=>n>1).length,rowsInRepeatedGroups:[...salts.values()].filter(n=>n>1).reduce((a,b)=>a+b,0)},limits:'Format-only inspection. No passwords tested; no proof of salt randomness, pepper use, compliance or resistance to guessing.'};
  }
  const api={parse,inspect,audit,levels};if(typeof module!=='undefined'&&module.exports)module.exports=api;
  if(typeof document==='undefined')return;
  const $=id=>document.getElementById(id);let loaded=null,report=null,generation=0;
  function status(text){$('storage-status').textContent=text;}
  function node(tag,text,parent){const e=document.createElement(tag);e.textContent=text;parent.append(e);return e;}
  function clearResults(){report=null;$('storage-results').hidden=true;$('storage-download').disabled=true;$('storage-groups').replaceChildren();}
  function use(data){loaded=data;clearResults();for(const id of ['hash-column','salt-column'])$(id).replaceChildren();node('option','Choose a column',$('hash-column')).value='';node('option','No separate salt column',$('salt-column')).value='-1';data.headers.forEach((h,i)=>{node('option',h,$('hash-column')).value=String(i);node('option',h,$('salt-column')).value=String(i);});$('storage-columns').hidden=false;status(`${data.rows.length} rows loaded locally. Choose the stored-password column; no row contents are displayed.`);}
  function render(r){
    report=r;$('storage-results').hidden=false;$('storage-download').disabled=false;$('storage-summary').textContent=`${r.rows} rows inspected. Cost floors observed in ${r.counts.floor} rows; ${r.rows-r.counts.floor} need review or interpretation.`;
    $('storage-groups').replaceChildren();for(const g of r.groups.slice(0,100)){const item=document.createElement('article');item.className='storage-group';$('storage-groups').append(item);node('h3',`${g.count} ${g.count===1?'row':'rows'} · ${g.format}`,item);node('p',`${levels[g.level]}${g.params?' · '+g.params:''}`,item);node('p',g.note,item);}
    if(r.groups.length>100)node('p','Showing the first 100 format/setting groups. The aggregate download includes all groups.',$('storage-groups'));
    $('storage-salts').textContent=`Embedded salt observed: ${r.salt.embedded} rows. Separate salt value present: ${r.salt.separate} rows. Salt not observable: ${r.salt.unobserved} rows. Repeated observed salts: ${r.salt.repeatedGroups} groups across ${r.salt.rowsInRepeatedGroups} rows. Duplicated export rows may explain repeats; presence and uniqueness do not prove randomness or correct use.`;
    status('Inspection complete. The results describe stored-record formats, not password strength.');
  }
  $('storage-file').addEventListener('change',async event=>{const token=++generation,file=event.target.files[0];event.target.value='';loaded=null;$('storage-columns').hidden=true;clearResults();if(!file)return;if(file.size>MAX_CHARS){status('Use a UTF-8 export under 5 MB.');return;}try{const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());if(token!==generation)return;use(parse(text));}catch(e){if(token===generation)status(e instanceof TypeError?'Could not read UTF-8 text. Export CSV or JSON as UTF-8.':e.message);}});
  for(const id of ['hash-column','salt-column','storage-owned'])$(id).addEventListener('change',()=>{clearResults();status('Selection changed. Run the inspection again.');});
  $('storage-run').addEventListener('click',()=>{clearResults();if(!$('storage-owned').checked){status('Confirm that this is your own export or an authorised audit.');return;}if(!loaded){status('Choose an export or the fictional sample first.');return;}try{if($('hash-column').value==='')fail('Choose the stored-password column.');render(audit(loaded,Number($('hash-column').value),Number($('salt-column').value)));}catch(e){status(e.message);}});
  $('storage-sample').addEventListener('click',()=>{generation++;use(parse(JSON.stringify([
    {record:'fictional-1',stored:'$argon2id$v=19$m=19456,t=2,p=1$'+btoa('fictional-salt-01').replace(/=/g,'')+'$'+btoa('fictional-digest-0000000000000001').replace(/=/g,'')},
    {record:'fictional-2',stored:'pbkdf2_sha256$100000$fictional-shared-salt$'+btoa('fictional-digest-'.padEnd(31,'0')+'2')},
    {record:'fictional-3',stored:'pbkdf2_sha256$600000$fictional-shared-salt$'+btoa('fictional-digest-'.padEnd(31,'0')+'3')},
    {record:'fictional-4',stored:'0'.repeat(32)},{record:'fictional-5',stored:null},{record:'fictional-6',stored:'$2b$09$'+'A'.repeat(53)}
  ])));$('hash-column').value='1';$('storage-owned').checked=true;status('Fictional format examples loaded. Digests are placeholders, not real account records. Choose Inspect storage.');});
  $('storage-clear').addEventListener('click',()=>{generation++;loaded=null;clearResults();$('storage-columns').hidden=true;$('storage-owned').checked=false;$('storage-file').value='';status('Export and results cleared from this tab. Downloaded summaries are unaffected.');});
  $('storage-download').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='password-storage-summary.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
})(typeof globalThis!=='undefined'?globalThis:this);
