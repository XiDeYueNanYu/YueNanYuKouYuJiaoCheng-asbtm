/* BGObf — che giấu chuỗi nhạy cảm (token, mã datasheet) trong tệp xuất để KHÔNG đọc được bằng cách xem mã nguồn hay tìm chữ.
   LƯU Ý: đây là làm khó người tò mò, KHÔNG phải mã hóa an toàn — mã giải nằm trong chính trang, và token vẫn thấy được ở tab Network
   của trình duyệt khi gọi API. Cách bảo vệ thật là dùng token quyền hẹp (xem hướng dẫn "tài khoản thu bài").
   Định dạng: "x1.<muối>.<base64url>" — XOR từng byte UTF-8 với khóa (hằng số + muối ngẫu nhiên mỗi lần xuất) và một dãy phụ thuộc vị trí. */
(function(g){
  'use strict';
  var K='bg\u00b7x1\u00b7KS';
  function u8(s){return new TextEncoder().encode(s)}
  function b64(b){var s='';for(var i=0;i<b.length;i+=0x8000)s+=String.fromCharCode.apply(null,b.subarray(i,i+0x8000));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
  function unb64(t){t=String(t).replace(/-/g,'+').replace(/_/g,'/');while(t.length%4)t+='=';var s=atob(t),o=new Uint8Array(s.length);for(var i=0;i<s.length;i++)o[i]=s.charCodeAt(i);return o}
  function mask(b,salt){var k=u8(K+salt),o=new Uint8Array(b.length);for(var i=0;i<b.length;i++)o[i]=b[i]^k[i%k.length]^((i*131+7)&255);return o}
  function rnd(){var a=new Uint8Array(6);(g.crypto||g.msCrypto).getRandomValues(a);var s='';for(var i=0;i<a.length;i++)s+=(a[i]%36).toString(36);return s}
  var isEnc=function(s){return typeof s==='string'&&/^x1\.[a-z0-9]{6}\./.test(s)};
  function enc(str){var salt=rnd();return'x1.'+salt+'.'+b64(mask(u8(String(str)),salt))}
  function dec(s){if(!isEnc(s))return s;var p=s.split('.'),salt=p[1];return new TextDecoder().decode(mask(unb64(p.slice(2).join('.')),salt))}
  g.BGObf={enc:enc,dec:dec,isEnc:isEnc,
    encObj:function(o){return enc(JSON.stringify(o))},
    decObj:function(s){try{return JSON.parse(dec(s))}catch(e){return null}}};
})(typeof window!=='undefined'?window:this);

/* Đăng nhập "phòng quân tử" khi mở bài — dùng chung cho TRÌNH SOẠN (tạo tài khoản, thử đăng nhập) và BÀI ĐÃ XUẤT (màn hình đăng nhập).
   Tài khoản nằm ở một bảng Vika/APITable (hoặc tab TaiKhoan của Google Sheet qua Apps Script — backend 'sheet': máy chủ kiểm tra, trả về phiên có chữ ký) (cột: tên đăng nhập, muối, mã băm PBKDF2-SHA256 của mật khẩu, họ tên, mã lớp, trạng thái, hạn dùng).
   Trang gửi tên + mật khẩu tới API (đọc đúng một dòng bằng token QUYỀN HẸP của tài khoản thu bài), tự băm mật khẩu và so với mã băm trong bảng.
   Ghi nhớ đăng nhập trong trình duyệt; mỗi lần mở lại im lặng kiểm tra lại (khóa/hết hạn/đổi mật khẩu có hiệu lực ngay), cho dùng ngoại tuyến vài ngày.
   MÃ HÓA NỘI DUNG (v4.32, tùy chọn P.login.encrypt): PBKDF2 ra 512 bit — 256 bit đầu là mã băm xác minh (như cũ), 256 bit sau là khóa bọc (KEK) KHÔNG BAO GIỜ lưu.
   Khóa nội dung (CEK, ngẫu nhiên theo dự án) mã hóa toàn bộ nội dung bài bằng AES-GCM; mỗi học sinh có một bản CEK đã bọc bằng KEK của mình (cột KhoaBoc).
   Không có mật khẩu hợp lệ thì chỉ thấy khối dữ liệu đã mã hóa. GIỚI HẠN: ai đã có mật khẩu hợp lệ vẫn lấy được nội dung; không thu hồi riêng từng người. */
(function(){
  'use strict';
  var DEF_COLS={user:'TenDangNhap',salt:'Muoi',hash:'MaBam',name:'HoTen',class:'MaLopHoc',status:'TrangThai',expire:'HetHan',wrap:'KhoaBoc'};
  var ALPHA='abcdefghjkmnpqrstuvwxyz23456789';   // bỏ ký tự dễ nhầm (i l o 0 1)
  var LOCKED=['khoa','lock','locked','off','0','no','false','nghi','dung','disable','disabled','\u505c\u7528','\u9501\u5b9a'];

  function normUser(u){return String(u==null?'':u).normalize('NFKC').trim().toLowerCase()}
  function plain(s){return String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/\u0111/g,'d').replace(/\u0110/g,'D').trim().toLowerCase()}
  function hex(buf){var a=new Uint8Array(buf),s='';for(var i=0;i<a.length;i++)s+=('0'+a[i].toString(16)).slice(-2);return s}
  function unhex(h){var o=new Uint8Array(h.length/2);for(var i=0;i<o.length;i++)o[i]=parseInt(h.substr(i*2,2),16);return o}
  function newSalt(){var a=new Uint8Array(16);crypto.getRandomValues(a);return hex(a)}
  function genPassword(n){var a=new Uint32Array(n),s='';crypto.getRandomValues(a);for(var i=0;i<n;i++)s+=ALPHA.charAt(a[i]%ALPHA.length);return s}
  function ceq(a,b){a=String(a);b=String(b);if(a.length!==b.length)return false;var r=0;for(var i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0}
  async function hash(pass,saltHex,iter){
    if(!(window.crypto&&crypto.subtle))throw Object.assign(new Error('secure'),{code:'secure'});
    var key=await crypto.subtle.importKey('raw',new TextEncoder().encode(String(pass).normalize('NFKC')),'PBKDF2',false,['deriveBits']);
    var bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:unhex(saltHex),iterations:iter||100000,hash:'SHA-256'},key,256);
    return hex(bits);
  }
  /* 512 bit: h = 256 bit đầu (xác minh, giống hash() cũ), k = 256 bit sau (khóa bọc, không lưu ở đâu cả) */
  async function derive(pass,saltHex,iter){
    if(!(window.crypto&&crypto.subtle))throw Object.assign(new Error('secure'),{code:'secure'});
    var key=await crypto.subtle.importKey('raw',new TextEncoder().encode(String(pass).normalize('NFKC')),'PBKDF2',false,['deriveBits']);
    var u=new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:unhex(saltHex),iterations:iter||100000,hash:'SHA-256'},key,512));
    return{h:hex(u.subarray(0,32)),k:u.slice(32)};
  }
  function b64(u8){var s='',i=0,C=0x8000;for(;i<u8.length;i+=C)s+=String.fromCharCode.apply(null,u8.subarray(i,i+C));return btoa(s)}
  function unb64(s){var b=atob(s),o=new Uint8Array(b.length);for(var i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o}
  async function sealB(keyBytes,u8){
    var iv=crypto.getRandomValues(new Uint8Array(12)),k=await crypto.subtle.importKey('raw',keyBytes,'AES-GCM',false,['encrypt']);
    var ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},k,u8)),o=new Uint8Array(12+ct.length);o.set(iv);o.set(ct,12);return o;
  }
  async function openB(keyBytes,u8){
    var k=await crypto.subtle.importKey('raw',keyBytes,'AES-GCM',false,['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:u8.subarray(0,12)},k,u8.subarray(12)));
  }
  function newKey(){var a=new Uint8Array(32);crypto.getRandomValues(a);return hex(a)}                   // CEK (hex) của dự án
  async function wrapKey(kek,cekHex){return hex(await sealB(kek,unhex(cekHex)))}                         // → chuỗi hex để dán vào cột KhoaBoc
  async function unwrapKey(kek,wrapHex){
    wrapHex=String(wrapHex||'').trim().toLowerCase();if(!/^[0-9a-f]{120}$/.test(wrapHex))return null;
    try{return await openB(kek,unhex(wrapHex))}catch(e){return null}
  }
  function statusOf(v){return LOCKED.indexOf(plain(v))>=0?'locked':'ok'}
  function expOf(v){if(v==null||v==='')return 0;if(typeof v==='number')return v<1e11?v*1000:v;var d=Date.parse(v);return isNaN(d)?0:d}

  /* ----- cấu hình ----- */
  function empty(){return{enabled:false,backend:'vika',sheet:{url:'',key:''},title:'',note:'',remember:true,days:30,offlineDays:7,iter:100000,pwLen:10,classCode:'',encrypt:false,encAssets:true,cek:'',
    vika:{host:'https://api.vika.cn',datasheet:'',view:'',token:'',fieldKey:'name'},cols:Object.assign({},DEF_COLS),lock:{on:false,admin:'admin',col:'BaiKhoa',gear:false}}}
  function norm(l){
    var e=empty();l=l&&typeof l==='object'?l:{};
    var s=function(v,d,n){return String(v==null?d:v).slice(0,n||300)},num=function(v,d,a,b){v=parseInt(v,10);return isFinite(v)?Math.min(b,Math.max(a,v)):d};
    e.enabled=!!l.enabled;e.title=s(l.title,'',120);e.note=s(l.note,'',500);e.remember=l.remember!==false;
    e.days=num(l.days,30,1,365);e.offlineDays=num(l.offlineDays,7,0,90);e.iter=num(l.iter,100000,1000,1000000);e.pwLen=num(l.pwLen,10,6,16);e.encrypt=!!l.encrypt;e.encAssets=l.encAssets!==false;e.cek=/^[0-9a-f]{64}$/.test(String(l.cek||''))?String(l.cek):'';if(e.encrypt&&!e.cek)e.cek=newKey();e.classCode=s(l.classCode,'',100);
    e.backend=l.backend==='sheet'?'sheet':'vika';
    var g=l.sheet&&typeof l.sheet==='object'?l.sheet:{};e.sheet={url:s(g.url,'',400),key:s(g.key,'',200)};
    var v=l.vika&&typeof l.vika==='object'?l.vika:{};
    e.vika={host:s(v.host,'https://api.vika.cn',200),datasheet:s(v.datasheet,'',200),view:s(v.view,'',100),token:s(v.token,'',300),fieldKey:v.fieldKey==='id'?'id':'name'};
    var c=l.cols&&typeof l.cols==='object'?l.cols:{};
    Object.keys(DEF_COLS).forEach(function(k){e.cols[k]=s(c[k],DEF_COLS[k],100).trim()||DEF_COLS[k]});
    var lk=l.lock&&typeof l.lock==='object'?l.lock:{};e.lock={on:!!lk.on,admin:normUser(s(lk.admin,'admin',60))||'admin',col:s(lk.col,'BaiKhoa',100).trim()||'BaiKhoa',gear:lk.gear===undefined?true:!!lk.gear};   // gear: có xuất nút ⚙ hay không (bản cũ v4.42 luôn có)
    return e;
  }
  function splitDs(s){var p=String(s||'').trim().replace(/^\/+|\/+$/g,'').split('/');return{dst:p[0]||'',view:p[1]||''}}
  /* cấu hình (soạn: có vika{}; xuất: có sec) → thông số gọi API */
  function resolve(cfg){
    if(cfg.backend==='sheet'){
      var SS=cfg.sec&&window.BGObf?(BGObf.decObj(cfg.sec)||{}):null,sh=SS?{url:SS.su,key:SS.sk}:(cfg.sheet||{});
      return{sheet:true,enc:!!(cfg.enc||cfg.encrypt),url:String(sh.url||'').trim(),key:String(sh.key||'').trim(),cols:Object.assign({},DEF_COLS,cfg.cols||{}),iter:cfg.iter||100000};
    }
    var S=cfg.sec&&window.BGObf?(BGObf.decObj(cfg.sec)||{}):null,dsRaw,view,token,fk;
    if(S){dsRaw=S.d||'';view=S.v||'';token=S.t||'';fk=S.k}
    else{var v=cfg.vika||{};dsRaw=v.datasheet||'';view=v.view||'';token=v.token||'';fk=v.fieldKey}
    var sp=splitDs(dsRaw);
    return{host:String(cfg.host||(cfg.vika&&cfg.vika.host)||'https://api.vika.cn').replace(/\/+$/,''),dst:sp.dst,view:String(view||sp.view||'').trim(),token:String(token||'').trim(),fk:fk==='id'?'id':'name',
      cols:Object.assign({},DEF_COLS,cfg.cols||{}),iter:cfg.iter||100000,enc:!!(cfg.enc||cfg.encrypt)};
  }
  var qs=function(p){return p.map(function(e){return encodeURIComponent(e[0])+'='+encodeURIComponent(e[1])}).join('&')};
  async function getJSON(c,pairs,ms){
    var url=c.host+'/fusion/v1/datasheets/'+encodeURIComponent(c.dst)+'/records?'+qs(pairs.concat(c.view?[['viewId',c.view]]:[],[['fieldKey',c.fk]]));
    var ctl=typeof AbortController!=='undefined'?new AbortController():null,t=0,res;
    if(ctl)t=setTimeout(function(){ctl.abort()},ms||15000);
    try{res=await fetch(url,{headers:{Authorization:'Bearer '+c.token},signal:ctl?ctl.signal:undefined})}
    catch(e){clearTimeout(t);throw Object.assign(new Error('net'),{net:true})}
    clearTimeout(t);
    var tx=await res.text(),j=null;try{j=JSON.parse(tx)}catch(e){}
    if(!res.ok||!j||j.success===false)throw Object.assign(new Error((j&&j.message)||('HTTP '+res.status)),{status:res.status});
    return j;
  }
  /* ----- backend Google Sheet (Apps Script Web App) ----- */
  var GS_MAP={key:'token',busy:'api',big:'api',wait:'api'};
  async function gsCall(c,body,ms){
    var ctl=typeof AbortController!=='undefined'?new AbortController():null,t=0,res;
    if(ctl)t=setTimeout(function(){ctl.abort()},ms||20000);
    try{res=await fetch(c.url,{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:JSON.stringify(Object.assign({k:c.key},body)),signal:ctl?ctl.signal:undefined,redirect:'follow'})}
    catch(e){clearTimeout(t);throw Object.assign(new Error('net'),{net:true})}
    clearTimeout(t);
    var tx=await res.text(),j=null;try{j=JSON.parse(tx)}catch(e){}
    if(!j)throw Object.assign(new Error('Máy chủ không trả JSON'),{api:true});
    if(j.success===false)throw Object.assign(new Error(j.message||j.code),{gs:j.code||'api',waitFor:j.code==='wait'});
    return j.data||{};
  }
  var gsCode=function(e){return e.net?'net':(e.gs?(GS_MAP[e.gs]||e.gs):'api')};
  async function gsVerify(c,u,pass){
    try{
      var sd=await gsCall(c,{a:'salt',u:u}),dv=await derive(pass,String(sd.salt||''),+sd.iter||c.iter);
      var d=await gsCall(c,{a:'login',u:u,h:dv.h}),a=d.account||{},key=null;
      if(c.enc){key=await unwrapKey(dv.k,a.wrap);if(!key)return{ok:false,code:'nokey'}}
      return{ok:true,account:{user:normUser(a.user||u),name:String(a.name||u).trim(),class:String(a.class||'').trim(),h:String(d.token||''),key:key,lock:d.lock}};
    }catch(e){
      if(e.code==='secure')return{ok:false,code:'secure'};
      if(e.gs==='wait')return{ok:false,code:'waitsrv'};
      return{ok:false,code:gsCode(e),msg:e.message};
    }
  }
  async function gsRecheck(c,sess){
    try{var d=await gsCall(c,{a:'recheck',token:sess.h}),a=d.account||{};return{ok:true,account:{user:normUser(a.user||sess.u),name:String(a.name||sess.u).trim(),class:String(a.class||'').trim(),h:String(d.token||sess.h),lock:d.lock}}}
    catch(e){return{ok:false,code:gsCode(e)}}
  }
  /* tìm dòng tài khoản: thử lọc theo công thức; nếu không thấy thì quét (xử lý khác biệt hoa/thường, công thức bị từ chối) */
  async function findAccount(c,user,extra){
    var cols=c.cols,fields=[cols.user,cols.salt,cols.hash,cols.name,cols.class,cols.status,cols.expire].concat(c.enc?[cols.wrap]:[]).concat(extra||[]).map(function(f){return['fields',f]});
    var same=function(r){return normUser(r.fields&&r.fields[cols.user])===user};
    try{
      var j=await getJSON(c,[['pageSize',3],['filterByFormula','{'+cols.user+'}="'+user+'"']].concat(fields)),m=((j.data||{}).records||[]).filter(same);
      if(m.length)return m;
    }catch(e){if(e.net||e.status===401||e.status===404||e.status===429)throw e}
    var out=[];
    for(var pn=1;pn<=5;pn++){
      var jj=await getJSON(c,[['pageSize',1000],['pageNum',pn]].concat(fields)),d=jj.data||{},recs=d.records||[];
      out=out.concat(recs.filter(same));
      if(!recs.length||pn*1000>=(d.total||0))break;
    }
    return out;
  }
  function accOf(f,c,h){return{user:normUser(f[c.cols.user]),name:String(f[c.cols.name]||normUser(f[c.cols.user])).trim(),class:String(f[c.cols.class]||'').trim(),h:h}}
  /* kiểm tra tên + mật khẩu → {ok,account} hoặc {ok:false,code} (code: empty|bad|net|token|api|cfg|dup|locked|expired|secure) */
  async function verify(cfg,user,pass){
    var c=resolve(cfg),u=normUser(user);
    if(!u||!pass)return{ok:false,code:'empty'};
    if(c.sheet)return c.url&&c.key?gsVerify(c,u,pass):{ok:false,code:'cfg'};
    if(/["\\{}]/.test(u))return{ok:false,code:'bad'};
    var rows;
    try{rows=await findAccount(c,u)}catch(e){return{ok:false,code:e.net?'net':(e.status===401||e.status===403?'token':'api'),msg:e.message}}
    if(!rows.length)return{ok:false,code:'bad'};   // không nói rõ sai tên hay sai mật khẩu
    if(rows.length>1)return{ok:false,code:'dup'};
    var f=rows[0].fields,salt=String(f[c.cols.salt]||'').trim(),h=String(f[c.cols.hash]||'').trim().toLowerCase();
    if(!/^[0-9a-f]{32,}$/.test(salt)||!/^[0-9a-f]{64}$/.test(h))return{ok:false,code:'cfg'};
    var dv;try{dv=await derive(pass,salt,c.iter)}catch(e){return{ok:false,code:e.code==='secure'?'secure':'cfg'}}
    if(!ceq(dv.h,h))return{ok:false,code:'bad'};
    if(statusOf(f[c.cols.status])==='locked')return{ok:false,code:'locked'};
    var ex=expOf(f[c.cols.expire]);if(ex&&ex<Date.now())return{ok:false,code:'expired'};
    var acc=accOf(f,c,dv.h);
    if(c.enc){acc.key=await unwrapKey(dv.k,f[c.cols.wrap]);if(!acc.key)return{ok:false,code:'nokey'}}
    return{ok:true,account:acc};
  }
  /* kiểm tra lại phiên đã nhớ (không cần mật khẩu): so mã băm đã lưu với mã băm hiện tại trong bảng */
  async function recheck(cfg,sess){
    var c=resolve(cfg),rows;
    if(c.sheet)return gsRecheck(c,sess);
    try{rows=await findAccount(c,sess.u)}catch(e){return{ok:false,code:e.net?'net':(e.status===401||e.status===403?'token':'api')}}
    if(rows.length!==1)return{ok:false,code:'gone'};
    var f=rows[0].fields;
    if(!ceq(String(f[c.cols.hash]||'').trim().toLowerCase(),sess.h))return{ok:false,code:'changed'};
    if(statusOf(f[c.cols.status])==='locked')return{ok:false,code:'locked'};
    var ex=expOf(f[c.cols.expire]);if(ex&&ex<Date.now())return{ok:false,code:'expired'};
    return{ok:true,account:accOf(f,c,sess.h)};
  }
  /* kiểm tra cột/kết nối cho trình soạn */
  async function probe(cfg){
    var c=resolve(cfg);
    if(c.sheet){
      var pg=await gsCall(c,{a:'ping'}),pr=await gsCall(c,{a:'probe'}),keys=pr.accHead||[],lk=keys.map(function(x){return String(x).toLowerCase()});
      var miss=['user','salt','hash'].filter(function(k){return pr.accHead&&lk.indexOf(String(c.cols[k]).toLowerCase())<0}).map(function(k){return c.cols[k]});
      return{total:pr.accCount,keys:keys,missing:miss,empty:!pr.accCount,version:pg.version,iter:pr.iter};
    }
    var j=await getJSON(c,[['pageSize',1]]),d=j.data||{},first=(d.records||[])[0],keys=first?Object.keys(first.fields||{}):[];
    var miss=['user','salt','hash'].filter(function(k){return first&&keys.indexOf(c.cols[k])<0}).map(function(k){return c.cols[k]});
    return{total:d.total,keys:keys,missing:miss,empty:!first};
  }

  var BG=window.BGLogin={derive:derive,newKey:newKey,wrapKey:wrapKey,unwrapKey:unwrapKey,sealB:sealB,openB:openB,b64:b64,unb64:unb64,hex:hex,unhex:unhex,gsCall:gsCall,DEF_COLS:DEF_COLS,empty:empty,norm:norm,normUser:normUser,hash:hash,newSalt:newSalt,genPassword:genPassword,verify:verify,recheck:recheck,probe:probe,resolve:resolve,user:null,token:''};

  /* Giải mã nội dung bài (bản xuất có mã hóa): enc = {p: payload đã niêm phong b64, a: [[tệp,mime,b64 hoặc '']...]}.
     payload = {h: HTML phần thân, j: JS của người học}. Tệp media được giải mã thành Blob URL rồi thay vào đường dẫn assets/<tệp>. */
  async function reveal(cek,enc,onProg){
    var pay=JSON.parse(new TextDecoder().decode(await openB(cek,unb64(enc.p)))),files=enc.a||[],map={},i;
    for(i=0;i<files.length;i++){
      var f=files[i],bytes;
      if(f[2])bytes=unb64(f[2]);
      else{var r=await fetch('assets/'+f[0]+'.enc');if(!r.ok)throw new Error('asset '+f[0]);bytes=new Uint8Array(await r.arrayBuffer())}
      map[f[0]]=URL.createObjectURL(new Blob([await openB(cek,bytes)],{type:f[1]||'application/octet-stream'}));
      if(onProg)onProg(i+1,files.length);
    }
    var html=pay.h,js=pay.j;
    if(files.length){
      var re=new RegExp('assets/('+files.map(function(f){return f[0].replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}).sort(function(a,b){return b.length-a.length}).join('|')+')(?![\\w.-])','g'),sub=function(m,n){return map[n]||m};
      html=html.replace(re,sub);js=js.replace(re,sub);
    }
    document.body.insertAdjacentHTML('afterbegin',html);
    var sc=document.createElement('script');sc.textContent=js;document.body.appendChild(sc);
  }
  BG.reveal=reveal;


  /* ================= ĐÓNG / MỞ BÀI HỌC (v4.42, riêng từng tài khoản từ v4.43) =================
     Mỗi tài khoản có một ô (cột cfg.lock.col, mặc định BaiKhoa) ghi DANH SÁCH BÀI ĐƯỢC MỞ cho tài khoản đó (số thứ tự bài như học sinh thấy):
       "1-3,5" chỉ mở các bài này · "*" mở tất cả · "0" đóng tất cả · "-2,4" mở tất cả TRỪ các bài này · TRỐNG = theo mặc định của lớp.
     Mặc định của lớp = ô của DÒNG ADMIN (admin = tài khoản có tên cfg.lock.admin trong CÙNG bảng tài khoản). Cả hai trống = mở hết.
     Google Sheet: máy chủ đọc/ghi ô này (getlock/setlock/listlock; chỉ admin ghi). Vika (chỉ đọc): giáo viên sửa thẳng ô trên trang Vika;
     bảng cài đặt chỉ giúp tạo chuỗi để dán. Đây là che GIAO DIỆN (học sinh biết đang học tới bài nào), không phải khóa bảo mật nội dung. */
  function parseLocks(str){
    var set={};String(str==null?'':str).split(/[,;\s]+/).forEach(function(t){
      var m=/^(\d{1,3})(?:-(\d{1,3}))?$/.exec(t.trim());if(!m)return;
      var a=+m[1],b=m[2]?+m[2]:a;if(b<a){var x=a;a=b;b=x}
      for(var i=Math.max(1,a);i<=Math.min(500,b);i++)set[i]=1;
    });return set;
  }
  function fmtLocks(set){
    var arr=Object.keys(set).map(Number).sort(function(p,q){return p-q}),out=[],i=0;
    while(i<arr.length){var j=i;while(j+1<arr.length&&arr[j+1]===arr[j]+1)j++;out.push(j>i+1?arr[i]+'-'+arr[j]:(j===i+1?arr[i]+','+arr[j]:String(arr[i])));i=j+1}
    return out.join(',');
  }
  /* một ô → tập bài ĐÓNG (N = số bài); ô trống/sai cú pháp → null (= theo mặc định) */
  function closedOf(spec,N){
    var s0=String(spec==null?'':spec).trim(),set={},i;
    if(!s0)return null;
    if(/^(\*|all|tat ca|tất cả|het)$/i.test(s0))return set;
    if(/^(0|none|khong)$/i.test(s0)){for(i=1;i<=N;i++)set[i]=1;return set}
    if(/[^0-9,;\-\s]/.test(s0))return null;
    if(s0.charAt(0)==='-'){var neg=parseLocks(s0.slice(1));return Object.keys(neg).length?neg:set}
    var open=parseLocks(s0);if(!Object.keys(open).length)return null;
    for(i=1;i<=N;i++)if(!open[i])set[i]=1;
    return set;
  }
  function effClosed(st,N){return closedOf(st.own,N)||closedOf(st.def,N)||{}}
  /* tập bài đóng → ô (danh sách bài MỞ) */
  function specOf(work,N){
    var open={},n=0,i;for(i=1;i<=N;i++)if(!work[i]){open[i]=1;n++}
    return n===N?'*':(n===0?'0':fmtLocks(open));
  }
  function cellStr(v){if(Array.isArray(v))v=v.join(',');return v==null?'':String(v).trim()}
  /* đọc ô BaiKhoa của một tài khoản trên Vika → chuỗi (ném lỗi nếu không đọc được) */
  async function vikaCell(c,L,u){
    var col=L.col||'BaiKhoa',same=function(r){return normUser(r.fields&&r.fields[c.cols.user])===u},rows=[];
    try{rows=await findAccount(c,u,[col])}catch(e){
      if(e.net||e.status===401||e.status===404||e.status===429)throw e;
      var jj=await getJSON(c,[['pageSize',1000]]);rows=((jj.data||{}).records||[]).filter(same);   // cột chưa có / API không nhận danh sách cột → đọc cả dòng
    }
    return rows.length?cellStr(rows[0].fields&&rows[0].fields[col]):'';
  }
  /* toàn bộ tài khoản + ô BaiKhoa (cho bảng cài đặt của admin) → {users:[{user,name,lock}],def} */
  async function listLock(cfg,token){
    var c=resolve(cfg),L=cfg.lock||{},col=L.col||'BaiKhoa',adm=normUser(L.admin);
    if(c.sheet){var d=await gsCall(c,{a:'listlock',token:token});return{users:(d.users||[]).filter(function(x){return x.user!==adm}),def:String(d.def||'')}}
    var recs=[],base=[[ 'pageSize',1000]],fields=[c.cols.user,c.cols.name,col].map(function(f){return['fields',f]}),useF=true;
    for(var pn=1;pn<=5;pn++){
      var jj;
      try{jj=await getJSON(c,base.concat([['pageNum',pn]],useF?fields:[]))}catch(e){if(useF&&!e.net&&e.status!==401&&e.status!==429){useF=false;pn--;continue}throw e}
      var dd=jj.data||{},rs=dd.records||[];recs=recs.concat(rs);if(!rs.length||pn*1000>=(dd.total||0))break;
    }
    var users=[],def='';
    recs.forEach(function(r){var f=r.fields||{},u=normUser(f[c.cols.user]);if(!u)return;
      if(u===adm){def=cellStr(f[col]);return}
      users.push({user:u,name:String(f[c.cols.name]||u).trim(),lock:cellStr(f[col])})});
    return{users:users,def:def};
  }
  /* đọc ô của chính mình + mặc định của lớp → {own,def} (ném lỗi nếu không đọc được) */
  async function pullLock(cfg,token,user){
    var c=resolve(cfg),L=cfg.lock||{};
    if(c.sheet){var d=await gsCall(c,{a:'getlock',token:token});return{own:String(d.own||''),def:String(d.def||'')}}
    var adm=normUser(L.admin),u=normUser(user),def=await vikaCell(c,L,adm);
    return{own:u===adm?def:await vikaCell(c,L,u),def:def};
  }
  var TL={
    closed:'课程尚未开放 · Bài này chưa mở',justClosed:'老师刚刚关闭了这一课，已为你切换 · Giáo viên vừa đóng bài này, đã chuyển bạn sang bài khác',
    none:'暂无开放的课程，请稍候 · Chưa có bài nào được mở, hãy chờ giáo viên',
    set:'⚙',setTitle:'Cài đặt (đóng/mở bài học) · 设置'
  };
  function lockInit(cfg,acc){
    var L=cfg.lock;if(!L||!L.on)return;
    var links=[].slice.call(document.querySelectorAll('#nav .navlist a[href^="#"]'));if(!links.length)return;
    var ids=links.map(function(a){return a.hash.slice(1)}),titles=links.map(function(a){var s=a.querySelector('span');return s?s.textContent:a.textContent}),N=ids.length;
    var isAdmin=normUser(acc.user)===normUser(L.admin),locked={},state={own:'',def:''},ckey='bg-lock:'+location.pathname+':'+(cfg.id||'')+':'+normUser(acc.user),root=document.documentElement;
    var c=resolve(cfg),tokenNow=function(){return BG.token};
    try{var cached=localStorage.getItem(ckey);if(cached!=null){var cj=JSON.parse(cached);state={own:String(cj.own||''),def:String(cj.def||'')}}}catch(e){}
    if(acc.lock&&typeof acc.lock==='object')state={own:String(acc.lock.own||''),def:String(acc.lock.def||'')};
    locked=effClosed(state,N);
    var pn=[].slice.call(document.querySelectorAll('main .pn a[href^="#"]'));
    function idxOf(id){return ids.indexOf(id)}                      // 0-based; số bài = +1
    function isLk(i){return i>=0&&!!locked[i+1]&&!isAdmin}
    function toast(msg){
      var t=el('div','bg-lktoast',msg);t.setAttribute('role','status');document.body.appendChild(t);setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t)},3800);
    }
    function paint(){
      links.forEach(function(a,i){
        var lk=!!locked[i+1],n=a.querySelector('i');
        a.classList.toggle('bg-lk',lk);if(lk&&!isAdmin)a.setAttribute('aria-disabled','true');else a.removeAttribute('aria-disabled');
        if(n){if(!n.hasAttribute('data-n'))n.setAttribute('data-n',n.textContent);n.textContent=lk?'\u{1F512}':n.getAttribute('data-n')}
        a.title=lk?(isAdmin?'Đang đóng với học sinh (bạn là admin nên vẫn xem được)':TL.closed):'';
      });
      pn.forEach(function(a){var i=idxOf(a.hash.slice(1));a.classList.toggle('bg-lk',i>=0&&!!locked[i+1]);if(isLk(i))a.setAttribute('aria-disabled','true');else a.removeAttribute('aria-disabled')});
    }
    /* đang đứng ở bài bị đóng → chuyển sang bài mở gần nhất phía trước (hoặc bài mở đầu tiên) */
    function guard(why){
      var cur=idxOf((location.hash||'#'+ids[0]).slice(1));if(cur<0)cur=0;
      if(!isLk(cur)){root.classList.remove('bg-alllocked');return}
      var to=-1,k;for(k=cur-1;k>=0;k--)if(!isLk(k)){to=k;break}
      if(to<0)for(k=0;k<ids.length;k++)if(!isLk(k)){to=k;break}
      if(to<0){root.classList.add('bg-alllocked');toast(TL.none);return}
      root.classList.remove('bg-alllocked');
      location.hash='#'+ids[to];toast(why==='live'?TL.justClosed:TL.closed);
    }
    function setState(st,remember){
      var before=fmtLocks(locked);
      state={own:String(st.own||''),def:String(st.def||'')};locked=effClosed(state,N);
      if(remember!==false){try{localStorage.setItem(ckey,JSON.stringify(state))}catch(e){}}
      paint();guard(before!==fmtLocks(locked)?'live':'');
    }
    document.addEventListener('click',function(e){          // bấm vào bài đóng: chặn (admin vẫn vào được)
      var a=e.target.closest&&e.target.closest('a[href^="#"]');if(!a)return;
      var i=idxOf(a.hash.slice(1));if(isLk(i)){e.preventDefault();e.stopPropagation();toast(TL.closed)}
    },true);
    addEventListener('hashchange',function(){guard('')});
    paint();guard('');
    async function pull(){try{setState(await pullLock(cfg,tokenNow(),acc.user))}catch(e){}}
    pull();setInterval(pull,60000);
    document.addEventListener('visibilitychange',function(){if(!document.hidden)pull()});

    /* ----- nút ⚙ và bảng cài đặt (chỉ khi bài được xuất kèm nút ⚙: cfg.lock.gear) ----- */
    if(L.gear===false||L.gear===0)return;
    var who=document.querySelector('.bgl-who');
    var gear=el('button',null,TL.set);gear.type='button';gear.title=TL.setTitle;gear.setAttribute('aria-label','Cài đặt');
    if(who)who.insertBefore(gear,who.firstChild.nextSibling);
    function close(m){if(m&&m.parentNode)m.parentNode.removeChild(m)}
    function modal(title){
      var ov=el('div','bgs-ov'),box=el('div','bgs-box');box.setAttribute('role','dialog');box.setAttribute('aria-modal','true');
      var h=el('h3',null,title);box.appendChild(h);ov.appendChild(box);document.body.appendChild(ov);
      ov.addEventListener('keydown',function(e){if(e.key==='Escape')close(ov)});
      return{ov:ov,box:box};
    }
    var codeFails=0,codeUntil=0;
    gear.onclick=function(){
      if(isAdmin)return panel({token:tokenNow()});
      var m=modal('Nhập mã cài đặt'),box=m.box;
      var st=el('p','bgs-st'),inp=el('input');inp.type='password';inp.autocomplete='off';inp.setAttribute('aria-label','Mã cài đặt');
      var ok=el('button','bgs-p','Vào cài đặt'),no=el('button',null,'Hủy');ok.type=no.type='button';
      box.appendChild(el('p','bgs-note','Chỉ dành cho giáo viên (mật khẩu của tài khoản admin).'));box.appendChild(inp);
      var row=el('div','bgs-row');row.appendChild(ok);row.appendChild(no);box.appendChild(row);box.appendChild(st);
      no.onclick=function(){close(m.ov)};
      async function go(){
        var now=Date.now();if(now<codeUntil){st.textContent='Thử quá nhiều lần, hãy chờ '+Math.ceil((codeUntil-now)/1000)+' giây.';return}
        if(!inp.value){st.textContent='Hãy nhập mã cài đặt.';return}
        ok.disabled=true;st.textContent='Đang kiểm tra…';
        var r=await verify(Object.assign({},cfg,{enc:0,encrypt:false}),L.admin,inp.value);   // chỉ kiểm tra mật khẩu admin, không cần khóa mở nội dung
        ok.disabled=false;
        if(r.ok){codeFails=0;close(m.ov);panel({token:String(r.account.h||'')});return}
        if(r.code==='bad'||r.code==='empty'){codeFails++;if(codeFails>=5){codeUntil=Date.now()+30000;codeFails=0}st.textContent='Mã cài đặt không đúng.'}
        else st.textContent=(T[r.code]||T.api).split(' · ').pop();
        inp.select();
      }
      ok.onclick=go;inp.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();go()}});
      setTimeout(function(){inp.focus()},30);
    };
    function panel(ctx){
      var m=modal('⚙ Cài đặt: đóng/mở bài học'),box=m.box,sheet=c.sheet,work={},target='',useDef=false,data={users:[],def:state.def,map:{}},col=L.col||'BaiKhoa';
      box.appendChild(el('p','bgs-note','Tick = bài được MỞ. Chọn "Mặc định cả lớp" hoặc một tài khoản học sinh (tài khoản chưa đặt riêng sẽ theo mặc định của lớp). Bạn (admin) luôn xem được mọi bài.'+
        (sheet?' Bấm "Lưu" để ghi vào ô "'+col+'" trong Google Sheet; học sinh thấy trong khoảng 1 phút.':
        ' Bảng Vika chỉ cho đọc nên hãy dán chuỗi bên dưới vào ô "'+col+'" của đúng dòng (mặc định cả lớp = dòng "'+L.admin+'") ngay trên trang Vika.')));
      var pick=el('div','bgs-row'),flt=el('input'),sel=el('select');flt.type='search';flt.placeholder='Lọc tên…';flt.setAttribute('aria-label','Lọc tài khoản');sel.setAttribute('aria-label','Áp dụng cho');
      pick.appendChild(document.createTextNode('Áp dụng cho: '));pick.appendChild(sel);pick.appendChild(flt);box.appendChild(pick);
      var defRow=el('label','bgs-it'),defCb=el('input');defCb.type='checkbox';defRow.appendChild(defCb);defRow.appendChild(document.createTextNode(' Theo mặc định của lớp (không đặt riêng)'));box.appendChild(defRow);
      var list=el('div','bgs-list'),boxes=[];
      titles.forEach(function(t,i){
        var lab=el('label','bgs-it'),cb=el('input');cb.type='checkbox';boxes.push(cb);
        cb.onchange=function(){useDef=false;if(cb.checked)delete work[i+1];else work[i+1]=1;sync()};   // sửa một bài = bắt đầu đặt riêng (từ mặc định hiện tại)
        lab.appendChild(cb);lab.appendChild(document.createTextNode(' Bài '+(i+1)+' — '+t));list.appendChild(lab);
      });
      box.appendChild(list);
      var tools=el('div','bgs-row'),bAll=el('button',null,'Mở tất cả'),bNone=el('button',null,'Đóng tất cả'),sel2=el('select'),bTo=el('button',null,'Áp dụng');
      bAll.type=bNone.type=bTo.type='button';sel2.setAttribute('aria-label','Chỉ mở đến bài');
      titles.forEach(function(t,i){var o=el('option',null,'Bài '+(i+1));o.value=i+1;sel2.appendChild(o)});
      function setAll(fn){useDef=false;boxes.forEach(function(cb,i){cb.checked=fn(i+1);if(cb.checked)delete work[i+1];else work[i+1]=1});sync()}
      bAll.onclick=function(){setAll(function(){return true})};bNone.onclick=function(){setAll(function(){return false})};
      bTo.onclick=function(){var n=+sel2.value;setAll(function(k){return k<=n})};
      tools.appendChild(bAll);tools.appendChild(bNone);tools.appendChild(document.createTextNode(' Chỉ mở đến: '));tools.appendChild(sel2);tools.appendChild(bTo);box.appendChild(tools);
      var out=el('textarea','bgs-out');out.readOnly=true;out.rows=2;out.setAttribute('aria-label','Chuỗi bài mở');
      var st=el('p','bgs-st'),row=el('div','bgs-row'),save=el('button','bgs-p',sheet?'Lưu vào Google Sheet':'Sao chép chuỗi'),cl=el('button',null,'Đóng');save.type=cl.type='button';
      box.appendChild(out);row.appendChild(save);row.appendChild(cl);box.appendChild(row);box.appendChild(st);
      function cur(){return target&&useDef?'':specOf(work,N)}
      function sync(){
        defRow.style.display=target?'':'none';defCb.checked=useDef;
        out.value=cur();
        st.textContent=target&&useDef?'Để trống ô: tài khoản này theo mặc định của lớp'+(data.def?' ("'+data.def+'")':' (mở tất cả)')+'.':'Ô '+col+(target?' của "'+target+'"':' của dòng "'+L.admin+'" (mặc định cả lớp)')+': '+out.value;
      }
      function load(){            // nạp trạng thái của mục đang chọn vào các ô tick
        var spec=target?(data.map[target]||''):data.def;
        useDef=!!target&&!spec;
        var cs=closedOf(spec,N)||closedOf(data.def,N)||{};work={};Object.keys(cs).forEach(function(k){work[k]=1});
        boxes.forEach(function(cb,i){cb.checked=!work[i+1]});sync();
      }
      function fillSel(){
        var q=flt.value.trim().toLowerCase(),keep=target;sel.innerHTML='';
        var o0=el('option',null,'Mặc định cả lớp');o0.value='';sel.appendChild(o0);
        data.users.forEach(function(u){var lb=u.user+(u.name&&u.name!==u.user?' — '+u.name:'')+(data.map[u.user]?'  ['+data.map[u.user]+']':'');
          if(q&&lb.toLowerCase().indexOf(q)<0&&u.user!==keep)return;var o=el('option',null,lb);o.value=u.user;sel.appendChild(o)});
        sel.value=keep;if(sel.value!==keep){sel.value='';}
      }
      sel.onchange=function(){target=sel.value;load()};flt.oninput=fillSel;
      defCb.onchange=function(){useDef=defCb.checked;if(useDef){var cs=closedOf(data.def,N)||{};work={};Object.keys(cs).forEach(function(k){work[k]=1});boxes.forEach(function(cb,i){cb.checked=!work[i+1]})}sync()};
      cl.onclick=function(){close(m.ov)};
      save.onclick=async function(){
        var v=cur(),who2=target||normUser(L.admin);
        if(!sheet){
          try{await navigator.clipboard.writeText(v);st.textContent='Đã sao chép "'+v+'". Dán vào ô "'+col+'" của dòng "'+who2+'" trên trang Vika'+(v?'':' (ô để trống)')+'.'}
          catch(e){out.select();st.textContent='Hãy bôi đen và sao chép chuỗi ở ô trên (rồi dán vào ô "'+col+'" của dòng "'+who2+'").'}
          if(target){if(v)data.map[target]=v;else delete data.map[target]}else{data.def=v;setState({own:state.own,def:v},false)}   // coi như đã dán: bảng và giao diện admin phản ánh ngay
          fillSel();return;
        }
        save.disabled=true;st.textContent='Đang lưu…';
        try{
          var d=await gsCall(c,{a:'setlock',token:ctx.token,u:target,value:v}),nv=String(d.value||'');
          if(target)data.map[target]=nv;else data.def=nv;
          try{setState(await pullLock(cfg,ctx.token,acc.user))}catch(e){}
          fillSel();sync();st.textContent='Đã lưu vào ô "'+col+'" của "'+who2+'": '+(nv||'(trống — theo mặc định của lớp)')+'.';
        }
        catch(e){st.textContent=e.gs==='perm'?'Tài khoản này không phải admin của máy chủ (kiểm tra thuộc tính ADMIN_USER).':(e.net?'Không kết nối được máy chủ.':(e.gs==='nouser'?'Chưa có tài khoản này trong tab TaiKhoan.':'Không lưu được: '+e.message))}
        save.disabled=false;
      };
      load();fillSel();
      st.textContent='Đang tải danh sách tài khoản…';
      listLock(cfg,ctx.token).then(function(d){
        data.users=d.users.sort(function(a,b){return a.user<b.user?-1:1});data.def=d.def;data.map={};d.users.forEach(function(u){if(u.lock)data.map[u.user]=u.lock});
        fillSel();load();
      },function(e){st.textContent=e.gs==='perm'?'Tài khoản này không phải admin của máy chủ.':'Không tải được danh sách tài khoản'+(e.net?' (mất kết nối)':'')+' — vẫn tạo được chuỗi cho "Mặc định cả lớp".'});
    }
  }

  /* ================= MÀN HÌNH ĐĂNG NHẬP (chỉ chạy trong bài đã xuất có cấu hình) ================= */
  var T={
    user:'账号 · Tên đăng nhập',pass:'密码 · Mật khẩu',go:'登录 · Đăng nhập',remember:'在此设备上记住我 · Ghi nhớ trên thiết bị này',show:'显示 · Hiện',hide:'隐藏 · Ẩn',out:'退出 · Đăng xuất',
    checking:'正在验证登录… · Đang kiểm tra đăng nhập…',
    bad:'账号或密码错误 · Sai tên đăng nhập hoặc mật khẩu',
    locked:'账号已被停用，请联系老师 · Tài khoản đã bị khóa, hãy liên hệ giáo viên',
    expired:'账号已过期，请联系老师 · Tài khoản đã hết hạn, hãy liên hệ giáo viên',
    net:'无法连接服务器，请检查网络后重试 · Không kết nối được máy chủ, hãy kiểm tra mạng rồi thử lại',
    token:'服务配置有误，请联系老师 · Cấu hình bị lỗi (token không hợp lệ), hãy báo giáo viên',
    api:'服务器返回错误，请稍后重试 · Máy chủ báo lỗi, hãy thử lại sau',
    cfg:'账号数据有误，请联系老师 · Dữ liệu tài khoản bị lỗi, hãy báo giáo viên',
    dup:'账号重复，请联系老师 · Tài khoản bị trùng, hãy báo giáo viên',
    empty:'请输入账号和密码 · Hãy nhập tên đăng nhập và mật khẩu',
    changed:'密码已更改，请重新登录 · Mật khẩu đã đổi, hãy đăng nhập lại',
    gone:'账号不存在，请重新登录 · Tài khoản không còn, hãy đăng nhập lại',
    sess:'登录已过期，请重新登录 · Phiên đăng nhập đã hết hạn, hãy đăng nhập lại',
    secure:'此环境不支持登录验证（需要 https:// 或直接打开本地文件）· Môi trường không hỗ trợ kiểm tra đăng nhập (cần https:// hoặc mở tệp trên máy)',
    wait:'尝试次数过多，请等待 {s} 秒 · Thử quá nhiều lần, hãy chờ {s} giây',
    nokey:'账号尚未开通内容密钥，请联系老师 · Tài khoản chưa có khóa mở nội dung, hãy báo giáo viên',
    decrypting:'正在解密课程内容… · Đang giải mã nội dung bài',
    decfail:'无法解密课程内容，请重新登录或联系老师 · Không giải mã được nội dung, hãy đăng nhập lại hoặc báo giáo viên',
    waitsrv:'尝试次数过多，请稍后再试 · Thử quá nhiều lần, hãy chờ vài phút rồi thử lại'
  };
  function el(tag,cls,txt){var e=document.createElement(tag);if(cls)e.className=cls;if(txt!=null)e.textContent=txt;return e}

  function start(){
    var holder=document.getElementById('bg-login-cfg');if(!holder)return;
    var cfg=null;try{cfg=JSON.parse(holder.textContent)}catch(e){}
    if(cfg&&cfg.enc)cfg.encrypt=true;
    if(holder.parentNode)holder.parentNode.removeChild(holder);   // gỡ cấu hình khỏi DOM (không hiện trong Elements)
    var root=document.documentElement,encData=null,encEl=document.getElementById('bg-enc');
    if(encEl){try{encData=JSON.parse(encEl.textContent)}catch(e){}if(encEl.parentNode)encEl.parentNode.removeChild(encEl)}
    var ov=el('div');ov.id='bg-login';ov.setAttribute('role','dialog');ov.setAttribute('aria-modal','true');ov.setAttribute('aria-labelledby','bg-login-h');
    var box=el('form','bgl-box');box.setAttribute('novalidate','');
    var h=el('h2','bgl-h',(cfg&&cfg.title)||'登录 · Đăng nhập');h.id='bg-login-h';box.appendChild(h);
    if(cfg&&cfg.note)box.appendChild(el('p','bgl-note',cfg.note));
    var st=el('p','bgl-st');st.setAttribute('role','alert');
    var fu=el('label','bgl-f');fu.appendChild(el('span',null,T.user));var iu=el('input');iu.type='text';iu.autocomplete='username';iu.autocapitalize='none';iu.spellcheck=false;iu.setAttribute('autocorrect','off');fu.appendChild(iu);
    var fp=el('label','bgl-f');fp.appendChild(el('span',null,T.pass));var rowp=el('span','bgl-pw'),ip=el('input');ip.type='password';ip.autocomplete='current-password';rowp.appendChild(ip);
    var sh=el('button','bgl-sh',T.show);sh.type='button';sh.onclick=function(){ip.type=ip.type==='password'?'text':'password';sh.textContent=ip.type==='password'?T.show:T.hide};rowp.appendChild(sh);fp.appendChild(rowp);
    var fr=el('label','bgl-r'),cr=el('input');cr.type='checkbox';cr.checked=true;fr.appendChild(cr);fr.appendChild(document.createTextNode(' '+T.remember));
    var go=el('button','bgl-go',T.go);go.type='submit';
    box.appendChild(fu);box.appendChild(fp);if(cfg&&cfg.remember)box.appendChild(fr);box.appendChild(go);box.appendChild(st);
    ov.appendChild(box);
    function mount(){if(!ov.parentNode)document.body.appendChild(ov)}
    function say(t,bad){st.textContent=t||'';st.className='bgl-st'+(bad?' bad':'')}
    mount();
    if(!cfg||!cfg.sec){say(T.cfg,true);go.disabled=true;return}
    var key='bg-login:'+location.pathname+':'+(cfg.id||'');
    /* get(): phiên đã nhớ lâu dài (localStorage) có cờ _p=1; phiên chỉ trong tab (sessionStorage) thì không — để khi mở lại giữ ĐÚNG kiểu lưu ban đầu */
    var store={get:function(){try{var a=localStorage.getItem(key);if(a){var o=JSON.parse(a);if(o)o._p=1;return o}var b=sessionStorage.getItem(key);return b?JSON.parse(b):null}catch(e){return null}},
      set:function(v,persist){var c={};for(var k in v)if(k!=='_p')c[k]=v[k];var s=JSON.stringify(c);try{localStorage.removeItem(key);sessionStorage.removeItem(key);(persist?localStorage:sessionStorage).setItem(key,s)}catch(e){}},
      clear:function(){try{localStorage.removeItem(key);sessionStorage.removeItem(key)}catch(e){}}};
    var fails=0,until=0;

    async function unlock(acc,sess,persist){
      BG.user={user:acc.user,name:acc.name,class:acc.class};BG.token=cfg.backend==='sheet'?String(acc.h||''):'';BG.key=acc.key||null;   // khóa nội dung: khối "update" dùng để giải mã bài nạp lúc chạy
      if(encData){
        if(!acc.key){store.clear();showForm(T.sess);return false}
        try{say(T.decrypting);await reveal(acc.key,encData,function(i,n){say(T.decrypting+' '+i+'/'+n)})}
        catch(e){store.clear();showForm(T.decfail);return false}
      }
      store.set({u:acc.user,h:acc.h,n:acc.name,c:acc.class,k:acc.key?b64(acc.key):undefined,t0:sess?sess.t0:Date.now(),ok:Date.now()},persist);
      root.classList.remove('bg-locked');if(ov.parentNode)ov.parentNode.removeChild(ov);
      var who=el('div','bgl-who');who.appendChild(el('span',null,'\u{1F464} '+acc.name));
      var out=el('button',null,T.out);out.type='button';out.onclick=function(){store.clear();location.reload()};who.appendChild(out);document.body.appendChild(who);
      try{window.dispatchEvent(new CustomEvent('bglogin',{detail:BG.user}))}catch(e){}
      try{lockInit(cfg,acc)}catch(e){}
      return true;
    }
    function showForm(msg){
      root.classList.add('bg-locked');mount();go.disabled=false;iu.disabled=ip.disabled=false;
      say(msg||'',!!msg);setTimeout(function(){try{(iu.value?ip:iu).focus()}catch(e){}},30);
    }
    box.addEventListener('submit',async function(e){
      e.preventDefault();
      var now=Date.now();if(now<until){say(T.wait.replace(/\{s\}/g,Math.ceil((until-now)/1000)),true);return}
      go.disabled=true;say(T.checking);
      var r=await verify(cfg,iu.value,ip.value);
      if(r.ok){fails=0;await unlock(r.account,null,!!(cfg.remember&&cr.checked));return}
      go.disabled=false;
      if(r.code==='bad'||r.code==='empty'){fails++;if(fails>=5){until=Date.now()+30000;fails=0}}
      say(T[r.code]||T.api,true);ip.select();
    });
    /* khôi phục phiên đã nhớ */
    var sess=store.get();
    if(!sess||!sess.u||!sess.h){showForm('');return}
    if(Date.now()-(sess.t0||0)>(cfg.days||30)*864e5){store.clear();showForm(T.sess);return}
    go.disabled=true;iu.disabled=ip.disabled=true;say(T.checking);
    var done=false,guard=setTimeout(function(){if(!done){done=true;offline(sess)}},7000);
    function offline(s){
      var okAt=s.ok||s.t0||0;
      if(cfg.offlineDays>0&&Date.now()-okAt<=cfg.offlineDays*864e5){unlock({user:s.u,name:s.n||s.u,class:s.c||'',h:s.h,key:s.k?unb64(s.k):null},s,!!s._p)}
      else showForm(T.net);
    }
    recheck(cfg,sess).then(function(r){
      if(done)return;done=true;clearTimeout(guard);
      if(r.ok){r.account.key=sess.k?unb64(sess.k):null;unlock(r.account,sess,!!sess._p)}
      else if(r.code==='net'||r.code==='api'||r.code==='token')offline(sess);
      else{store.clear();showForm(T[r.code]||T.sess)}
    },function(){if(!done){done=true;clearTimeout(guard);offline(sess)}});
  }
  if(document.getElementById('bg-login-cfg')){
    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
  }
})();
