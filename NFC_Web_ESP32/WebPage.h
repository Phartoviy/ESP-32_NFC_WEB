#pragma once
#include <Arduino.h>
const char WEB_PAGE[] PROGMEM = R"HTML(<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NFC · ESP32</title><style>
*{box-sizing:border-box}body{font:16px system-ui,sans-serif;background:#f1f5f9;color:#14243b;max-width:880px;margin:auto;padding:24px}h1{margin-bottom:4px}p{line-height:1.5}.card{background:white;border:1px solid #d9e2ef;border-radius:16px;padding:22px;margin:18px 0}label{display:block;margin:12px 0 6px}input,textarea,select,button{font:inherit;border-radius:8px;padding:10px;border:1px solid #b9c9dc}input,textarea{width:100%}textarea{min-height:90px}button{background:#145ed3;color:white;border:0;cursor:pointer;margin:8px 6px 0 0}button:disabled{opacity:.45;cursor:wait}.secondary{background:#45566c}.danger{background:#b43720}small{color:#52647a}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:14px;max-height:500px;overflow:auto}#selected{font-weight:600}#result{min-height:65px}.row{display:flex;gap:16px}.row>div{flex:1}summary{cursor:pointer;font-weight:600}a{color:#145ed3}@media(max-width:550px){body{padding:12px}.row{display:block}}
</style><h1>NFC · ESP32</h1><p>Чтение и запись через PN532. Держите на антенне только одну метку.</p>
<div class="card"><h2>1. Выберите метку</h2><button id="scan">Сканировать</button><button class="secondary" id="reinit">Перезапустить NFC</button><p id="selected">Метка не выбрана</p><small>При смене метки сканируйте заново. UID проверяется перед каждой операцией.</small></div>
<div class="card"><h2>2. NTAG213 / 215 / 216</h2><button id="read">Прочитать память и NDEF</button><label for="mode">Что записать</label><select id="mode"><option value="text">Текст UTF-8</option><option value="uri">Ссылка HTTP / HTTPS</option></select><label for="value">Содержимое</label><textarea id="value" maxlength="240" placeholder="Привет! Или https://example.com"></textarea><small id="count">0 байт UTF-8; предел поля 240 байт. Вместимость зависит от метки.</small><br><button id="write" class="danger">Записать NDEF</button><p><small>Заменяет существующее NDEF-сообщение. Остаток старой памяти не стирается. Не убирайте метку до завершения.</small></p></div>
<div class="card"><details><summary>MIFARE Classic 1K / 4K — отдельные блоки</summary><p>Используйте известный ключ своего сектора. Запись блока 0 и блоков с ключами отключена.</p><div class="row"><div><label for="block">Блок</label><input id="block" type="number" min="0" max="255" value="4"></div><div><label for="keytype">Тип ключа</label><select id="keytype"><option>A</option><option>B</option></select></div></div><label for="key">Ключ (6 байт HEX)</label><input id="key" value="FFFFFFFFFFFF" maxlength="32" autocomplete="off" spellcheck="false"><button id="cread">Прочитать блок</button><label for="data">Новые данные (16 байт HEX)</label><input id="data" maxlength="64" placeholder="00112233445566778899AABBCCDDEEFF" spellcheck="false"><button id="cwrite" class="danger">Записать блок</button></details></div>
<div class="card"><h2>Результат</h2><div id="status" role="status" aria-live="polite">Готово</div><pre id="result"></pre><button class="secondary" id="save">Скачать результат TXT</button></div>
<script>
const token='@@TOKEN@@';let uid='',busy=false;const $=id=>document.getElementById(id);
$('value').addEventListener('input',()=>{$('count').textContent=new TextEncoder().encode($('value').value).length+' байт UTF-8; максимум 240, в пределах памяти метки.'});
async function run(op,params={}){
 if(busy)return;if(!['scan','reinit'].includes(op)&&!uid){alert('Сначала сканируйте метку');return;}
 if(['write','classic-write'].includes(op)&&!confirm('Записать данные на метку '+uid+'? Существующие данные будут заменены.'))return;
 busy=true;document.querySelectorAll('button').forEach(b=>b.disabled=true);$('status').textContent='Выполняется… Не убирайте метку.';
 if(op==='scan'||op==='reinit'){uid='';$('selected').textContent='Метка не выбрана';}
 try{const r=await fetch('/api/'+op,{method:'POST',headers:{'X-NFC-Token':token,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({...params,uid})});const text=await r.text();$('result').textContent=text;$('status').textContent=r.ok?'Успешно':'Ошибка';
 if(r.ok&&op==='scan'){const m=text.match(/^UID: ([0-9A-F]+)/);if(m){uid=m[1];$('selected').textContent='UID: '+uid;}}
 if(r.status===409){uid='';$('selected').textContent='Сканируйте метку заново';}
 }catch(e){$('status').textContent='Связь потеряна. Если шла запись, сначала прочитайте метку для проверки.';$('result').textContent=String(e);}
 finally{busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false);}
}
$('scan').onclick=()=>run('scan');$('reinit').onclick=()=>run('reinit');$('read').onclick=()=>run('read');
$('write').onclick=()=>run('write',{mode:$('mode').value,value:$('value').value});
function classic(op){run(op,{block:$('block').value,key:$('key').value,keytype:$('keytype').value,data:$('data').value});}
$('cread').onclick=()=>classic('classic-read');$('cwrite').onclick=()=>classic('classic-write');
$('save').onclick=()=>{const url=URL.createObjectURL(new Blob([$('result').textContent],{type:'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='nfc-'+(uid||'result')+'.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
</script></html>)HTML";
