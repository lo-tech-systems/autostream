(function(){
function alignPoll(){
  fetch('/api/align/status',{cache:'no-store'}).then(function(r){return r.json();}).then(function(d){
    var startBtn=document.getElementById('alignStartBtn');
    var abortBtn=document.getElementById('alignAbortBtn');
    var statusEl=document.getElementById('alignStatus');
    var launchEl=document.getElementById('alignLaunch');
    var running=(d.state==='running'||d.state==='finishing');
    if(startBtn)startBtn.disabled=running;
    if(abortBtn)abortBtn.style.display=running?'':'none';
    if(statusEl){
      if(running){
        var out=d.current_output_name?(' \u2014 playing on '+d.current_output_name):'';
        statusEl.textContent='Calibrating'+out+' (cycle '+(d.cycle_count||0)+')';
      } else if(d.last_error){
        statusEl.textContent='Stopped: '+d.last_error;
      } else {
        statusEl.textContent='';
      }
    }
    if(launchEl){
      if(running&&d.launch_url){
        launchEl.style.display='';
        var link=document.getElementById('alignLaunchLink');
        if(link){link.href=d.launch_url;}
      } else {
        launchEl.style.display='none';
      }
    }
  }).catch(function(){});
}
window.alignStart=function(){
  var startBtn=document.getElementById('alignStartBtn');
  var statusEl=document.getElementById('alignStatus');
  var outputIds=[];
  document.querySelectorAll('.align-output-checkbox:checked').forEach(function(cb){outputIds.push(cb.value);});
  var volumeEl=document.getElementById('alignVolume');
  var volume=volumeEl?parseInt(volumeEl.value,10):50;
  var originalLabel=startBtn?startBtn.textContent:'Start';
  if(startBtn){startBtn.disabled=true;startBtn.textContent='Starting\u2026';}
  if(statusEl)statusEl.textContent='';
  fetch('/api/align/start',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({output_ids:outputIds,volume:volume})
  }).then(function(r){return r.json();}).then(function(d){
    if(!d.ok||!d.launch_url){
      if(startBtn){startBtn.disabled=false;startBtn.textContent=originalLabel;}
      if(statusEl)statusEl.textContent='Could not start: '+(d.error||'error');
      return;
    }
    window.location.href=d.launch_url;
  }).catch(function(){
    if(startBtn){startBtn.disabled=false;startBtn.textContent=originalLabel;}
    if(statusEl)statusEl.textContent='Could not start: network error';
  });
};
window.alignAbort=function(){
  fetch('/api/align/abort',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({})
  }).then(function(){alignPoll();}).catch(function(){});
};
window.alignApply=function(){
  var offsets={};
  var summary=[];
  document.querySelectorAll('.align-review-table tbody tr').forEach(function(tr){
    var id=tr.querySelector('.align-offset-id');
    var val=tr.querySelector('.align-offset-val');
    if(id&&val){
      offsets[id.value]=parseInt(val.value,10)||0;
      summary.push({
        name:tr.cells[0]?tr.cells[0].textContent:id.value,
        current:tr.cells[3]?tr.cells[3].textContent:'',
        proposed:tr.cells[4]?tr.cells[4].textContent:''
      });
    }
  });
  fetch('/api/align/apply',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({offsets:offsets})
  }).then(function(r){return r.json();}).then(function(d){
    if(!d||!d.ok){
      var st=document.getElementById('align-apply-status');
      if(st)st.textContent='Could not apply: '+((d&&d.error)||'error');
      return;
    }
    var rows=summary.map(function(s){
      return '<tr><td>'+s.name+'</td><td>'+s.current+'</td><td><strong>'+s.proposed+'</strong></td></tr>';
    }).join('');
    var block=document.getElementById('align-review-block');
    if(block){
      block.innerHTML='<h2>Offsets applied</h2>'
        +'<table class="align-review-table">'
        +'<thead><tr><th>Output</th><th>Previous</th><th>New</th></tr></thead>'
        +'<tbody>'+rows+'</tbody></table>'
        +'<p class="helptext">The new offsets are live on the outputs now.</p>'
        +'<div style="margin-top:1rem;">'
        +'<a class="pill-btn small" href="/owntone-setup" style="width:100%;margin-top:0.5rem;">Open Output Settings</a>'
        +'<a class="pill-btn small" href="/align" style="width:100%;margin-top:0.5rem;">Run Alignment Again</a>'
        +'</div>';
    }
  }).catch(function(){
    var st=document.getElementById('align-apply-status');
    if(st)st.textContent='Could not apply: network error';
  });
};
window.alignShowPrivacy=function(){
  var msg='<p>This measurement page is downloaded from lo-tech.co.uk because '
    +'browsers only allow microphone access on a secure (HTTPS) website. '
    +'Fetching it is a normal page load, like visiting any website \u2014 so '
    +"lo-tech.co.uk's server does see that request happen.</p>"
    +'<p>The settings for this run (which outputs, which tones) travel in '
    +'part of the link that browsers never send to a web server, so '
    +'lo-tech.co.uk does not see them.</p>'
    +'<p>All listening and analysis happens on your phone itself \u2014 no audio '
    +'is ever recorded or transmitted.</p>'
    +'<p>Once the measurement finishes, the timing results are sent '
    +'directly to this device over your own network, not to lo-tech.co.uk.</p>';
  var btnOk=document.getElementById('infoModalOk');
  if(btnOk)btnOk.textContent='Continue';
  showInfoModal('Privacy',msg,true);
};
window.alignDiscard=function(){
  fetch('/api/align/discard',{
    method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-CSRF-Token':window.__CSRF||''},
    body:JSON.stringify({})
  }).then(function(){window.location.href='/align';}).catch(function(){});
};
window.alignUpdateReference=function(){
  var first=true;
  document.querySelectorAll('.align-output-checkbox').forEach(function(cb){
    var card=cb.closest('.output-card');
    var chip=card?card.querySelector('.align-ref-chip'):null;
    if(!chip)return;
    var isRef=cb.checked&&first;
    if(cb.checked)first=false;
    chip.style.display=isRef?'inline-block':'none';
  });
};
document.addEventListener('DOMContentLoaded',function(){
  alignPoll();
  setInterval(alignPoll,2000);
  alignUpdateReference();
});
}());
