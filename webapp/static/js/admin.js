// Basic chart rendering and auto-refresh for admin dashboard
window.addEventListener('DOMContentLoaded', function(){
  const data = window._admin_data || {};

  function renderCharts(){
    // Distribution pie
    const dist = data.distribution || {};
    const labels = Object.keys(dist);
    const vals = Object.values(dist);
    const ctx = document.getElementById('chartTypes');
    if(ctx){
      new Chart(ctx.getContext('2d'), {
        type: 'pie',
        data: { labels: labels, datasets: [{ data: vals, backgroundColor: ['#3b82f6','#f59e0b','#ef4444','#7c3aed','#64748b'] }] },
        options: { plugins: { legend: { position: 'bottom' } } }
      });
    }

    // Top IPs - vertical bar
    const ipCtx = document.getElementById('chartTopIPs');
    if(ipCtx){
      const ips = (data.topIps||[]).map(x=>x[0]);
      const counts = (data.topIps||[]).map(x=>x[1]);
      new Chart(ipCtx.getContext('2d'),{ type:'bar', data:{ labels:ips, datasets:[{ label:'Attacks', data:counts, backgroundColor:'#3b82f6' }] }, options:{ plugins:{ legend:{ display:false } }, responsive:true } });
    }

    // Top paths - horizontal bar
    const pathCtx = document.getElementById('chartTopPaths');
    if(pathCtx){
      const paths = (data.topPaths||[]).map(x=>x[0]);
      const counts = (data.topPaths||[]).map(x=>x[1]);
      new Chart(pathCtx.getContext('2d'),{ type:'bar', data:{ labels:paths, datasets:[{ label:'Hits', data:counts, backgroundColor:'#3b82f6' }] }, options:{ indexAxis:'y', plugins:{ legend:{ display:false } }, responsive:true } });
    }
  }

  function renderLiveFeed(){
    const feed = document.getElementById('liveFeed');
    if(!feed) return;
    feed.innerHTML = '';
    const items = (data.attacksChart || []).slice(0,10);
    for(const it of items){
      const time = (it.timestamp||'').split('T').pop() || '';
      const type = it.attack_type || 'UNKNOWN';
      const ip = it.ip || '-';
      const action = (it.action||'').toUpperCase() || '';
      const li = document.createElement('li');
      li.className = 'mb-2';
      li.innerHTML = `<span class="text-primary">[${time.slice(0,5)}]</span> <strong>${type}</strong> ${action.toLowerCase()} from <span class="fw-bold">${ip}</span>`;
      feed.appendChild(li);
    }
  }

  renderCharts();
  renderLiveFeed();

  // Auto-refresh dashboard data every 10s
  setInterval(()=>{
    fetch(window.location.pathname).then(resp=>{ if(resp.ok) location.reload(); }).catch(()=>{});
  },10000);

  // Search box behavior
  const search = document.getElementById('adminSearch');
  if(search){
    search.addEventListener('keyup', function(e){ if(e.key==='Enter'){ const q=encodeURIComponent(search.value.trim()); if(q) window.location='/admin/attacks?q='+q; }});
  }
});
