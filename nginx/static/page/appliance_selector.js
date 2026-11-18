  function refreshApplianceSelector(){
    fetch('/api/appliances',{cache:'no-store'})
      .then(function(r){return r.json();})
      .then(function(data){
        if(!data||!data.ok||!Array.isArray(data.appliances)) return;
        var el=document.getElementById('appliance-selector');
        var fallbackId=window.__SELECTOR_CURRENT_ID||window.__LOCAL_ID||window.__REMOTE_AID||'';
        var fallbackPage=window.__SELECTOR_CURRENT_PAGE||'home';
        var currentId=el?(el.getAttribute('data-current-id')||fallbackId):fallbackId;
        var currentPage=el?(el.getAttribute('data-current-page')||fallbackPage):fallbackPage;
        updateSelectorFromAppliances(data.appliances,currentId,currentPage);
      })
      .catch(function(){});
  }
