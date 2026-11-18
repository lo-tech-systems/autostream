var pageData = (function () {
  try { return JSON.parse(document.getElementById('page-data').textContent); }
  catch (e) { return {}; }
})();
setTimeout(function(){window.location.href=pageData.redirect_url;},5000);
