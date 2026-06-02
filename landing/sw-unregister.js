if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(function(r){r.forEach(function(s){s.unregister();});});
}
