// Handshake's service worker: shows the server's push messages and opens the ledger they're about.
self.addEventListener('push', e => {
  let m = {};
  try { m = e.data.json(); } catch (err) { m = { title: 'Handshake', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(m.title || 'Handshake', { body: m.body || '', icon: '/icon-192.png', badge: '/icon-192.png', data: { url: m.url || '/' } }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = new URL(e.notification.data.url, self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    const open = list.find(c => new URL(c.url).origin === self.location.origin);
    return open ? open.navigate(url).then(c => (c || open).focus()) : self.clients.openWindow(url);
  }));
});
