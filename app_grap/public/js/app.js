// ----- Navigation entre les onglets -----
const tabs = document.querySelectorAll('#mainTabs .nav-link');
const sections = document.querySelectorAll('.tab-content');

tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    tabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    sections.forEach(sec => sec.classList.add('d-none'));
    document.querySelector(`#tab-${tab.dataset.tab}`).classList.remove('d-none');
  });
});

// ----- Envoi d'une trame SNMP -----
document.getElementById('snmpForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const data = {
    type: document.getElementById('type').value,
    community: document.getElementById('community').value,
    target: document.getElementById('target').value,
    oid: document.getElementById('oid').value,
    value: document.getElementById('value').value
  };

  const responseZone = document.getElementById('responseZone');
  const responseText = document.getElementById('responseText');
  responseZone.classList.remove('d-none');
  responseText.textContent = "Envoi en cours...";

  try {
    const res = await fetch('http://localhost:5000/api/snmp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await res.json();
    responseText.textContent = JSON.stringify(result, null, 2);
  } catch (err) {
    responseText.textContent = "Erreur de communication avec le serveur SNMP.";
  }
});

// ----- Sauvegarde de la configuration -----
document.getElementById('configForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const config = {
    ip: document.getElementById('configIp').value,
    port: document.getElementById('configPort').value,
    community: document.getElementById('configCommunity').value
  };
  localStorage.setItem('snmpConfig', JSON.stringify(config));
  alert('Configuration sauvegardée avec succès !');
});

// ----- Historique des trames -----
document.getElementById('refreshHistory').addEventListener('click', async () => {
  const tbody = document.getElementById('historyTable');
  tbody.innerHTML = '<tr><td colspan="6">Chargement...</td></tr>';

  try {
    const res = await fetch('http://localhost:5000/api/history');
    const data = await res.json();

    if (data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Aucune trame enregistrée.</td></tr>';
      return;
    }

    tbody.innerHTML = data.map(trame => `
      <tr>
        <td>${trame.date}</td>
        <td>${trame.type}</td>
        <td>${trame.oid}</td>
        <td>${trame.cible}</td>
        <td>${trame.valeur || '-'}</td>
        <td>${trame.statut}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-danger">Erreur lors du chargement de l’historique.</td></tr>';
  }
});