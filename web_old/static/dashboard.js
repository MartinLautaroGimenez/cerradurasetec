let chartLinea, chartBarras, chartTorta, chartGauge;

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('active');
}

function toggleTheme() {
  document.body.classList.toggle('dark-theme');
}

function showSection(id) {
  ['dashboard', 'usuarios', 'logs'].forEach(s =>
    document.getElementById(`section-${s}`).classList.add('d-none')
  );
  document.getElementById(`section-${id}`).classList.remove('d-none');
  document.getElementById('section-title').innerText =
    id === 'dashboard' ? 'Dashboard' :
    id === 'usuarios' ? 'Usuarios' : 'Logs';
}

function showForm(u = null) {
  document.getElementById('usuarioId').value = u?.id || '';
  document.getElementById('uid').value = u?.uid || '';
  document.getElementById('nombre').value = u?.nombre || '';
  modal.show();
}

document.getElementById('formUsuario').addEventListener('submit', e => {
  e.preventDefault();
  const id = document.getElementById('usuarioId').value;
  const payload = {
    uid: document.getElementById('uid').value,
    nombre: document.getElementById('nombre').value
  };
  fetch(id ? `/api/usuarios/${id}` : '/api/usuarios', {
    method: id ? 'PUT' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(() => {
    modal.hide();
    cargarUsuarios();
    Swal.fire('✅ Guardado', '', 'success');
  });
});

function eliminarUsuario(id) {
  Swal.fire({
    title: '¿Eliminar usuario?',
    icon: 'warning',
    showCancelButton: true,
    confirmButtonText: 'Sí, eliminar'
  }).then(result => {
    if (result.isConfirmed) {
      fetch(`/api/usuarios/${id}`, { method: 'DELETE' }).then(() => {
        cargarUsuarios();
        Swal.fire('Eliminado', '', 'success');
      });
    }
  });
}

function cargarUsuarios() {
  fetch('/api/usuarios').then(r => r.json()).then(data => {
    const tbody = document.querySelector('#tablaUsuarios tbody');
    tbody.innerHTML = '';
    data.forEach(u => {
      tbody.innerHTML += `<tr>
        <td>${u.id}</td>
        <td>${u.uid}</td>
        <td>${u.nombre}</td>
        <td>
          <button class="btn btn-warning btn-sm" onclick='showForm(${JSON.stringify(u)})'>✏️</button>
          <button class="btn btn-danger btn-sm" onclick='eliminarUsuario(${u.id})'>🗑</button>
        </td>
      </tr>`;
    });
  });
}

function filtrarLogs() {
  const desde = document.getElementById('desde').value;
  const hasta = document.getElementById('hasta').value;
  fetch(`/api/logs?desde=${desde}&hasta=${hasta}`)
    .then(res => res.json())
    .then(data => {
      const tbody = document.querySelector('#tablaLogs tbody');
      tbody.innerHTML = '';
      data.forEach(l => {
        const fecha = l.creado_en || l.fecha_hora || '--';
        tbody.innerHTML += `<tr>
          <td>${l.id}</td>
          <td>${l.uid}</td>
          <td>${l.nombre}</td>
          <td>${fecha}</td>
        </tr>`;
      });
    });
}

function exportarLogs() {
  window.location.href = '/api/logs/exportar';
}

function cargarDashboard() {
  fetch('/api/logs?desde=2023-01-01&hasta=2099-12-31')
    .then(res => res.json())
    .then(data => {
      const total = data.length;
      const unicos = new Set(data.map(l => l.uid)).size;
      const validos = data.filter(l => l.nombre !== 'desconocido').length;
      const invalidos = total - validos;
      const porcentaje = total === 0 ? 0 : Math.round((validos / total) * 100);

      document.getElementById('totalAccesos').textContent = total;
      document.getElementById('totalUIDs').textContent = unicos;
      document.getElementById('validos').textContent = validos;
      document.getElementById('invalidos').textContent = invalidos;

      // Accesos por día (línea)
      const porDia = {};
      data.forEach(l => {
        const dia = (l.creado_en || l.fecha_hora).split(' ')[0];
        porDia[dia] = (porDia[dia] || 0) + 1;
      });
      const dias = Object.keys(porDia).sort();
      const conteo = dias.map(d => porDia[d]);

      chartLinea?.destroy();
      chartLinea = new Chart(document.getElementById('graficoLinea'), {
        type: 'line',
        data: {
          labels: dias,
          datasets: [{
            label: 'Accesos diarios',
            data: conteo,
            borderColor: '#3b82f6',
            tension: 0.4,
            fill: true,
            backgroundColor: 'rgba(59,130,246,0.1)'
          }]
        }
      });

      // Torta: UIDs más frecuentes
      const porUID = {};
      data.forEach(l => {
        porUID[l.uid] = (porUID[l.uid] || 0) + 1;
      });
      const topUIDs = Object.entries(porUID)
        .sort((a,b) => b[1]-a[1])
        .slice(0,5);
      const [labels, values] = [topUIDs.map(e => e[0]), topUIDs.map(e => e[1])];

      chartTorta?.destroy();
      chartTorta = new ApexCharts(document.getElementById('graficoTorta'), {
        chart: { type: 'donut' },
        series: values,
        labels: labels,
        theme: { mode: 'dark' }
      });
      chartTorta.render();

      // Barras válidos vs inválidos
      chartBarras?.destroy();
      chartBarras = new ApexCharts(document.getElementById('graficoBarras'), {
        chart: { type: 'bar' },
        series: [{
          name: 'Cantidad',
          data: [validos, invalidos]
        }],
        xaxis: { categories: ['Válidos', 'Inválidos'] },
        colors: ['#22c55e', '#ef4444'],
        theme: { mode: 'dark' }
      });
      chartBarras.render();

      // Radial gauge
      chartGauge?.destroy();
      chartGauge = new ApexCharts(document.getElementById('graficoGauge'), {
        chart: { type: 'radialBar' },
        series: [porcentaje],
        labels: ['% Éxito'],
        colors: ['#3b82f6'],
        theme: { mode: 'dark' }
      });
      chartGauge.render();
    });
    fetch('/api/stats').then(r => r.json()).then(data => {
  // Heatmap
  const dias = Object.keys(data.por_dia).sort();
  const valores = dias.map(d => data.por_dia[d]);
  new ApexCharts(document.getElementById('graficoHeatmap'), {
    chart: { type: 'heatmap', height: 300 },
    series: [{
      name: 'Accesos',
      data: dias.map((d, i) => ({ x: d, y: valores[i] }))
    }],
    theme: { mode: 'dark' },
    colors: ['#0ea5e9']
  }).render();

  // Gauge intervalo
  new ApexCharts(document.getElementById('gaugeIntervalo'), {
    chart: { type: 'radialBar' },
    series: [Math.min(100, data.intervalo_promedio_segundos / 10)],
    labels: ['Intervalo (s)'],
    theme: { mode: 'dark' },
    colors: ['#facc15']
  }).render();

  // Último acceso + reloj
  const fecha = data.ultimo_acceso;
  document.getElementById('ultimoAccesoReal').textContent = fecha;
  let start = new Date(fecha);
  setInterval(() => {
    const ahora = new Date();
    const diff = Math.floor((ahora - start) / 1000);
    document.getElementById('relojAcceso').textContent = `hace ${diff} segundos`;
  }, 1000);

  // Toast visual
  Toastify({
    text: `¡Dashboard cargado con ${data.total} accesos!`,
    duration: 3000,
    gravity: "top",
    position: "right",
    backgroundColor: "#22c55e"
  }).showToast();
});

}

// Init
cargarUsuarios();
cargarDashboard();
