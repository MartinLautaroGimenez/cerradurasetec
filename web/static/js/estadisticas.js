  const estadoData = {{ estado_data | tojson }};
  const topUIDs = {{ top_uids | tojson }};
  const porDia = {{ por_dia | tojson }};
  const heatmapRaw = {{ heatmap_data | tojson }};

  // Estado
  const estadoChart = echarts.init(document.getElementById('grafico_estado'));
  estadoChart.setOption({
    title: { text: 'Accesos válidos vs inválidos' },
    tooltip: {},
    xAxis: { type: 'category', data: estadoData.map(e => e.estado) },
    yAxis: { type: 'value' },
    series: [{ type: 'bar', data: estadoData.map(e => e.cantidad) }]
  });

  // Top UIDs
  const uidChart = echarts.init(document.getElementById('grafico_uids'));
  uidChart.setOption({
    title: { text: 'Top 5 UIDs más usados' },
    tooltip: { trigger: 'item' },
    series: [{
      type: 'pie',
      radius: '50%',
      data: topUIDs.map(uid => ({ value: uid.cantidad, name: uid.uid }))
    }]
  });

  // Por día
  const diasChart = echarts.init(document.getElementById('grafico_dias'));
  diasChart.setOption({
    title: { text: 'Accesos últimos 7 días' },
    xAxis: { type: 'category', data: porDia.map(d => d.dia) },
    yAxis: { type: 'value' },
    series: [{ type: 'line', data: porDia.map(d => d.cantidad) }]
  });

  // Gauge
  const total = estadoData.reduce((a, b) => a + b.cantidad, 0);
  const validos = estadoData.find(e => e.estado === 'correcto')?.cantidad || 0;
  const gaugeChart = echarts.init(document.getElementById('grafico_gauge'));
  gaugeChart.setOption({
    title: { text: 'Porcentaje de accesos correctos' },
    series: [{
      type: 'gauge',
      progress: { show: true },
      detail: { valueAnimation: true, formatter: '{value}%' },
      data: [{ value: ((validos / total) * 100).toFixed(1), name: 'Éxito' }]
    }]
  });

  // Heatmap
  const horas = [...Array(24).keys()];
  const dias = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const heatData = heatmapRaw.map(e => [
    parseInt(e.hora), dias.indexOf(e.dia_semana), e.cantidad
  ]);
  const heatChart = echarts.init(document.getElementById('grafico_heatmap'));
  heatChart.setOption({
    title: { text: 'Actividad por día y hora' },
    tooltip: {
      position: 'top',
      formatter: d => `${dias[d.value[1]]}, ${d.value[0]}:00 — ${d.value[2]} accesos`
    },
    grid: { height: '70%', top: '10%' },
    xAxis: {
      type: 'category',
      data: horas.map(h => h + ":00"),
      name: 'Hora'
    },
    yAxis: {
      type: 'category',
      data: dias,
      name: 'Día'
    },
    visualMap: {
      min: 0,
      max: Math.max(...heatData.map(v => v[2])),
      calculable: true,
      orient: 'horizontal',
      left: 'center',
      bottom: '5%'
    },
    series: [{
      name: 'Accesos',
      type: 'heatmap',
      data: heatData,
      label: { show: false },
      emphasis: { itemStyle: { shadowBlur: 10, shadowColor: '#333' } }
    }]
  });