function updateProgress() {
  fetch('/api/progress')
    .then(response => response.json())
    .then(data => {
      if (data.progress === 0) {
        document.getElementById('progress-container').classList.add('hidden');
        document.getElementById('completed-message').classList.add('hidden');
        document.getElementById('no-progress').classList.remove('hidden');
      } else if (data.progress > 0 && data.progress < 100) {
        document.getElementById('no-progress').classList.add('hidden');
        document.getElementById('progress-container').classList.remove('hidden');
        document.getElementById('completed-message').classList.add('hidden');
        document.getElementById('progress-text').innerText = data.progress.toFixed(2) + '%';
        document.getElementById('progress-bar').value = data.progress;
        setTimeout(updateProgress, 1000);
      } else if (data.progress >= 100) {
        document.getElementById('progress-container').classList.add('hidden');
        document.getElementById('completed-message').classList.remove('hidden');
        setTimeout(function() {
          document.getElementById('completed-message').classList.add('hidden');
          document.getElementById('no-progress').classList.remove('hidden');
        }, 3000);
      }
    })
    .catch(err => {
      console.error(err);
    });
}
updateProgress();

function loadIPs() {
  fetch('/api/ips')
    .then(response => response.json())
    .then(data => {
      let select = document.getElementById('ip-select');
      if (data.length === 0) {
        setTimeout(loadIPs, 5000);
        return;
      }
      select.innerHTML = '<option value="">-- Selecione um IP --</option>';
      data.forEach(ip => {
        let option = document.createElement('option');
        option.value = ip;
        option.text = ip;
        select.appendChild(option);
      });
    });
}
loadIPs();

function loadProtocols() {
  let selectedIP = document.getElementById('ip-select').value;
  let protocolSelect = document.getElementById('protocol-select');
  if (selectedIP) {
    fetch('/api/protocols?ip=' + encodeURIComponent(selectedIP))
      .then(response => response.json())
      .then(data => {
        protocolSelect.innerHTML = '<option value="">-- Todos Protocolos --</option>';
        data.forEach(protocol => {
          let option = document.createElement('option');
          option.value = protocol;
          option.text = protocol;
          protocolSelect.appendChild(option);
        });
      });
  } else {
    protocolSelect.innerHTML = '<option value="">-- Selecione um IP primeiro --</option>';
  }
}
document.getElementById('ip-select').addEventListener('change', loadProtocols);

let ctx = document.getElementById('timelineChart').getContext('2d');
let timelineChart = new Chart(ctx, {
  type: 'line',
  data: { labels: [], datasets: [{ label: 'Eventos', data: [], borderColor: '#3b82f6', tension: 0.1 }] },
  options: {
    scales: {
      x: { type: 'time', time: { unit: 'minute' }, title: { display: true, text: 'Tempo' } },
      y: { title: { display: true, text: 'Número de Eventos' } }
    }
  }
});

function loadTimeline() {
  let selectedIP = document.getElementById('ip-select').value;
  let selectedProtocol = document.getElementById('protocol-select').value;
  let selectedView = document.getElementById('view-mode-select').value;
  if (selectedView === "complete") {
    timelineChart.options.scales.x.time.unit = "second";
  } else {
    timelineChart.options.scales.x.time.unit = "minute";
  }
  if (selectedIP) {
    let url = '/api/timeline?ip=' + encodeURIComponent(selectedIP) + '&view=' + encodeURIComponent(selectedView);
    if (selectedProtocol) {
      url += '&protocol=' + encodeURIComponent(selectedProtocol);
    }
    fetch(url)
      .then(response => response.json())
      .then(data => {
        if (selectedView === "summarized") {
          let labels = data.map(item => item.minute);
          let counts = data.map(item => item.count);
          timelineChart.data.labels = labels;
          timelineChart.data.datasets[0].data = counts;
        } else {
          let labels = data.map(item => item.timestamp);
          let counts = data.map(item => item.count);
          timelineChart.data.labels = labels;
          timelineChart.data.datasets[0].data = counts;
        }
        timelineChart.update();
      });
  }
  setTimeout(loadTimeline, 5000);
}
loadTimeline();

function loadEvents() {
    let selectedIP = document.getElementById('ip-select').value;
    let selectedProtocol = document.getElementById('protocol-select').value;
    if (selectedIP) {
      let url = '/api/events?ip=' + encodeURIComponent(selectedIP);
      if (selectedProtocol) {
        url += '&protocol=' + encodeURIComponent(selectedProtocol);
      }
      fetch(url)
        .then(response => response.json())
        .then(data => {
          let tbody = document.querySelector('#events-table tbody');
          tbody.innerHTML = ''; 
          data.forEach(event => {
            let row = document.createElement('tr');
            row.innerHTML = `
              <td class="px-4 py-2 border">${event.timestamp}</td>
              <td class="px-4 py-2 border">${event.ip}</td>
              <td class="px-4 py-2 border">${event.protocol}</td>
            `;
            tbody.appendChild(row);
          });
        });
    }
    setTimeout(loadEvents, 5000);
  }
  loadEvents();

document.getElementById('ip-select').addEventListener('change', loadTimeline);
document.getElementById('protocol-select').addEventListener('change', loadTimeline);
document.getElementById('view-mode-select').addEventListener('change', function() {
  let chartContainer = document.getElementById('chart-container');
  if (this.value === "complete") {
    chartContainer.style.height = "600px"; 
    timelineChart.options.scales.x.time.unit = "second";
  } else {
    chartContainer.style.height = "400px";
    timelineChart.options.scales.x.time.unit = "minute";
  }
  timelineChart.update();
  loadTimeline();
});