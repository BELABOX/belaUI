/*
    belaUI - web UI for the BELABOX project
    Copyright (C) 2020-2021 BELABOX project

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

let isStreaming = false;
let config = {};

let ws = null;

function tryConnect() {
  let c = new WebSocket("ws://" + window.location.host);
  c.addEventListener('message', function (event) {
    handleMessage(JSON.parse(event.data));
  });

  c.addEventListener('close', function (event) {
    ws = null;

    showError("Disconnected from BELABOX. Trying to reconnect...");
    setTimeout(tryConnect, 1000);

    $('.btn-netact').attr('disabled', true);
  });

  c.addEventListener('open', function (event) {
    ws = c;

    hideError();
    tryTokenAuth();
    $('.btn-netact').removeAttr('disabled');
  });
}

tryConnect();

/* WS keep-alive */
/* If the browser / tab is in the background, the Javascript may be suspended,
   while the WS stays connected. In that case we don't want to receive periodic
   updates from the belaUI server as we'll have to walk through a potentially
   long list of stale data when the browser / tab regains focus and wakes up.

   The periodic keep-alive packets let the server know that this client is still
   active and should receive updates.
*/
setInterval(function() {
  if (ws) {
    ws.send(JSON.stringify({keepalive: null}));
  }
}, 10000);


/* Authentication */
function tryTokenAuth() {
  let authToken = localStorage.getItem('authToken');
  if (authToken) {
    ws.send(JSON.stringify({auth: {token: authToken}}));
  } else {
    showLoginForm();
  }
}

function handleAuthResult(msg) {
  if (msg.success === true) {
    if (msg.auth_token) {
      localStorage.setItem('authToken', msg.auth_token);
    }
    $('#login').hide();
    $('#main').show();
    hideError();
  } else {
    showLoginForm();
  }
}

/* Show the revision number */
function setRevisions(revs) {
  let list = '';
  for (s in revs) {
    if (list != '') list += ', ';
    list += `${s}\xa0${revs[s]}`;
  }

  $('#revisions').text(list);
}


/* Network interfaces list */
function setNetif(name, ip, enabled) {
  ws.send(JSON.stringify({'netif': {'name': name, 'ip': ip, 'enabled': enabled}}));
}

function genNetifEntry(enabled, name, ip, throughput, isBold = false) {
  let checkbox = '';
  if (enabled != undefined) {
    const esc_name = name.replaceAll("'", "\\'");
    const esc_ip = name.replaceAll("'", "\\'");
    checkbox = `<input type="checkbox"
                 onclick="setNetif('${esc_name}', '${esc_ip}', this.checked)"
                 ${enabled ? 'checked' : ''}>`;
  }

  const html = `
    <tr>
      <td>${checkbox}</td>
      <td class="netif_name"></td>
      <td class="netif_ip"></td>
      <td class="netif_tp ${isBold ? 'font-weight-bold' : ''}"></td>
    </tr>`;

  const entry = $($.parseHTML(html));
  entry.find('.netif_name').text(name);
  entry.find('.netif_ip').text(ip);
  entry.find('.netif_tp').text(throughput);

  return entry;
}

function updateNetif(netifs) {
  let modemList = [];
  let totalKbps = 0;

  for (const i in netifs) {
    data = netifs[i];
    tpKbps = Math.round((data['tp'] * 8) / 1024);
    totalKbps += tpKbps;

    modemList.push(genNetifEntry(data.enabled, i, data.ip, `${tpKbps} Kbps`));
  }

  if (Object.keys(netifs).length > 1) {
    modemList.push(genNetifEntry(undefined, '', '', `${totalKbps} Kbps`, true));
  }

  $('#modems').html(modemList);
}

function updateSensors(sensors) {
  const sensorList = [];

  for (const i in sensors) {
    data = sensors[i];

    const entryHtml = `
      <tr>
        <td class="sensor_name"></td>
        <td class="sensor_value"></td>
      </tr>`;
    const entry = $($.parseHTML(entryHtml));
    entry.find('.sensor_name').text(i);
    entry.find('.sensor_value').text(data);
    sensorList.push(entry);
  }

  $('#sensors').html(sensorList);
}


/* isStreaming status updates */
function updateStatus(status) {
  isStreaming = status.is_streaming;

  if (isStreaming) {
    updateButtonAndSettingsShow({
      add: "btn-danger",
      remove: "btn-success",
      text: "Stop",
      enabled: true,
      settingsShow: false,
    });
  } else {
    updateButtonAndSettingsShow({
      add: "btn-success",
      remove: "btn-danger",
      text: "Start",
      enabled: true,
      settingsShow: true,
    });
  }
}


/* Configuration loading */
function loadConfig(c) {
  config = c;

  initBitrateSlider(config.max_br ?? 5000);
  initDelaySlider(config.delay ?? 0);
  initSrtLatencySlider(config.srt_latency ?? 2000);
  updatePipelines(null);

  document.getElementById("srtStreamid").value = config.srt_streamid ?? "";
  document.getElementById("srtlaAddr").value = config.srtla_addr ?? "";
  document.getElementById("srtlaPort").value = config.srtla_port ?? "";
}


/* Pipelines */
function updatePipelines(ps) {
  if (ps != null) {
    pipelines = ps;
  }

  const pipelinesSelect = document.getElementById("pipelines");
  pipelinesSelect.innerText = null;

  for (const id in pipelines) {
    const option = document.createElement("option");
    option.value = id;
    option.innerText = pipelines[id];
    if (config.pipeline && config.pipeline == id) {
      option.selected = true;
    }

    pipelinesSelect.append(option);
  }
}


/* Bitrate setting updates */
function updateBitrate(br) {
  $('#bitrateSlider').slider('option', 'value', br.max_br);
  showBitrate(br.max_br);
}


/* Error messages */
function showError(message) {
  $("#errorMsg>span").text(message);
  $("#errorMsg").show();
}

function hideError() {
  $("#errorMsg").hide();
}


/* Handle server-to-client messages */
function handleMessage(msg) {
  console.log(msg);
  for (const type in msg) {
    switch(type) {
      case 'auth':
        handleAuthResult(msg[type]);
        break;
      case 'revisions':
        setRevisions(msg[type]);
        break;
      case 'netif':
        updateNetif(msg[type]);
        break;
      case 'sensors':
        updateSensors(msg[type]);
        break;
      case 'status':
        updateStatus(msg[type]);
        break;
      case 'config':
        loadConfig(msg[type]);
        break;
      case 'pipelines':
        updatePipelines(msg[type]);
        break;
      case 'bitrate':
        updateBitrate(msg[type]);
        break;
      case 'error':
        showError(msg[type].msg);
        break;
    }
  }
}


/* Start / stop */
function getConfig() {
  const maxBr = $("#bitrateSlider").slider("value");

  let config = {};
  config.pipeline = document.getElementById("pipelines").value;
  config.delay = $("#delaySlider").slider("value");
  config.max_br = maxBr;
  config.srtla_addr = document.getElementById("srtlaAddr").value;
  config.srtla_port = document.getElementById("srtlaPort").value;
  config.srt_streamid = document.getElementById("srtStreamid").value;
  config.srt_latency = $("#srtLatencySlider").slider("value");

  return config;
}

async function start() {
  hideError();

  ws.send(JSON.stringify({start: getConfig()}));
}

async function stop() {
  ws.send(JSON.stringify({stop: 0}));
}

async function send_command(cmd) {
  ws.send(JSON.stringify({command: cmd}));
}


/* UI */
function updateButton({ add, remove, text, enabled }) {
  const button = document.getElementById("startStop");

  button.classList.add(add);
  button.classList.remove(remove);

  button.innerHTML = text;
  if (enabled) {
    button.removeAttribute("disabled");
  } else {
    button.setAttribute("disabled", true);
  }
}

function updateButtonAndSettingsShow({ add, remove, text, enabled, settingsShow }) {
  const settingsDivs = document.getElementById("settings");

  if (settingsShow) {
    settingsDivs.classList.remove("d-none");
  } else {
    settingsDivs.classList.add("d-none");
  }

  updateButton({add, remove, text, enabled });
}


function setBitrate(max) {
  if (isStreaming) {
    ws.send(JSON.stringify({bitrate: {max_br: max}}));
  }
}

function showBitrate(value) {
  document.getElementById(
    "bitrateValues"
  ).value = `Max bitrate: ${value} Kbps`;
}

function initBitrateSlider(bitrateDefault) {
  $("#bitrateSlider").slider({
    range: false,
    min: 500,
    max: 12000,
    step: 250,
    value: bitrateDefault,
    slide: (event, ui) => {
      showBitrate(ui.value);
      setBitrate(ui.value);
    },
  });
  showBitrate(bitrateDefault);
}

function showDelay(value) {
  document.getElementById("delayValue").value = `Audio delay: ${value} ms`;
}

function initDelaySlider(defaultDelay) {
  $("#delaySlider").slider({
    min: -2000,
    max: 2000,
    step: 20,
    value: defaultDelay,
    slide: (event, ui) => {
      showDelay(ui.value);
    },
  });
  showDelay(defaultDelay);
}

function showSrtLatency(value) {
  document.getElementById("srtLatencyValue").value = `SRT latency: ${value} ms`;
}

function initSrtLatencySlider(defaultLatency) {
  $("#srtLatencySlider").slider({
    min: 100,
    max: 4000,
    step: 100,
    value: defaultLatency,
    slide: (event, ui) => {
      showSrtLatency(ui.value);
    },
  });
  showSrtLatency(defaultLatency);
}


/* UI event handlers */
document.getElementById("startStop").addEventListener("click", () => {
  if (!isStreaming) {
    updateButton({text: "Starting..."});
    start();
  } else {
    stop();
  }
});

function showLoginForm() {
  $('#main').hide();
  $('#login').show();
}

$('#login>form').submit(function() {
  let auth_req = {auth: {
                    password: $('#password').val(),
                    persistent_token: $('#rememberMe').prop('checked')
                 }};
  $('#password').val('');
  ws.send(JSON.stringify(auth_req));
  console.log();

  return false;
});

$('#logout').click(function() {
  localStorage.removeItem('authToken');
  ws.send(JSON.stringify({logout: true}));
  showLoginForm();
});

$('.command-btn').click(function() {
  send_command(this.id);
});

$('button.showHidePassword').click(function() {
  const inputField = $(this).parents('.input-group').find('input');
  if(inputField.attr('type') == 'password') {
    inputField.attr('type', 'text');
    $(this).text('Hide');
  } else {
    inputField.attr('type', 'password');
    $(this).text('Show');
  }
});
