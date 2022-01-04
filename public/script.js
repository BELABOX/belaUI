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

    updateNetact(false);
  });

  c.addEventListener('open', function (event) {
    ws = c;

    hideError();
    tryTokenAuth();
    updateNetact(true);
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
    $('#login').addClass('d-none');
    $('#initialPasswordForm').addClass('d-none');
    $('#main').removeClass('d-none');
    hideError();
  } else if (!isShowingInitialPasswordForm) {
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
    const esc_ip = ip.replaceAll("'", "\\'");
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


/* Remote status */
let remoteConnectedHideTimer;
function showRemoteStatus(status) {
  if (remoteConnectedHideTimer) {
    clearTimeout(remoteConnectedHideTimer);
    remoteConnectedHideTimer = undefined;
  }

  if (status === true) {
    $('#remoteStatus').removeClass('alert-danger');
    $('#remoteStatus').addClass('alert-success');
    $('#remoteStatus').text("BELABOX cloud remote: connected");
    remoteConnectedHideTimer = setTimeout(function() {
      $('#remoteStatus').addClass('d-none');
      remoteConnectedHideTimer = undefined;
    }, 5000);
  } else if (status.error) {
    switch(status.error) {
      case 'network':
        $('#remoteStatus').text("BELABOX cloud remote: network error. Trying to reconnect...\n");
        break;
      case 'key':
        $('#remoteStatus').text("BELABOX cloud remote: invalid key\n");
        break;
      default:
        return;
    }

    $('#remoteStatus').addClass('alert-danger');
    $('#remoteStatus').removeClass('alert-success');
  } else {
    return;
  }
  $('#remoteStatus').removeClass('d-none');
}

/* status updates */
function updateStatus(status) {
  if (status.is_streaming !== undefined) {
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

  if (status.remote) {
    showRemoteStatus(status.remote);
  }

  if (status.set_password === true) {
    showInitialPasswordForm();
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

  $('#remoteDeviceKey').val(config.remote_key);
  $('#remoteKeyForm button[type=submit]').prop('disabled', true);
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

/* Wifi Settings */
const wifiElement = document.querySelector("#wifi");

// Function to request a refresh of the wifi networks
function refreshWifiNetworks() {
  if (!ws) return;
  ws.send(JSON.stringify({ 
    wifiCommand: {
      command: "refreshNetworks",
    }
  }));

  // Disable buttons and add a loading spinner
  document.querySelectorAll(".refreshbutton").forEach((button) => button.disabled = true);
  document.querySelectorAll(".networks").forEach((network) => network.innerHTML = `
    <tr>
      <td>
        <div class="text-center">
          <div class="spinner-border" role="status">
            <span class="sr-only">Loading...</span>
          </div>
        </div>
      </td>
    </tr>
  `);
  document.querySelectorAll(".knownNetworks").forEach((network) => network.innerHTML = "");
};

function connectToNetworkHandler(dataset) {
  if (dataset.uuid) {
    ws.send(JSON.stringify({ 
      wifiCommand: {
        command: "connectToKnownNetwork",
        uuid: dataset.uuid
      },
    }));
  } else if (dataset.security === "") {
    ws.send(JSON.stringify({ 
      wifiCommand: {
        command: "connectToOpenNetwork",
        ssid: dataset.ssid
      },
    }));
  } else {
    $('#wifiModal').find('#wifiModalTitle').text("Connect to network");
    $('#wifiModal').find('#wifiModalBody').html(`
      <form>
        <div class="form-group">
          <label for="connection-ssid" class="col-form-label">SSID</label>
          <input type="text" class="form-control" id="connection-ssid" value="${dataset.ssid}" readonly>
        </div>
        <div class="form-group">
          <label for="connection-password" class="col-form-label">Password</label>
          <input type="password" class="form-control" id="connection-password">
        </div>
      </form>
    `);
    $('#wifiModal').find('#wifiModalFooter').html(`
      <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
      <button type="button" class="btn btn-success" data-dismiss="modal" onClick="connectToNetworkWithPW('${dataset.device}', '${dataset.ssid}')">Connect</button>
    `);
  
    $('#wifiModal').modal({ show: true });
    setTimeout(() => {
      $('#connection-password').focus();
    }, 500);
  }
}

function connectToNetworkWithPW(device, ssid) {
  const password = $('#connection-password').val();

  ws.send(JSON.stringify({ 
    wifiCommand: {
      command: "connectToNewNetwork",
      device,
      ssid,
      password
    },
  }));
}

function deleteKnownConnectionHandler(dataset) {
  $('#wifiModal').find('#wifiModalTitle').text("Delete connection?");
  $('#wifiModal').find('#wifiModalBody').html(`
    <form>
      <div class="form-group">
        <label for="connection-name" class="col-form-label">Connection:</label>
        <input type="text" class="form-control" id="connection-name" value="${dataset.ssid}" readonly>
      </div>
    </form>
  `);
  $('#wifiModal').find('#wifiModalFooter').html(`
    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
    <button  type="button" class="btn btn-danger" data-dismiss="modal" onClick="deleteKnownConnection('${dataset.uuid}')">Delete</button>
  `);

  $('#wifiModal').modal({ show: true });
}

function deleteKnownConnection(uuid) {
  ws.send(JSON.stringify({ 
    wifiCommand: {
      command: "deleteKnownConnection",
      uuid
    },
  }));
}

function disconnectWifiDevice(device) {
  ws.send(JSON.stringify({ 
    wifiCommand: {
      command: "disconnectWifiDevice",
      device
    },
  }));
}

// Update wifi devices based on new status
function updateWifiDevices(status) {
  const devices = Object.keys(status);

  devices.forEach((device) => {
    // If wifi device is not yet on the page, add it.
    if (document.querySelector(`#${device}`) == null) {
      const html = `
        <div id="${device}" class="wifi-settings card mb-2">
          <div class="card-header bg-success text-center" type="button" data-toggle="collapse" data-target="#collapseWifi-${device}">
            <button class="btn btn-link text-white" type="button" data-toggle="collapse" data-target="#collapseWifi-${device}" aria-expanded="false" aria-controls="collapseWifi-${device}">
              Wifi settings: <strong>${device}</strong>
            </button>
          </div>

          <div class="collapse" id="collapseWifi-${device}">
            <div class="card-body">

              <label for="connection-${device}">Current connection</label>
              <div class="input-group mb-2">
                <input type="text" id="connection-${device}" class="form-control text-center" value="----" readonly>
                <div id="conButtons-${device}" class="input-group-append"></div>
              </div>

              <hr class="mb-4">

              <button type="button" id="refreshNetworks-${device}" class="btn btn-block btn-warning btn-netact mb-2 refreshbutton" onClick="refreshWifiNetworks()">
                Scan Wifi List
              </button>

              <div class="mb-3 text-secondary text-center small lastRefresh"></div>

              <table class="table mb-2">
                <tbody id="wifiNetworks-${device}" class="networks"></tbody>
              </table>

              <table class="table mb-0">
                <tbody id="knownWifiNetworks-${device}" class="knownNetworks"></tbody>
              </table>
  
            </div>
          </div>
        </div>
      `

      wifiElement.insertAdjacentHTML('beforeend', html);
    };

    // Set values for current connection
    document.getElementById(`connection-${device}`).value = status[device].ssid ? status[device].ssid : "----";

    // Add / Remove buttons for current connection
    const conButtons = document.getElementById(`conButtons-${device}`);
    conButtons.innerHTML = status[device].ssid ? `
      <button class="btn btn-secondary px-4" type="button" data-device="${device}" onClick="disconnectWifiDevice(this.dataset.device)">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-wifi-off" viewBox="0 0 16 16">
          <path d="M10.706 3.294A12.545 12.545 0 0 0 8 3C5.259 3 2.723 3.882.663 5.379a.485.485 0 0 0-.048.736.518.518 0 0 0 .668.05A11.448 11.448 0 0 1 8 4c.63 0 1.249.05 1.852.148l.854-.854zM8 6c-1.905 0-3.68.56-5.166 1.526a.48.48 0 0 0-.063.745.525.525 0 0 0 .652.065 8.448 8.448 0 0 1 3.51-1.27L8 6zm2.596 1.404.785-.785c.63.24 1.227.545 1.785.907a.482.482 0 0 1 .063.745.525.525 0 0 1-.652.065 8.462 8.462 0 0 0-1.98-.932zM8 10l.933-.933a6.455 6.455 0 0 1 2.013.637c.285.145.326.524.1.75l-.015.015a.532.532 0 0 1-.611.09A5.478 5.478 0 0 0 8 10zm4.905-4.905.747-.747c.59.3 1.153.645 1.685 1.03a.485.485 0 0 1 .047.737.518.518 0 0 1-.668.05 11.493 11.493 0 0 0-1.811-1.07zM9.02 11.78c.238.14.236.464.04.66l-.707.706a.5.5 0 0 1-.707 0l-.707-.707c-.195-.195-.197-.518.04-.66A1.99 1.99 0 0 1 8 11.5c.374 0 .723.102 1.021.28zm4.355-9.905a.53.53 0 0 1 .75.75l-10.75 10.75a.53.53 0 0 1-.75-.75l10.75-10.75z"/>
        </svg>
      </button>
      <button class="btn btn-danger" type="button" data-uuid="${status[device].uuid}" data-ssid="${status[device].ssid}" onClick="deleteKnownConnectionHandler(this.dataset)">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash-fill" viewBox="0 0 16 16">
          <path d="M2.5 1a1 1 0 0 0-1 1v1a1 1 0 0 0 1 1H3v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V4h.5a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H10a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1H2.5zm3 4a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 .5-.5zM8 5a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7A.5.5 0 0 1 8 5zm3 .5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 1 0z"/>
        </svg>
      </button>
    ` : "";
  });

  // Cleanup disconnected devices from UI
  const wifiSettingsElements = document.querySelectorAll(".wifi-settings");
  wifiSettingsElements.forEach((we) => {
    if (devices.includes(we.id)) return;
    we.remove();
  });
}

function updateWifiNetworks({ knownWifiConnections, availableWifiNetworks }) {
  Object.keys(availableWifiNetworks).forEach(device => {
    const wifiNetworksFiltered = availableWifiNetworks[device].filter((n) => n.active !== true).map((n) => {
      // If known connection, add a delete button
      const knownConnection = knownWifiConnections[device] && knownWifiConnections[device].find((c) => c.ssid === n.ssid) || null;

      const html = `
        <tr>
          <td class="security px-0">${n.security != "" ? `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-lock-fill" viewBox="0 0 16 16">
              <path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/>
            </svg>` : ""}
          </td>
          <td class="signal">${n.bars}</td>
          <td class="ssid" ${knownConnection ? `data-uuid="${knownConnection.uuid}"`: ""} data-ssid="${n.ssid}" data-security="${n.security}" data-device="${device}" onClick="connectToNetworkHandler(this.dataset)">${n.ssid}</td>
          <td class="deleteButton text-right">${knownConnection ? `
            <button class="btn btn-danger" type="button" data-uuid="${knownConnection.uuid}" data-ssid="${knownConnection.ssid}" onClick="deleteKnownConnectionHandler(this.dataset)">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash-fill" viewBox="0 0 16 16">
                <path d="M2.5 1a1 1 0 0 0-1 1v1a1 1 0 0 0 1 1H3v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V4h.5a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H10a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1H2.5zm3 4a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 .5-.5zM8 5a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7A.5.5 0 0 1 8 5zm3 .5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 1 0z"/>
              </svg>
            </button>
          ` : ""}
          </td>
        </tr>
      `;

      return $($.parseHTML(html));
    });

    // Remove known networks if they are visible in scanlist
    const knownNetworksFiltered = knownWifiConnections[device] && knownWifiConnections[device].filter((n) => !availableWifiNetworks[device].find((c) => c.ssid === n.ssid)).map((n) => {
      const html = `
        <tr class="table-active">
          <td class="ssid">${n.ssid}</td>
          <td class="deleteButton text-right">
            <button class="btn btn-danger" type="button" data-uuid="${n.uuid}" data-ssid="${n.ssid}" onClick="deleteKnownConnectionHandler(this.dataset)">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash-fill" viewBox="0 0 16 16">
                <path d="M2.5 1a1 1 0 0 0-1 1v1a1 1 0 0 0 1 1H3v9a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V4h.5a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H10a1 1 0 0 0-1-1H7a1 1 0 0 0-1 1H2.5zm3 4a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 .5-.5zM8 5a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-1 0v-7A.5.5 0 0 1 8 5zm3 .5v7a.5.5 0 0 1-1 0v-7a.5.5 0 0 1 1 0z"/>
              </svg>
            </button>
          </td>
        </tr>
      `;

      return $($.parseHTML(html));
    });
    
    $(`#wifiNetworks-${device}`).html(wifiNetworksFiltered);
    $(`#knownWifiNetworks-${device}`).html(knownNetworksFiltered);

    document.querySelectorAll(".refreshbutton").forEach((button) => button.disabled = false);
    document.querySelectorAll(".lastRefresh").forEach((el) => el.innerHTML = `Last update: ${new Date().toLocaleTimeString()}`);
  });
}


/* Error messages */
function showError(message) {
  $("#errorMsg>span").text(message);
  $("#errorMsg").removeClass('d-none');
}

function hideError() {
  $("#errorMsg").addClass('d-none');
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
      case 'wifidevices':
        updateWifiDevices(msg[type])
        break;
      case 'wifinetworks':
        updateWifiNetworks(msg[type])
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

function updateNetact(isActive) {
  if (isActive) {
    $('.btn-netact').attr('disabled', false);
    checkRemoteKey();
    $('.set-password').trigger('input');
  } else {
    $('.btn-netact').attr('disabled', true);
  }
}


function showLoginForm() {
  $('#main').addClass('d-none');
  $('#initialPasswordForm').addClass('d-none');
  $('#login').removeClass('d-none');
}

function sendAuthMsg(password, isPersistent) {
  let auth_req = {auth: {password, persistent_token: isPersistent}};
  ws.send(JSON.stringify(auth_req));
}

$('#login>form').submit(function() {
  const password = $('#password').val();
  const rememberMe = $('#login .rememberMe').prop('checked');
  sendAuthMsg(password, rememberMe);

  $('#password').val('');

  return false;
});

let isShowingInitialPasswordForm = false;
function showInitialPasswordForm() {
  $('#main').addClass('d-none');
  $('#login').addClass('d-none');
  $('#initialPasswordForm').removeClass('d-none');
  isShowingInitialPasswordForm = true;
}

function checkPassword() {
  const form = $(this).parents('form');

  const p = $(form).find('input[type=password]').val();
  let isValid = false;

  if (p.length < 8) {
    $(form).find('.hint').text('Minimum length: 8 characters');
  } else {
    $(form).find('.hint').text('');
    isValid = true;
  }

  $(form).find('button[type=submit]').prop('disabled', !isValid);
}
$('.set-password').on('input', checkPassword);

function sendPasswordFromInput(form) {
  const passwordInput = $(form).find('input[type=password]');
  const password = passwordInput.val();

  passwordInput.val('');
  $(form).find('button[type=submit]').prop('disabled', true);

  ws.send(JSON.stringify({config: {password}}));

  return password;
}

$('#initialPasswordForm form').submit(function() {
  const password = sendPasswordFromInput(this);
  const remember = $(this).find('.rememberMe').prop('checked');
  sendAuthMsg(password, remember);

  return false;
});

$('form#updatePasswordForm').submit(function() {
  sendPasswordFromInput(this);

  return false;
});

function checkRemoteKey() {
  const remote_key = $('#remoteDeviceKey').val();
  const disabled = (remote_key == config.remote_key);
  $('#remoteKeyForm button[type=submit]').prop('disabled', disabled);
}
$('#remoteDeviceKey').on('input', checkRemoteKey);

$('#remoteKeyForm').submit(function() {
  const remote_key = $('#remoteDeviceKey').val();
  ws.send(JSON.stringify({config: {remote_key}}));
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
