/*
    belaUI - web UI for the BELABOX project
    Copyright (C) 2020-2022 BELABOX project

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

function getThemeSetting() {
  return $('#themeSelector>select').val();
}

function updateTheme(theme) {
  if (!theme) {
    theme = getThemeSetting();
  }

  if (theme == 'auto') {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      theme = 'dark';
    }
  }

  if (theme == 'dark') {
    $('body').addClass('dark');
  } else {
    $('body').removeClass('dark');
  }
}

// Load the persistent setting, if available
function loadThemeSetting() {
  const s = localStorage.getItem('theme');
  if (s) {
    $('#themeSelector>select').val(s);
  }
  updateTheme();
}
loadThemeSetting();

// Update the theme if the selector is changed
$('#themeSelector>select').change(function () {
  const s = getThemeSetting();
  localStorage.setItem('theme', s);
  updateTheme(s);
});

// Update the theme if the system preference changes
if (window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function() {
    updateTheme();
  });
}


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
    $('#notifications').empty();
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
    // Reset state
    modems = {};
    wifiIfs = {};

    // Reset the UI
    $('#login').addClass('d-none');
    $('#initialPasswordForm').addClass('d-none');
    hideError();
    $('#notifications').empty();
    $('#wifi').empty();
    $('#modemManager').empty();
    $('#main').removeClass('d-none');
    $('#themeSelector').removeClass('d-none');
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

function genNetifEntry(error, enabled, name, ip, throughput, isBold = false) {
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
  if (error) {
    const cb = entry.find('input');
    cb.attr('disabled', true);
    cb.attr('title', `Can't enable: ${error}`);
  }

  return entry;
}

function updateNetif(netifs) {
  let modemList = [];
  let totalKbps = 0;

  for (const i in netifs) {
    data = netifs[i];
    tpKbps = Math.round((data['tp'] * 8) / 1024);
    totalKbps += tpKbps;

    modemList.push(genNetifEntry(data.error, data.enabled, i, data.ip, `${tpKbps} Kbps`));
  }

  if (Object.keys(netifs).length > 1) {
    modemList.push(genNetifEntry(undefined, undefined, '', '', `${totalKbps} Kbps`, true));
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


/* Software updates */
function showSoftwareUpdates(status) {
  if (status) {
    if (status.package_count) {
      $('#softwareUpdate span.desc').text(`(${status.package_count} packages, ${status.download_size})`);
    } else {
      $('#softwareUpdate span.desc').text('(up to date)');
    }
    $('#softwareUpdate').attr('disabled', !status.package_count);
  } else if (status === null) {
    $('#softwareUpdate span.desc').text('(checking for updates...)');
    $('#softwareUpdate').attr('disabled', true);
  }
  if (status === false) {
     $('#softwareUpdate').addClass('d-none');
  } else {
    $('#softwareUpdate').removeClass('d-none');
  }
}

function showSoftwareUpdateValue(cls, value, total) {
  if (value > 0) {
    $(`#softwareUpdateStatus .${cls} .value`).text(`${value} / ${total}`);
    $(`#softwareUpdateStatus .${cls}`).removeClass('d-none');
  } else {
    $(`#softwareUpdateStatus .${cls}`).addClass('d-none');
  }
}

function showSoftwareUpdateStatus(status) {
  if (!status) {
    $('#softwareUpdateStatus').addClass('d-none');
    return;
  }

  $('#startStop, #softwareUpdate, .command-btn').attr('disabled', status.result === undefined);

  showSoftwareUpdateValue('downloading', status.downloading, status.total);
  showSoftwareUpdateValue('unpacking', status.unpacking, status.total);
  showSoftwareUpdateValue('setting-up', status.setting_up, status.total);

  if (status.result === 0) {
    $('#softwareUpdateStatus p.result').text('Update completed. Restarting the encoder...');
    $('#softwareUpdateStatus p.result').removeClass('text-danger');
    $('#softwareUpdateStatus p.result').addClass('text-success');
    $('#softwareUpdateStatus .result').removeClass('d-none');
  } else if (status.result !== undefined) {
    $('#softwareUpdateStatus p.result').text("Update error: " + status.result);
    $('#softwareUpdateStatus p.result').removeClass('text-success');
    $('#softwareUpdateStatus p.result').addClass('text-danger');
    $('#softwareUpdateStatus .result').removeClass('d-none');
  } else {
    $('#softwareUpdateStatus .result').addClass('d-none');
  }

  $('#softwareUpdateStatus').removeClass('d-none');
}

$('#softwareUpdate').click(function() {
  const msg = 'Are you sure you want to start a software update? ' +
              'This may take several minutes. ' +
              'You won\'t be able to start a stream until it\'s completed. ' +
              'The encoder will briefly disconnect after a successful upgrade. ' +
              'Never remove power or reset the encoder while updating. If the encoder is powered from a battery, ensure it\'s fully charged.';

  if (confirm(msg)) {
    send_command('update');
  }
});


/* SSH status / control */
let sshStatus;
function showSshStatus(s) {
  if (s !== undefined) {
    sshStatus = s;
  }

  if (!sshStatus) return;

  const pass = !config.ssh_pass ? 'password not set' : (sshStatus.user_pass ? 'user-set password' : config.ssh_pass)
  $('label[for=sshPassword]').text(`SSH password (username: ${sshStatus.user})`);

  $('#sshPassword').val(pass);
  if (sshStatus.active) {
    $('#startSsh').addClass('d-none');
    $('#stopSsh').removeClass('d-none');
  } else {
    $('#stopSsh').addClass('d-none');
    $('#startSsh').removeClass('d-none');
  }
  $('#sshSettings').removeClass('d-none');
}

$('#resetSshPass').click(function() {
  const msg = 'Are you sure you want to reset the SSH password?';

  if (confirm(msg)) {
    send_command('reset_ssh_pass');
  }
});


/* Audio device / codec selection */
let audioSrcList = [];
function updateAudioSrcs(list) {
  if (list !== null) {
    audioSrcList = list;
  }

  const audioSelect = document.getElementById("audioSource");
  audioSelect.innerText = null;
  let asrcFound = false;

  for (const card of audioSrcList) {
    const option = document.createElement("option");
    option.value = card;
    option.innerText = card;

    audioSelect.append(option);
    if (config.asrc && card == config.asrc) {
      option.selected = true;
      asrcFound = true;
    }
  }

  if (config.asrc && !asrcFound) {
    const option = document.createElement("option");
    option.innerText = config.asrc + " (unavailable)";
    option.value = config.asrc;
    option.selected = true;
    audioSelect.append(option);
  }
}

let audioCodecList = {};
function updateAudioCodecs(list) {
  if (list !== null) {
    audioCodecList = list;
  }

  const audioCodec = document.getElementById("audioCodec");
  audioCodec.innerText = null;

  for (const codec in audioCodecList) {
    const option = document.createElement("option");
    option.value = codec;
    option.innerText = audioCodecList[codec];

    if (config.acodec && codec == config.acodec) {
      option.selected = true;
    }
    audioCodec.append(option);
  }
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

  if (status.available_updates !== undefined) {
    showSoftwareUpdates(status.available_updates);
  }

  if (status.updating !== undefined) {
    showSoftwareUpdateStatus(status.updating);
  }

  if (status.ssh) {
    showSshStatus(status.ssh);
  }

  if (status.wifi) {
    updateWifiState(status.wifi);
  }

  if (status.modems) {
    updateModemsState(status.modems);
  }

  if (status.asrcs) {
    updateAudioSrcs(status.asrcs);
  }
}


/* Configuration loading */
function loadConfig(c) {
  config = c;

  initBitrateSlider(config.max_br ?? 5000);
  initDelaySlider(config.delay ?? 0);
  initSrtLatencySlider(config.srt_latency ?? 2000);
  updatePipelines(null);
  updateAudioSrcs(null);
  updateRelays(null);

  const srtlaAddr = config.srtla_addr ?? "";
  showHideRelayHint(srtlaAddr);
  $('#srtlaAddr').val(srtlaAddr);
  $('#srtlaPort').val(config.srtla_port ?? "");
  $('#srtStreamid').val(config.srt_streamid ?? "");

  $('#remoteDeviceKey').val(config.remote_key);
  $('#remoteKeyForm button[type=submit]').prop('disabled', true);
  $("#bitrateOverlay").prop('checked', config.bitrate_overlay)

  if (config.ssh_pass && sshStatus) {
    showSshStatus();
  }
}


/* Pipelines */
function genOptionList(options, selected) {
  const list = [];
  for (const o of options) {
    for (const value in o) {
      const html = '<option></option>'
      const entry = $($.parseHTML(html));
      entry.attr('value', value);
      entry.text(o[value].name);
      if (selected && value == selected) {
        entry.attr('selected', true);
      }
      if (o[value].disabled) {
        entry.attr('disabled', true);
      }
      list.push(entry);
    }
  }
  return list;
}

let pipelines = {};
function updatePipelines(ps) {
  if (ps != null) {
    pipelines = ps;
  }

  const list = genOptionList([pipelines], config.pipeline);
  $('#pipelines').html(list);

  pipelineSelectHandler($('#pipelines').val())
}

function pipelineSelectHandler(s) {
  const p = pipelines[s];
  if (!p) return;

  if (p.asrc) {
    $('#selectAudioSource').removeClass('d-none');
  } else {
    $('#selectAudioSource').addClass('d-none');
  }

  if (p.acodec) {
    $('#selectAudioCodec').removeClass('d-none');
  } else {
    $('#selectAudioCodec').addClass('d-none');
  }
}

$("#pipelines").change(function(ev) {
  pipelineSelectHandler(ev.target.value);
});

/* Remote relays config */
let isValidRelaySelection = true;
function updateRelaySettings() {
  if ($('#relayServer').val() == 'manual') {
    $('.remote-relay-account').addClass('d-none');
    $('.manual-relay-addr, .manual-streamid').removeClass('d-none');
    isValidRelaySelection = true;
  } else {
    $('.manual-relay-addr').addClass('d-none');
    $('.remote-relay-account').removeClass('d-none');
    if ($('#relayAccount').val() == 'manual') {
      $('.manual-streamid').removeClass('d-none');
    } else {
      $('.manual-streamid').addClass('d-none');
    }
    isValidRelaySelection = ($('#relayAccount').val() !== null);
  }

  if (isValidRelaySelection) {
    removeNotification('relay_account_unavailable');
  } else {
    showNotification({name: 'relay_account_unavailable', type: 'error',
                      msg: 'Your selected relay server account is no longer available. ' +
                           'Please select a different one to start the stream.'});
  }
  updateButtonEnabledDisabled();
}
$('#relayServer, #relayAccount').change(function() {
  updateRelaySettings();
});

let relays;
function updateRelays(r) {
  if (r && r.servers && r.accounts) {
    relays = r;
  }

  const preset = {manual: {name: 'Manual configuration'}};

  let selectedServer = config.relay_server;
  if (!relays || config.srtla_addr || config.srtla_port) {
    selectedServer = 'manual';
  } else if (!config.relay_server || !relays.servers[config.relay_server]) {
    for (const s in relays.servers) {
      if (relays.servers[s].default) {
        selectedServer = s;
      }
    }
  }
  const serverList = genOptionList([relays ? relays.servers : {}, preset], selectedServer);
  $('#relayServer').html(serverList);

  let selectedAccount = config.relay_account;
  if (!relays || config.srt_streamid !== undefined) {
    selectedAccount = 'manual';
  } else if (config.relay_account) {
    if (!relays.accounts[config.relay_account]) {
      preset['unavailable'] = {name: 'No longer available', disabled: true};
      selectedAccount = 'unavailable';
    }
  }
  const accountList = genOptionList([relays ? relays.accounts : {}, preset], selectedAccount);
  $('#relayAccount').html(accountList);

  updateRelaySettings();
}

/* Bitrate setting updates */
function updateBitrate(br) {
  $('#bitrateSlider').slider('option', 'value', br.max_br);
  showBitrate(br.max_br);
}


/* WiFi manager */
function wifiScan(button, deviceId) {
  if (!ws) return;

  // Disable the search button immediately
  const wifiManager = $(button).parents('.wifi-settings');
  wifiManager.find('.wifi-scan-button').attr('disabled', true);

  // Send the request
  ws.send(JSON.stringify({wifi: {scan: deviceId}}));

  // Duration
  const searchDuration = 10000;

  setTimeout(function() {
    wifiManager.find('.wifi-scan-button').attr('disabled', false);
    wifiManager.find('.scanning').addClass('d-none');
  }, searchDuration);

  wifiManager.find('.connect-error').addClass('d-none');
  wifiManager.find('.scanning').removeClass('d-none');
}

function wifiSendNewConnection() {
  $('#wifiNewErrAuth').addClass('d-none');
  $('#wifiNewErrGeneric').addClass('d-none');
  $('#wifiNewConnecting').removeClass('d-none');

  $('#wifiConnectButton').attr('disabled', true);

  const device = $('#connection-device').val();
  const ssid = $('#connection-ssid').val();
  const password = $('#connection-password').val();

  ws.send(JSON.stringify({
    wifi: {
      new: {
        device,
        ssid,
        password
      }
    }
  }));

  return false;
}

function wifiConnect(e) {
  const network = $(e).parents('tr.network').data('network');

  if (network.active) return;

  if (network.uuid) {
    ws.send(JSON.stringify({wifi: {connect: network.uuid}}));

    const wifiManager = $(e).parents('.wifi-settings');
    wifiManager.find('.connect-error').addClass('d-none');
    wifiManager.find('.connecting').removeClass('d-none');
  } else {
    if (network.security === "") {
      if (confirm(`Connect to the open network ${network.ssid}?`)) {
        ws.send(JSON.stringify({
          wifi: {
            new: {
              ssid: network.ssid,
              device: network.device
            }
          }
        }));
      }
    } else {
      if (network.security.match('802.1X')) {
        alert("This network uses 802.1X enterprise authentication, " +
              "which belaUI doesn't support at the moment");
      } else if (network.security.match('WEP')) {
        alert("This network uses legacy WEP authentication, " +
              "which belaUI doesn't support");
      } else {
        $('#connection-ssid').val(network.ssid);
        $('#connection-device').val(network.device);
        $('#connection-password').val('');
        $('.wifi-new-status').addClass('d-none');
        $('#wifiConnectButton').attr('disabled', false);
        $('#wifiModal').modal({ show: true });

        setTimeout(() => {
          $('#connection-password').focus();
        }, 500);
      }
    }
  }
}

function wifiDisconnect(e) {
  const network = $(e).parents('tr').data('network');

  if (confirm(`Disconnect from ${network.ssid}?`)) {
    ws.send(JSON.stringify({
      wifi: {
        disconnect: network.uuid
      },
    }));
  }
}

function wifiForget(e) {
  const network = $(e).parents('tr').data('network');

  if (confirm(`Forget network ${network.ssid}?`)) {
    ws.send(JSON.stringify({
      wifi: {
        forget: network.uuid
      },
    }));
  }
}

function wifiFindCardId(deviceId) {
  return `wifi-manager-${parseInt(deviceId)}`;
}

function wifiSignalSymbol(signal) {
  if (signal < 0) signal = 0;
  if (signal > 100) signal = 100;
  const symbol = 9601 + Math.floor(signal / 12.51);
  let cl = "text-success";
  if (signal < 40) {
    cl = "text-danger";
  } else if (signal < 75) {
    cl = "text-warning";
  }
  return `<span class="${cl}">&#${symbol}</span>`;
}

function wifiListAvailableNetwork(device, deviceId, a) {
  const savedUuid = device.saved[a.ssid];
  if (savedUuid) {
    delete device.saved[a.ssid];
  }

  const html = `
    <tr class="network">
      <td class="signal px-0"></td>
      <td class="band px-0"></td>
      <td class="security px-0"></td>
      <td class="text-break">
        <span class="connected d-none"><u>Connected</u><br/></span>
        <span class="ssid" onClick="wifiConnect(this)"></span>
      </td>
      <td class="text-right px-0">
        <button class="d-none btn btn-warning px-1 py-0 disconnect btn-sm netact"
                onClick="wifiDisconnect(this)" title="Disconnect">
          <span class="font-weight-bold button-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-wifi-off" viewBox="0 0 16 16">
              <path d="M10.706 3.294A12.545 12.545 0 0 0 8 3C5.259 3 2.723 3.882.663 5.379a.485.485 0 0 0-.048.736.518.518 0 0 0 .668.05A11.448 11.448 0 0 1 8 4c.63 0 1.249.05 1.852.148l.854-.854zM8 6c-1.905 0-3.68.56-5.166 1.526a.48.48 0 0 0-.063.745.525.525 0 0 0 .652.065 8.448 8.448 0 0 1 3.51-1.27L8 6zm2.596 1.404.785-.785c.63.24 1.227.545 1.785.907a.482.482 0 0 1 .063.745.525.525 0 0 1-.652.065 8.462 8.462 0 0 0-1.98-.932zM8 10l.933-.933a6.455 6.455 0 0 1 2.013.637c.285.145.326.524.1.75l-.015.015a.532.532 0 0 1-.611.09A5.478 5.478 0 0 0 8 10zm4.905-4.905.747-.747c.59.3 1.153.645 1.685 1.03a.485.485 0 0 1 .047.737.518.518 0 0 1-.668.05 11.493 11.493 0 0 0-1.811-1.07zM9.02 11.78c.238.14.236.464.04.66l-.707.706a.5.5 0 0 1-.707 0l-.707-.707c-.195-.195-.197-.518.04-.66A1.99 1.99 0 0 1 8 11.5c.374 0 .723.102 1.021.28zm4.355-9.905a.53.53 0 0 1 .75.75l-10.75 10.75a.53.53 0 0 1-.75-.75l10.75-10.75z"/>
            </svg>
          </span>
          <span class="button-text">Disconnect</span>
        </button>
        <button class="d-none btn btn-danger px-1 py-0 forget btn-sm netact"
                onClick="wifiForget(this)" title="Forget">
          <span class="font-weight-bold button-icon">&#128465;</span>
          <span class="button-text">Forget</span>
        </button>
      </td>
    </tr>`;

  const network = $($.parseHTML(html));
  network.find('.signal').html(wifiSignalSymbol(a.signal));// + '%');
  network.find('.band').html((a.freq > 5000) ? '5&#13203;' : '2.4&#13203;');
  const ssidEl = network.find('.ssid');
  ssidEl.text(a.ssid);

  network.data('network', {active: a.active, uuid: savedUuid, ssid: a.ssid, device: deviceId, security: a.security});

  if (a.security != '') {
    // show a cross mark for 802.1X or WEP networks (unsupported)
    // or a lock symbol for PSK networks (supported)
    network.find('.security').html(a.security.match(/802\.1X|WEP/) ? '&#10060;' : '&#128274;');
  }
  if (a.active) {
    network.find('.disconnect').removeClass('d-none');
    network.find('.connected').removeClass('d-none');
  }
  if (!a.active) {
    network.find('.ssid').addClass('can-connect');
  }
  if (savedUuid) {
    network.find('.forget').removeClass('d-none');
  }

  return network;
}

function wifiListSavedNetwork(ssid, uuid) {
  const html = `
    <tr class="network">
      <td class="ssid col-11"></td>
      <td class="col-1">
        <button class="btn btn-danger px-1 py-0 forget btn-sm netact"
                onClick="wifiForget(this)" title="Forget">
          <span class="font-weight-bold button-icon">&#128465;</span>
          <span class="button-text">Forget</span>
        </button>
      </td>
    </tr>`;

  const network = $($.parseHTML(html));
  network.find('.ssid').text(ssid);

  network.data('network', {ssid, uuid});

  return network;
}

function wifiCheckHotspotSettings(deviceId) {
  if (!wifiIfs[deviceId] || !wifiIfs[deviceId].hotspot) return;

  const cardId = wifiFindCardId(deviceId);
  const form = $(`#${cardId}`).find('.hotspot');

  let anyValueChanged = false;
  let allValuesValid = true;

  const nameInput = form.find('.hotspot-name').val();
  if (nameInput != wifiIfs[deviceId].hotspot.name) {
    anyValueChanged = true;
    const hint = form.find('.hotspot-name-hint');
    if (nameInput.length < 1 || nameInput.length > 32) {
      hint.removeClass('d-none');
      allValuesValid = false;
    } else {
      hint.addClass('d-none');
    }
  }

  const passwordInput = form.find('.hotspot-password').val();
  if (passwordInput != wifiIfs[deviceId].hotspot.password) {
    anyValueChanged = true;
    const hint = form.find('.hotspot-password-hint');
    if (passwordInput.length < 8 || passwordInput.length > 64) {
      hint.removeClass('d-none');
      allValuesValid = false;
    } else {
      hint.addClass('d-none');
    }
  }

  const channelInput = form.find('.hotspot-channel');
  if (channelInput.val() != wifiIfs[deviceId].hotspot.channel) {
    anyValueChanged = true;
  }

  form.find('.hotspot-config-save').attr('disabled', !anyValueChanged || !allValuesValid)
}

let wifiIfs = {};
function updateWifiState(msg) {
  for (const i in wifiIfs) {
    wifiIfs[i].removed = true;
  }

  for (let deviceId in msg) {
    // Mark the interface as not removed
    if (wifiIfs[deviceId]) {
      delete wifiIfs[deviceId].removed;
    }

    const cardId = wifiFindCardId(deviceId);
    const device = msg[deviceId];
    let deviceCard = $(`#${cardId}`);

    if (deviceCard.length == 0) {
      const html = `
        <div id="${cardId}" class="wifi-settings card mb-2">
          <div class="card-header bg-success text-center" type="button" data-toggle="collapse" data-target="#collapseWifi-${deviceId}">
            <button class="btn btn-link text-white" type="button" data-toggle="collapse" data-target="#collapseWifi-${deviceId}" aria-expanded="false" aria-controls="collapseWifi-${deviceId}">
              Wifi: <strong class="device-name"></strong><span class="device-hw"></span>
            </button>
          </div>

          <div class="collapse" id="collapseWifi-${deviceId}">
            <div class="card-body">
              <div class="hotspot d-none">
                <p class="hotspot-modified hotspot-warning d-none text-danger">The NetworkManager connection for the hotspot has been modified from the BELABOX defaults. Correct functionality can't be guaranteed. If you experience issues, please delete it via command line</p>

                <div class="form-group">
                  <label>Network name</label>
                  <p class="hotspot-name-hint text-danger d-none">The network name must be between 1 and 32 characters long</p>
                  <input type="text" class="form-control hotspot-name recheck-netact">
                </div>

                <div class="form-group">
                  <label>Password</label>
                  <p class="hotspot-password-hint text-danger d-none">The password must be between 8 and 64 characters long</p>
                  <div class="input-group">
                    <input type="password" class="form-control hotspot-password netact">
                    <div class="input-group-append">
                      <button class="btn btn-outline-secondary showHidePassword" type="button">Show</button>
                    </div>
                  </div>
                </div>

                <div class="form-group">
                  <label>Wifi channel</label>
                  <select class="form-control hotspot-channel netact">
                  </select>
                </div>

                <div class="text-danger form-group save-error small d-none"></div>
                <div class="text-info form-group saving small d-none"><div class="spinner-border spinner-border-sm"></div> Saving...</div>
                <div class="text-success form-group saved small d-none">Saved</div>

                <button class="btn btn-block btn-primary mb-2 hotspot-config-save netact" disabled>Save</button>
                <button class="btn btn-block btn-warning mb-2 client-mode netact">Turn hotspot off</button>
              </div> <!-- .hotspot -->

              <div class="client d-none">
                <button type="button" class="btn btn-block btn-secondary btn-netact mb-2 wifi-scan-button" onClick="wifiScan(this, ${deviceId})">
                  Scan for WiFi networks
                </button>

                <div class="connecting small text-info d-none">
                  <div class="spinner-border spinner-border-sm" role="status">
                  </div>
                  Connecting...
                </div>

                <div class="connect-error small text-info d-none">
                  Error connecting to the network. Has the password changed?
                </div>

                <div class="scanning small text-info d-none">
                  <div class="spinner-border spinner-border-sm" role="status">
                  </div>
                  Scanning...
                </div>

                <table class="table mb-2 table-hover table-sm small">
                  <tbody class="networks available-networks"></tbody>
                </table>

                <table class="d-none table mt-4 table-hover table-sm small saved-networks">
                  <thead>
                    <th colspan=2>Other saved networks</th>
                  </thead>
                  <tbody class="networks saved-networks"></tbody>
                </table>

                <button class="btn btn-block btn-warning mb-2 hotspot-mode netact" disabled>Hotspot mode</button>
              </div> <!-- .client -->
            </div>
          </div>
        </div>`;

      deviceCard = $($.parseHTML(html));

      deviceCard.find('button.showHidePassword').click(showHidePassword);

      deviceCard.find('button.hotspot-mode').click(function() {
        if (confirm('This will immediately disconnect the WiFi adapter from any connected networks and turn on the hotspot. Proceed?')) {
          ws.send(JSON.stringify({wifi: {hotspot: {start: {device: deviceId}}}}));
        }
      });

      deviceCard.find('button.client-mode').click(function() {
        if (confirm('This will immediately disconnect any connected clients and disable the hotspot. Proceed?')) {
          ws.send(JSON.stringify({wifi: {hotspot: {stop: {device: deviceId}}}}));
        }
      });

      deviceCard.find('.hotspot-name, .hotspot-password, .hotspot-channel').on('input', function() {wifiCheckHotspotSettings(deviceId)});

      deviceCard.find('button.hotspot-config-save').click(function() {
        let config = {
          device: deviceId,
          name: deviceCard.find('input.hotspot-name').val(),
          password: deviceCard.find('input.hotspot-password').val(),
          channel: deviceCard.find('select.hotspot-channel').val(),
        };
        ws.send(JSON.stringify({wifi: {hotspot: {config}}}));

        $(this).attr('disabled', true);
        deviceCard.find('.save-error, .saved').addClass('d-none');
        deviceCard.find('.saving').removeClass('d-none');
      });

      deviceCard.appendTo('#wifi');
    }

    // Update the card's header
    deviceCard.find('.device-name').text(device.ifname);
    deviceCard.find('.device-hw').text(device.hw ? ` (${device.hw})` : '');

    // Disable or enable the hotspot mode button depending on whether the hardware supports it
    deviceCard.find('button.hotspot-mode').attr('disabled', (!device.supports_hotspot && !device.hotspot));

    if (device.hotspot) {
      if (!wifiIfs[deviceId] || !wifiIfs[deviceId].hotspot || wifiIfs[deviceId].hotspot.name != device.hotspot.name) {
        deviceCard.find('.hotspot-name').val(device.hotspot.name);
      }
      if (!wifiIfs[deviceId] || !wifiIfs[deviceId].hotspot || wifiIfs[deviceId].hotspot.password != device.hotspot.password) {
        deviceCard.find('.hotspot-password').val(device.hotspot.password);
      }
      if (!wifiIfs[deviceId] || !wifiIfs[deviceId].hotspot || wifiIfs[deviceId].hotspot.channel != device.hotspot.channel) {
        const channels = genOptionList([device.hotspot.available_channels], device.hotspot.channel);
        deviceCard.find('select.hotspot-channel').html(channels);
      }

      if (device.hotspot.warnings && device.hotspot.warnings.includes('modified')) {
        deviceCard.find('.hotspot-modified').removeClass('d-none');
      } else {
        deviceCard.find('.hotspot-modified').addClass('d-none');
      }

      deviceCard.find('.client').addClass('d-none');
      deviceCard.find('.hotspot').removeClass('d-none');
    } else {
      // Show the available networks
      let networkList = [];

      for (const a of msg[deviceId].available) {
        if (a.active) {
          networkList.push(wifiListAvailableNetwork(device, deviceId, a));
        }
      }

      for (const a of msg[deviceId].available) {
        if (!a.active) {
          networkList.push(wifiListAvailableNetwork(device, deviceId, a));
        }
      }

      deviceCard.find('.available-networks').html(networkList);

      // Show the saved networks
      networkList = [];
      for (const ssid in msg[deviceId].saved) {
        const uuid = msg[deviceId].saved[ssid];
        networkList.push(wifiListSavedNetwork(ssid, uuid));
      }

      if (networkList.length) {
        deviceCard.find('tbody.saved-networks').html(networkList);
        deviceCard.find('table.saved-networks').removeClass('d-none');
      } else {
        deviceCard.find('table.saved-networks').addClass('d-none');
      }

      deviceCard.find('.hotspot').addClass('d-none');
      deviceCard.find('.client').removeClass('d-none');
    }
  }

  for (const i in wifiIfs) {
    if (wifiIfs[i].removed) {
      const cardId = wifiFindCardId(i);
      $(`#${cardId}`).remove();
    }
  }

  wifiIfs = msg;
}

function handleWifiResult(msg) {
  if (msg.connect !== undefined) {
    const wifiManagerId = `#${wifiFindCardId(msg.device)}`;
    $(wifiManagerId).find('.connecting').addClass('d-none');
    if (msg.connect === false) {
      $(wifiManagerId).find('.connect-error').removeClass('d-none');
    }
  } else if (msg.new) {
    if (msg.new.error) {
      $('#wifiNewConnecting').addClass('d-none');

      switch (msg.new.error) {
        case 'auth':
          $('#wifiNewErrAuth').removeClass('d-none');
          break;
        case 'generic':
          $('#wifiNewErrGeneric').removeClass('d-none');
          break;
      }

      $('#wifiConnectButton').attr('disabled', false);
    }
    if (msg.new.success) {
      $('#wifiModal').modal('hide');
    }
  } else if (msg.hotspot) {
    if (msg.hotspot.config) {
      const wifiManager = $(`#${wifiFindCardId(msg.hotspot.config.device)}`);

      if (msg.hotspot.config.success) {
        wifiManager.find('.save-error, .saving').addClass('d-none');
        wifiManager.find('.saved').removeClass('d-none');

      } else if (msg.hotspot.config.error) {
        let errMsg;

        switch (msg.hotspot.config.error) {
          case 'name':
          case 'password':
          case 'channel':
            errMsg = `invalid ${msg.hotspot.config.error}`;
            break;
          case 'saving':
          case 'activating':
            errMsg = 'couldn\'t apply the new settings';
            break;
        }
        if (errMsg) {
          const errorField = wifiManager.find('.save-error');
          errorField.text('Failed to save the settings: ' + errMsg);
          wifiManager.find('.saved, .saving').addClass('d-none');
          errorField.removeClass('d-none');
        }
      }
    }
  }
}


/* Modem manager */
function modemFindCardId(deviceId) {
  return `modemManager${parseInt(deviceId)}`;
}

let modems = {};
function updateModemsState(msg) {
  for (const i in modems) {
    modems[i].removed = true;
  }

  for (let deviceId in msg) {
    if (modems[deviceId]) {
      delete modems[deviceId].removed;
    }

    const cardId = modemFindCardId(deviceId);
    const device = msg[deviceId];
    const modem = modems[deviceId];

    let deviceCard = $(`#${cardId}`);

    if (deviceCard.length == 0) {
      const html = `
        <div id="${cardId}" class="modem-settings card mb-2">
          <div class="card-header bg-success text-center" type="button" data-toggle="collapse" data-target="#collapse-${cardId}">
            <button class="btn btn-link text-white" type="button" data-toggle="collapse" data-target="#collapse-${cardId}" aria-expanded="false" aria-controls="#collapse-${cardId}">
              Modem: <strong class="device-ifname"></strong><span class="device-name"></span>
            </button>
          </div>

          <div class="collapse" id="collapse-${cardId}">
            <div class="form-group px-3 py-1 mb-2 border-bottom modem-status">
              <span class="signal d-none"></span>
              <span class="status d-none"></span>
              <span class="no-sim text-danger d-none">No SIM card</span>
            </div>
            <div class="card-body pt-0 pb-3 d-none">
              <div class="form-group mb-1">
                <label class="mb-0" for="networkType-${cardId}">Network type</label>
                <select class="network-type-input custom-select" id="networkType-${cardId}"></select>
              </div>
              <div class="form-group mb-1">
                <input type="checkbox" class="roaming-input" id="roaming-${cardId}">
                <label class="mb-0" for="roaming-${cardId}">Allow roaming</label>
              </div>
              <div class="form-group mb-1 network-selection-group">
                <label class="mb-0" for="networkSelection-${cardId}">Network</label>
                <div class="input-group">
                  <select class="network-selection-input custom-select" id="networkSelection-${cardId}"></select>
                  <div class="input-group-append">
                    <button class="btn btn-outline-primary network-scan-button">Scan</button>
                  </div>
                </div>
              </div>
              <div class="form-group mb-1 autoconfig-group d-none">
                <input type="checkbox" class="autoconfig-input" id="autoconfig-${cardId}" disabled>
                <label class="mb-0" for="autoconfig-${cardId}">Automatic APN configuration</label>
              </div>
              <div class="apn-manual-config">
                <div class="form-group mb-1">
                  <label class="mb-0" for="apn-${cardId}">APN</label>
                  <input type="text" class="form-control apn-input" id="apn-${cardId}">
                </div>
                <div class="form-group mb-1">
                  <label class="mb-0" for="username-${cardId}">Username</label>
                  <input type="text" class="form-control username-input" id="username-${cardId}">
                </div>
                <div class="form-group mb-2">
                  <label class="mb-0" for="password-${cardId}">Password</label>
                  <input type="text" class="form-control password-input" id="password-${cardId}">
                </div>
              </div>

              <button class="btn btn-block btn-primary netact save-button" disabled>Save</button>
            </div>
          </div>
        </div>`;

      deviceCard = $($.parseHTML(html));

      // Set the name
      if (device.ifname) {
        deviceCard.find('.device-ifname').text(device.ifname);
        deviceCard.find('.device-name').text(` (${device.name})`);
      } else {
        deviceCard.find('.device-name').text(device.name);
      }

      // Show the status bar, either with the no SIM message or actual signal info
      if (device.no_sim) {
        deviceCard.find('.no-sim').removeClass('d-none');
      } else {
        deviceCard.find('.signal, .status, .card-body').removeClass('d-none');
      }

      // Dynamically show and hide network selection depending on the roaming checkbox
      const showHideNetworkSelection = function() {
        const checkbox = $(this);
        const networkSelection = $(this).parents('.card-body').find('.network-selection-group');
        if (checkbox.prop('checked')) {
          networkSelection.removeClass('d-none');
        } else {
          networkSelection.addClass('d-none');
        }
      };
      deviceCard.find('.roaming-input').on('change', showHideNetworkSelection);

      // Check if the device supports GSM autoconfiguration
      if (device.config && device.config.autoconfig !== undefined) {
        // Dynamically show and hide APN settings depending on the autoconfig checkbox
        const showHideApnConfig = function() {
          const checkbox = $(this);
          const apnConfigForm = $(this).parents('.card-body').find('.apn-manual-config');
          if (checkbox.prop('checked')) {
            apnConfigForm.addClass('d-none');
          } else {
            apnConfigForm.removeClass('d-none');
          }
        };
        const checkbox = deviceCard.find('.autoconfig-input');
        checkbox.on('change', showHideApnConfig);
        checkbox.prop('disabled', false);
        deviceCard.find('.autoconfig-group').removeClass('d-none');
      }

      const scanButton = deviceCard.find('.network-scan-button');
      scanButton.click(function() {
        if (confirm('Scanning for networks will temporarily disable the data connection of this modem. Proceed?')) {
          scanButton.prop('disabled', true);
          scanButton.text('Scanning...');
          ws.send(JSON.stringify({modems: {scan: {device: deviceId}}}));
        }
      });

      const getUserConfig = function(deviceCard) {
        const network_type = deviceCard.find('.network-type-input').val();
        const roaming = deviceCard.find('.roaming-input').prop('checked');
        const network = deviceCard.find('.network-selection-input').val();
        const autoconfig = deviceCard.find('.autoconfig-input').prop('checked');
        const apn = deviceCard.find('.apn-input').val();
        const username = deviceCard.find('.username-input').val();
        const password = deviceCard.find('.password-input').val();

        return {network_type, roaming, network, autoconfig, apn, username, password};
      };

      deviceCard.find('.save-button').click(function() {
        const config = getUserConfig(deviceCard);
        config.device = deviceId;

        ws.send(JSON.stringify({modems: {config}}));

        $(this).prop('disabled', true);
      });

      // Disable or enable the save button depending on whether any values have changed
      const inputs = deviceCard.find('input, select');
      inputs.on('change, input', function() {
        if (!modems[deviceId] || !modems[deviceId].config) return false;

        const userConfig = getUserConfig(deviceCard);
        const savedConfig = Object.assign({network_type: modems[deviceId].network_type.active}, modems[deviceId].config);
        let changed = false;
        for (const i in savedConfig) {
          if (userConfig[i] !== savedConfig[i]) {
            console.log(`${i} changed`);
            changed = true;
            break;
          }
        }
        deviceCard.find('.save-button').prop('disabled', !changed);
      });

      deviceCard.appendTo('#modemManager');
    }

    // The following settings may be updated for an existing modem
    if (device.network_type) {
      const options = {};
      for (const i in device.network_type.supported) {
        const value = device.network_type.supported[i];
        const name = value.replace(/g/g, 'G / ').replace(/ \/ $/, '');
        options[value] = {name};
      }
      deviceCard.find('.network-type-input').html(genOptionList([options], device.network_type.active));
    }

    if (device.config) {
      deviceCard.find('.apn-input').attr('value', device.config.apn);
      deviceCard.find('.username-input').attr('value', device.config.username);
      deviceCard.find('.password-input').attr('value', device.config.password);
      deviceCard.find('.roaming-input').attr('checked', device.config.roaming);

      // Trigger UI updates
      if (device.config.autoconfig !== undefined) {
        deviceCard.find('.autoconfig-input').attr('checked', device.config.autoconfig);
        deviceCard.find('.autoconfig-input').trigger('change');
      }
      deviceCard.find('.roaming-input').trigger('change');
    }

    if (device.status) {
      deviceCard.find('.signal').html(wifiSignalSymbol(device.status.signal));
      const statusText = `${device.status.signal}% ${device.status.network_type || ''} `+
                         `${device.status.network || ''}${device.status.roaming ? ' (R)': ''} - ${device.status.connection}`
      deviceCard.find('.status').text(statusText);
    }

    const networkSelect = deviceCard.find('.network-selection-input');
    if (device.available_networks || device.config || networkSelect.find('option').length == 0) {
        const selectedNetwork = (device.config ? device.config.network : ((modem && modem.config) ? modem.config.network : undefined));
        const availableNetworks = device.available_networks || (modem ? modem.available_networks : {});
        const auto = {'': {name: 'Automatic' + ((selectedNetwork == '') ? ' (selected)' : '')}};
        const options = {};
        for (const i in availableNetworks) {
          let name = availableNetworks[i].name;
          let availability = '';
          if (i == selectedNetwork) {
            availability = 'selected';
          }
          if (availableNetworks[i].availability) {
            if (availability) {
              availability += ' & ';
            }
            availability += availableNetworks[i].availability;
          }
          if (availability) {
            name += ` (${availability})`
          }
          options[i] = {
            name,
            disabled: (availableNetworks[i].availability == 'forbidden')
          };
        }
        networkSelect.html(genOptionList([auto, options], selectedNetwork));

        // Re-enable the scan button after receiving the results
        if (device.available_networks) {
          const scanButton = deviceCard.find('.network-scan-button');
          scanButton.prop('disabled', false);
          scanButton.text('Scan');
        }
    }

    // Update the cached modem state
    modems[deviceId] = Object.assign(modem || {}, device);

    // Disable or enable the save button if any settings have been updated
    if (device.network_type || device.config) {
      deviceCard.find('.network-type-input').trigger('input');
    }
  }

  for (const i in modems) {
    if (modems[i].removed) {
      const cardId = modemFindCardId(i);
      $(`#${cardId}`).remove();
      delete modems[i];
    }
  }
}


/* Error messages */
function showError(message) {
  $("#errorMsg>span").text(message);
  $("#errorMsg").removeClass('d-none');
}

function hideError() {
  $("#errorMsg").addClass('d-none');
}


/* Notifications */
function notificationId(name) {
  return `notification-${name}`;
}

function showNotification(n) {
  if (!n.name || !n.type || !n.msg) return;
  const alertId = notificationId(n.name);

  let alert = $(`#${alertId}`);
  if (alert.length == 0) {
    const html = `
      <div class="alert mb-2">
        <span class="msg"></span>
        <button type="button" class="close d-none" data-dismiss="alert" aria-label="Close">
          <span aria-hidden="true">&times;</span>
        </button>
      </div>`;
    alert = $($.parseHTML(html));

    alert.attr('id', alertId);
    if (n.is_dismissable) {
      alert.addClass('alert-dismissible');
      alert.find('button').removeClass('d-none');
    }

    alert.appendTo('#notifications');
  } else {
    alert.removeClass(['alert-secondary', 'alert-danger', 'alert-warning', 'alert-success']);
    const t = alert.data('timerHide');
    if (t) {
      clearTimeout(t);
    }
  }

  let colorClass = 'alert-secondary'
  switch(n.type) {
    case 'error':
      alert.addClass(`alert-danger`);
      break;
    case 'warning':
    case 'success':
      alert.addClass(`alert-${n.type}`);
      break;
  }
  alert.addClass(colorClass);

  alert.find('span.msg').text(n.msg);

  if (n.duration) {
    alert.data('timerHide', setTimeout(function() {
      alert.slideUp(300, function() {
        $(this).remove();
      });
    }, n.duration * 1000));
  }

  $('html, body').animate({
    scrollTop: 0,
    scrollLeft: 0
  }, 200);
}

function removeNotification(name) {
  const alertId = notificationId(name);
  $(`#${alertId}`).remove();
}

function handleNotification(msg) {
  if (msg.show) {
    for (const n of msg.show) {
      showNotification(n);
    }
  }
  if (msg.remove) {
    for (const n of msg.remove) {
      removeNotification(n);
    }
  }
}


/* Log download */
function downloadLog(msg) {
  const blob = new Blob([msg.contents], {type: 'text/plain'})

  const a = window.document.createElement('a');
  a.href = window.URL.createObjectURL(blob);
  a.download = msg.name;
  a.click();

  window.URL.revokeObjectURL(blob);
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
      case 'relays':
        updateRelays(msg[type]);
        break;
      case 'bitrate':
        updateBitrate(msg[type]);
        break;
      case 'wifi':
        handleWifiResult(msg[type]);
        break;
      case 'error':
        showError(msg[type].msg);
        break;
      case 'notification':
        handleNotification(msg[type]);
        break;
      case 'log':
        downloadLog(msg[type]);
        break;
      case 'acodecs':
        updateAudioCodecs(msg[type]);
        break;
    }
  }
}


/* Start / stop */
function getConfig() {
  const maxBr = $("#bitrateSlider").slider("value");

  let config = {};
  config.pipeline = document.getElementById("pipelines").value;
  if (pipelines[config.pipeline].asrc) {
    config.asrc = document.getElementById("audioSource").value;
  }
  if (pipelines[config.pipeline].acodec) {
    config.acodec = document.getElementById("audioCodec").value;
  }
  config.delay = $("#delaySlider").slider("value");
  config.max_br = maxBr;
  config.srt_latency = $("#srtLatencySlider").slider("value");
  config.bitrate_overlay = $("#bitrateOverlay").prop('checked');

  const relayServer = $('#relayServer').val();
  if (relayServer !== 'manual') {
    config.relay_server = relayServer;
  } else {
    config.srtla_addr = $("#srtlaAddr").val();
    config.srtla_port = $("#srtlaPort").val();
  }

  const relayAccount = $('#relayAccount').val();
  if (relayServer !== 'manual' && relayAccount !== 'manual') {
    config.relay_account = relayAccount;
  } else {
    config.srt_streamid = $("#srtStreamid").val();
  }

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
let startStopButtonIsEnabled;
function updateButtonEnabledDisabled(isEnabled) {
  if (isEnabled !== undefined) {
    startStopButtonIsEnabled = isEnabled;
  }
  const button = $("#startStop");
  button.attr('disabled', !startStopButtonIsEnabled || !isValidRelaySelection);
}

function updateButton({ add, remove, text, enabled }) {
  const button = document.getElementById("startStop");

  button.classList.add(add);
  button.classList.remove(remove);

  button.innerHTML = text;
  updateButtonEnabledDisabled(enabled);
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

  if (value < 1500) {
    $('#latencyWarning').removeClass('d-none');
  } else {
    $('#latencyWarning').addClass('d-none');
  }
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
    updateButton({text: "Starting...", enabled: false});
    start();
  } else {
    updateButton({text: "Stopping...", enabled: false});
    stop();
  }
});

function updateNetact(isActive) {
  if (isActive) {
    $('.netact, .recheck-netact').attr('disabled', false);
    $('.recheck-netact').trigger('input');
    showSoftwareUpdates(false);
  } else {
    $('.netact, .recheck-netact').attr('disabled', true);
    updateButtonEnabledDisabled(false);
  }
}


function showLoginForm() {
  $('#main').addClass('d-none');
  $('#initialPasswordForm').addClass('d-none');
  $('#login').removeClass('d-none');
  $('#themeSelector').removeClass('d-none');
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
  $('#themeSelector').removeClass('d-none');
  isShowingInitialPasswordForm = true;
}

function checkPassword() {
  const form = $(this).parents('form');

  const p = $(this).val();
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
  const passwordInput = $(form).find('input.set-password');
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
  const confirmationMsg = $(this).attr('data-confirmation');
  if (!confirmationMsg || confirm(confirmationMsg)) {
    // convert to snake case
    const cmd = this.id.split(/(?=[A-Z])/).join('_').toLowerCase();
    send_command(cmd);
  }
});

function showHidePassword() {
  const inputField = $(this).parents('.input-group').find('input');
  if(inputField.attr('type') == 'password') {
    inputField.attr('type', 'text');
    $(this).text('Hide');
  } else {
    inputField.attr('type', 'password');
    $(this).text('Show');
  }
}
$('button.showHidePassword').click(showHidePassword);

function showHideRelayHint(addr) {
  const isCloudRelay = addr.match(/belabox.net$/);
  if (isCloudRelay) {
    $('#cloudRelay').addClass('d-none');
  } else {
    $('#cloudRelay').removeClass('d-none');
  }
}

$('input#srtlaAddr').change(function() {
  showHideRelayHint($(this).val());
});

/* Input fields automatically copied to clipboard when clicked */
function copyInputValToClipboard(obj) {
  if (!document.queryCommandSupported || !document.queryCommandSupported("copy")) {
    return false;
  }

  let input = $(obj);
  let valField = input;

  valField = $('<input>');
  valField.css('position', 'fixed');
  valField.css('top', '100000px');
  valField.val(input.val());
  $('body').append(valField);

  let success = false;
  try {
    valField.select();
    document.execCommand("copy");
    success = true;
  } catch (err) {
    console.log("Copying failed: " + err.message);
  }

  valField.remove();

  return success;
}

$('input.click-copy').tooltip({title: 'Copied', trigger: 'manual'});
$('input.click-copy').click(function(ev) {
  const target = ev.target;
  let input = $(ev.target);

  if (copyInputValToClipboard(target)) {
    input.tooltip('show');
    if (target.copiedTooltipTimer) {
      clearTimeout(target.copiedTooltipTimer);
    }
    target.copiedTooltipTimer = setTimeout(function() {
      input.tooltip('hide');
      delete target.copiedTooltipTimer;
    }, 3000);
  }
});
