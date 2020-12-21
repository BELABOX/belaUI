/*
    belaUI - web UI for the BELABOX project
    Copyright (C) 2020 BELABOX project

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

let prev_modems;
let update_timer;
let isStreaming = false;

function enableUpdates() {
  update_timer = setInterval(updateStatus, 1000);
}

function updateStatus() {
  updateStartStopButton();
  updateModems();
}

async function updateStartStopButton() {
  const response = await fetch("/status");
  isStreaming = await response.json();

  if (!response.ok) return;

  if (!isStreaming) {
    updateButtonAndSettingsShow({
      add: "btn-success",
      remove: "btn-danger",
      settingsShow: true,
      text: "Start",
    });
  } else {
    updateButtonAndSettingsShow({
      add: "btn-danger",
      remove: "btn-success",
      settingsShow: false,
      text: "Stop",
    });
  }
}

function updateButtonAndSettingsShow({ add, remove, settingsShow, text }) {
  const button = document.getElementById("startStop");
  const settingsDivs = document.getElementById("settings");

  button.classList.add(add);
  button.classList.remove(remove);

  if (settingsShow) {
    settingsDivs.classList.remove("d-none");
  } else {
    settingsDivs.classList.add("d-none");
  }

  button.innerHTML = text;
}

async function updateModems() {
  const response = await fetch("/modems");
  const modems = await response.json();

  if (!response.ok) return;

  const modemsList = document.getElementById("modems");
  let html = "";

  modems.forEach((modem, i) => {
    let txb = 0;

    if (prev_modems && i in prev_modems && "txb" in prev_modems[i]) {
      txb = modem.txb - prev_modems[i].txb;
      txb = Math.round((txb * 8) / 1024);
    }

    html += `<tr>
        <td>${modem.i}</td>
        <td>${modem.ip}</td>
        <td>${txb} Kbps</td>
      </tr>`;
  });

  modemsList.innerHTML = html;
  prev_modems = modems;
}

async function getPipelines() {
  const response = await fetch("/pipelines");
  const pipelines = await response.json();

  if (!response.ok) return;

  const pipelinesSelect = document.getElementById("pipelines");

  pipelines.forEach(({ id, selected, name }) => {
    const option = document.createElement("option");
    option.value = id;
    option.selected = selected;
    option.innerText = name;

    pipelinesSelect.append(option);
  });
}

async function getConfig() {
  const response = await fetch("/config");
  const config = await response.json();

  if (!response.ok) return;

  init_bitrate_slider([config.min_br ?? 500, config.max_br ?? 5000]);
  init_delay_slider(config.delay ?? 0);

  document.getElementById("srtlaAddr").value = config["srtla_addr"] ?? "";
  document.getElementById("srtlaPort").value = config["srtla_port"] ?? "";
}

function show_delay(value) {
  document.getElementById("delay-value").value = `Audio delay: ${value} ms`;
}

function init_delay_slider(default_delay) {
  $("#delay-slider").slider({
    min: -2000,
    max: 2000,
    step: 20,
    value: default_delay,
    slide: (event, ui) => {
      show_delay(ui.value);
    },
  });
  show_delay(default_delay);
}

function showBitrate(values) {
  document.getElementById(
    "bitrate-values"
  ).value = `Bitrate: ${values[0]} - ${values[1]} Kbps`;
}

function setBitrate([min_br, max_br]) {
  let formBody = new URLSearchParams();
  formBody.set("min_br", min_br);
  formBody.set("max_br", max_br);

  fetch("/bitrate", {
    method: "POST",
    body: formBody,
  });
}

function init_bitrate_slider(bitrate_defaults) {
  $("#bitrate-slider").slider({
    range: true,
    min: 500,
    max: 12000,
    step: 100,
    values: bitrate_defaults,
    slide: (event, ui) => {
      showBitrate(ui.values);
      setBitrate(ui.values);
    },
  });
  showBitrate(bitrate_defaults);
}

document.getElementById("startStop").addEventListener("click", () => {
  clearInterval(update_timer);

  if (!isStreaming) {
    start();
  } else {
    stop();
  }
});

async function start() {
  const [min_br, max_br] = $("#bitrate-slider").slider("values");

  let formBody = new URLSearchParams();
  formBody.set("pipeline", document.getElementById("pipelines").value);
  formBody.set("delay", $("#delay-slider").slider("value"));
  formBody.set("min_br", min_br);
  formBody.set("max_br", max_br);
  formBody.set("srtla_addr", document.getElementById("srtlaAddr").value);
  formBody.set("srtla_port", document.getElementById("srtlaPort").value);

  const response = await fetch("/start", {
    method: "POST",
    body: formBody,
  });

  if (response.ok) {
    enableUpdates();
  }
}

async function stop() {
  const response = await fetch("/stop", { method: "POST" });
  if (response.ok) {
    enable_updates();
  }
}

getPipelines();
getConfig();
updateStatus();
enableUpdates();
