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

var prev_modems;
var update_timer;
function enable_updates() {
  update_timer = setInterval(function() {
    update_status();
  }, 1000);
}

function show_bitrate(values) {
  $("#bitrate-values").val("Bitrate: " + values[0] + " - " + values[1] + " Kbps");
}
function set_bitrate(values) {
  $.post('/bitrate', {min_br: values[0], max_br: values[1]});
}
function show_delay(value) {
  $("#delay-value").val("Audio delay: " + value + " ms");
}

function update_status() {
  $.getJSON('/status', null, function(data) {
    if(data) {
      $('.start').hide();
      $('#stop_btn').css('background-color', '#cc3712');
      $('#stop_btn').show();
    } else {
      $('#stop_btn').hide();
      $('a#start_btn').css('background-color', '#12cc4a');
      $('.start').show();
    }
  });

  $.getJSON('/modems', null, function(data) {
    text = "";
    data.forEach(function(modem, i) {
      txb = 0;
      if (prev_modems && i in prev_modems && 'txb' in prev_modems[i]) {
        txb = modem['txb'] - prev_modems[i]['txb'];
        txb = Math.round(txb*8/1024);
      }
      text += "<li>" + modem['i'] + " - " + modem['ip'] + " - " + txb +" Kbps/s</li>"
    });
    $('#modems').html($.parseHTML(text));
    prev_modems = data;
  });
}

function init_ui() {
  $('.collapsible_settings div.inner').hide();
  $('.collapsible_settings span.arrow').each(function() {
    $(this).html("&#x25BC;")
  });
  $('.collapsible_settings a.name').click(function(event) {
    var parent = $(this).parent();
    var is_visible = parent.find("div.inner").is(":visible");
    parent.find("div.inner").slideToggle();
    parent.find("span.arrow").html(is_visible ? "&#x25BC;" : "&#x25B2;");
    return false;
  });

  $('#start_btn').click(function() {
    clearInterval(update_timer);
    $(this).css('background-color', 'white');
    var pipeline = $("#pipeline").val();
    var delay = $("#delay-slider").slider("value");
    var br = $("#bitrate-slider").slider("values");
    var srtla_addr = $("#srtla_addr").val();
    var srtla_port = $("#srtla_port").val();
    $.post('/start', {pipeline: pipeline, delay: delay, min_br: br[0], max_br: br[1], srtla_addr: srtla_addr, srtla_port: srtla_port}, function() {
      enable_updates();
    });
  });
  $('#stop_btn').click(function() {
    clearInterval(update_timer);
    $(this).css('background-color', 'white');
    $.post('/stop', null, function() {
      enable_updates();
    });
  });
}

function init_delay_slider(default_delay) {
  $("#delay-slider").slider({
    min: -2000,
		max: 2000,
		step: 20,
		value: default_delay,
		slide: function(event, ui) {
			show_delay(ui.value);
		}
	});
	show_delay(default_delay);
}

function init_bitrate_slider(bitrate_defaults) {
  $("#bitrate-slider").slider({
	  range: true,
		min: 500,
		max: 12000,
		step: 100,
		values: bitrate_defaults,
		slide: function(event, ui) {
		  show_bitrate(ui.values);
			set_bitrate(ui.values);
		}
	});
	show_bitrate(bitrate_defaults);
}

function init_srtla_settings(srtla_addr, srtla_port) {
  $('#srtla_addr').val(srtla_addr);
  $('#srtla_port').val(srtla_port);
}

$(function() {
  init_ui();

  // Fetch the pipeline list
  $.getJSON('/pipelines', null, function(data) {
    text = "";
    data.forEach(function(pipeline, id) {
      selected = "";
      if (pipeline['selected']) {
        selected = " selected=\"selected\"";
      }
      text += "<option value=\"" + pipeline['id'] + "\"" + selected + ">"
      + pipeline['name'] + "</option>";
    });
    $('#pipeline').html($.parseHTML(text));
  });

  // Fetch the current config
  $.getJSON('/config', null, function(data) {
    var bitrate_defaults = [data['min_br'] || 500, data['max_br'] || 5000];
    init_bitrate_slider(bitrate_defaults);

    var default_delay = data['delay'] || 0;
    init_delay_slider(default_delay);

    var srtla_addr = data['srtla_addr'] || '';
    var srtla_port = data['srtla_port'] || '';
    init_srtla_settings(srtla_addr, srtla_port);
  });

  update_status();
  enable_updates();
});
