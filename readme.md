This implementation of belaUI is deprecated, unmaintained, unsupported and potentially insecure. Use the nodejs-based implementation in the [ws_nodejs](https://github.com/BELABOX/belaUI/tree/ws_nodejs) branch. Migration guide [available here](https://github.com/BELABOX/tutorial/wiki/Migrating-from-the-deprecated-belaUI-implementation-to-the-newer-nodejs-based-implementation). Major improvements are available:

* authentication
* temperature and on the 4GB Jetson voltage and current measurements
* more accurate and reliable bitrate calculations on the server-side
* more efficient network connections using websockets instead of HTTP polling
* significantly reduced CPU load which should help with performance on CPU-heavy pipelines
* network hotplugging: new modems plugged in while streaming are automatically added to srtla's bonding group without having to stop the stream
* use of each network interface can be enabled or disabled, both offline and while streaming. E.g. useful if you don't want to stream through your phone's hotspot but want to use it for management, or if one network is being glitchy in a particular area

