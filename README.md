# lan-discovery

## Installation

```bash
$ npm install lan-discovery --save
$ node test.js
```

## Usage

### Example

```javascript
const LanDiscovery = require('lan-discovery');
let discovery = new LanDiscovery({ verbose: false, timeout: 60 });
discovery.on(LanDiscovery.EVENT_DEVICE_INFOS, (device) => {
	console.log('--> event '+ LanDiscovery.EVENT_DEVICE_INFOS +' :\n', device);
});

let myInterface = await discovery.getDefaultInterface();
let tabIP = LanDiscovery.cidrRange(myInterface.cidr);
discovery.startScan({ ipArrayToScan: tabIP });
```

---

### `EVENTS`
EVENT_SCAN_RESPONSE : one device just responded to ping
EVENT_DEVICE_INFOS : we juste retrieve one device informations
EVENT_SCAN_COMPLETE : ping scan complete
EVENT_DEVICES_INFOS : we retrieve all devices informations

---

### `async arpTable(): Promise<Array>`

Retrieves the network's arp table

---

### `async deviceInfos(): Promise<Object>`

Get all informations about a device identified by his IP address

---

### `async deviceIP(mac: string): Promise<string | null>`

Get the IP address for given MAC address
Warning : can return null if the lan has not been scanned recently

---

### `async deviceMAC(ip: string): Promise<string | null>`

Get the MAC address for given IP address
Warning : can return null if you haven't previously send a ping request

---

### `async deviceName(ip: string): Promise<string | null>`

Get hostname from ip address

---

### `async getDefaultInterface(): Promise<Object>`

Return active network informations

---

### `isIP(ip: string): boolean`

Checks if an IP address is valid

---

### `isMAC(mac: string): boolean`

Checks if a MAC address is valid

---

### `async osPingCommand(ip: string): Promise<bool | null>`

Ping an ip address with os ping command (slower but usefull to update the os arp table)

---

### `startScan(): This`

Start the lan scan (Node ICMP Requests) and return the class object

---

## Credits

This librarie is heavyly inspired from theses modules :
- device-discovery (Mark Tiedemann)
- arpping (haf-decent)
- @network-utils/arp-lookup (Justin Taddei)
- @network-utils/tcp-ping   (Justin Taddei)
- default-gateway (Sindre Sorhus)

... but re-writed to fit my needs :
- get ip/mac/name with one cross platform librarie (at least linux and windows)
- no more nmap dependencies
- use of nodejs ping implementation (net-ping) to keep performance
- use of ES8 keyword async/await
- use class and class inheritance
- use of event pattern

## License

MIT
