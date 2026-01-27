# lan-discovery

## Installation

```bash
$ npm install lan-discovery --save
$ node test.js
```

## Usage

### Example - Hybrid Scan (ARP Broadcast + Ping) - Recommended

**Low-impact method**: ARP broadcast first to discover active devices, then ping only on discovered IPs.

```javascript
const LanDiscovery = require('lan-discovery');
let discovery = new LanDiscovery({ verbose: false, timeout: 60 });

// Listen to ARP discovery events
discovery.on(LanDiscovery.EVENT_ARP_RESPONSE, (device) => {
	console.log('ARP discovered:', device.ip, device.mac);
});

// Listen to ping and device info events
discovery.on(LanDiscovery.EVENT_DEVICE_INFOS, (device) => {
	console.log('Device info:', device); // { ip, mac, name, alive: true }
});

discovery.on(LanDiscovery.EVENT_DEVICES_INFOS, (devices) => {
	console.log('All devices:', devices.length, 'found');
});

let myInterface = await discovery.getDefaultInterface();
await discovery.startHybridScan({ 
	networkInterface: myInterface,
	timeout: 3000,
	interval: 100
});
```

**Note**: 
  - **Linux/macOS/Windows**: If no administrator rights, throws an error.
  - **Linux/macOS**: For ARP broadcast, use scan-arp command (sudo apt install arp-scan)
  - **Windows**:  For ARP broadcast, use third_party/scan-arp.exe (packed in the application)

### Example - Standard Scan (ICMP on all IPs), more impact on network but no administrator rights required

```javascript
const LanDiscovery = require('lan-discovery');
let discovery = new LanDiscovery({ verbose: false, timeout: 60 });
discovery.on(LanDiscovery.EVENT_DEVICE_INFOS, (device) => {
	console.log('--> event '+ LanDiscovery.EVENT_DEVICE_INFOS +' :\n', device);
});

let myInterface = await discovery.getDefaultInterface();
let tabIP = LanDiscovery.cidrRange(myInterface.cidr);
discovery.startScan({ ipArrayToScan: tabIP, interval: 100 });
```

---

### `EVENTS`
EVENT_SCAN_RESPONSE : one device just responded to ping
EVENT_DEVICE_INFOS : we juste retrieve one device informations
EVENT_SCAN_COMPLETE : ping scan complete
EVENT_DEVICES_INFOS : we retrieve all devices informations
EVENT_ARP_RESPONSE : one device discovered via ARP broadcast (device = {ip, mac})
EVENT_ARP_COMPLETE : ARP broadcast scan complete

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


### `async startScan(objParam): Promise<This>`

Start the lan scan (Node ICMP Requests) and return promise resolving the network scan.

**Requirements:**
- **All platforms (priority)**: `raw-socket` package for efficient ping session via net-ping
  - The `raw-socket` package is included in dependencies and will be installed automatically

### `async startHybridScan(objParam): Promise<This>`

Start hybrid scan: Instead of scanning all IPs, ARP broadcast first (L2 low impact), then ping (L3) only on discovered IPs.
Return promise resolving the network scan.

**Requirements:**
- **All platforms (priority)**: `raw-socket` package for efficient ping session via net-ping
  - The `raw-socket` package is included in dependencies and will be installed automatically
- **Windows**: administrator rights
- **Linux/macOS**: administrator rights, `arp-scan` command (`sudo apt install arp-scan`)

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

On linux/macOS, we use arp-scan command available at https://github.com/royhills (Roy Hills)
On windows, we use arp-scan.exe available at https://github.com/QbsuranAlang (Qbsuran Alang)

## License

MIT
