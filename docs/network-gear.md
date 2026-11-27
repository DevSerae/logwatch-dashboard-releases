# Network gear: switches, firewalls, APs, NAS, printers

Anything that can send syslog works with the `syslog` module. Point the device at the board host on `syslog.port`
(514 by default, UDP or TCP). Logs show up on the **Logs** tab under the device's hostname. The device also counts for
"stopped sending logs" once it has sent something.

Set a proper hostname on the device. Some devices send their IP or nothing; their logs then appear under that value.

## Examples

**Cisco IOS / IOS-XE**
```
logging host 192.0.2.10 transport udp port 514
logging trap informational
logging origin-id hostname
service timestamps log datetime msec localtime show-timezone
```

**Cisco NX-OS**: `logging server 192.0.2.10 6 use-vrf management`

**MikroTik RouterOS**
```
/system logging action add name=logwatch target=remote remote=192.0.2.10 remote-port=514 bsd-syslog=yes
/system logging add topics=info action=logwatch
/system logging add topics=warning action=logwatch
/system logging add topics=error action=logwatch
```

**pfSense / OPNsense**: Status → System Logs → Settings → Remote Logging. Enter the board address and port 514, and pick
the facilities you want.

**UniFi**: the `unifi` module reads the API, so nothing is needed. If you also want raw device syslog, use Settings →
CyberSecure / System → Activity Logging (SIEM server).

**Synology DSM**: Log Center → Log Sending → server = the board, port 514, UDP, format BSD (RFC 3164).

**TrueNAS**: System → Advanced → Syslog → server `192.0.2.10:514`.

**ESXi**: `esxcli system syslog config set --loghost=udp://192.0.2.10:514 && esxcli system syslog reload`, and open the
syslog firewall rule.

## Alerts from device logs: `log_rules`

The built-in collectors understand Linux auth and service failures. For everything else, add rules to `config.yaml`:

```yaml
log_rules:
  - name: Switch port flapping
    query: 'hostname:core-switch ("changed state to down" OR "LINK-3-UPDOWN")'
    threshold: 3                 # matches per 5-minute window, per host
    severity: warning
    source: network
  - name: Firewall admin login
    query: 'hostname:fw-1 "admin" ("logged in" OR "login successful")'
    threshold: 1
    severity: info
    source: network
  - name: NAS disk warning
    query: 'hostname:nas-1 ("SMART" OR "degraded" OR "bad sector")'
    threshold: 1
    severity: error
    source: storage
```

Queries are [LogsQL](https://docs.victoriametrics.com/victorialogs/logsql/). Try them on the **Logs** tab first. Each
rule raises one item per host. The item stays on the board until you resolve it, and new matches update it.

## NetFlow / IPFIX (`netflow` module)

Export flows to the board host on UDP `netflow.port` (2055). Flows appear on the Edge tab.

- **MikroTik**: `/ip traffic-flow set enabled=yes` and
  `/ip traffic-flow target add dst-address=192.0.2.10 port=2055 version=ipfix`
- **pfSense/OPNsense**: Reporting → NetFlow (OPNsense), or the softflowd package (pfSense). Destination = the board:2055.
- **Cisco**: Flexible NetFlow exporter with destination 192.0.2.10 and transport udp 2055.

Flows are high-volume. Export from the WAN interface only, and keep an eye on `VL_MAX_DISK`.
