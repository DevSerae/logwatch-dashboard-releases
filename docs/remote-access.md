# Reaching remote servers

The board needs plain IP reachability, in two directions:

- **board → server**: SSH (TCP 22, or the port in the host list) for the pull, traffic, images, WAF and CrowdSec roles;
  HTTPS for APIs (Proxmox, UniFi, Wazuh, …).
- **server → board**: syslog (514 TCP/UDP), Fluent Bit forward (24224 TCP), NetFlow (2055 UDP), whichever you enable.

The containers use the board VM's routes, so whatever gives the VM a route (a kernel network interface) covers them too.
Userspace-only VPN modes (`tailscaled --tun=userspace-networking`, NetBird without `NET_ADMIN`) don't: the containers
can't see them. The installer's **Access** tab sets this up and **Test reachability** shows, for every server you
entered, which interface it's reached through and whether its SSH port answers.

Use any mix of these:

| Way | On the board VM | On the servers | Addresses in the host lists |
|---|---|---|---|
| Direct (LAN, routed VLANs, site-to-site VPN on the router) | nothing | firewall allows the ports above | LAN IPs |
| Tailscale | `curl -fsSL https://tailscale.com/install.sh \| sh` then `tailscale up --auth-key <key> --hostname logwatch` | in the tailnet, or behind a subnet router (`--accept-routes` on the VM) | 100.x or MagicDNS names |
| NetBird | `curl -fsSL https://pkgs.netbird.io/install.sh \| sh` then `netbird up --setup-key <key> [--management-url …]` | peers, or behind a routing peer (Network Routes) | NetBird IPs or DNS names |
| Cloudflare One | WARP client, enrolled headless with a service token (`/var/lib/cloudflare-warp/mdm.xml`) | Cloudflare Tunnel / WARP Connector with private network routes | private IPs |
| Other (WireGuard, ZeroTier, OpenVPN, …) | bring it up on the VM | as that VPN needs | as routed |

Policies:

- **Tailscale**: an ACL / grant allowing the board's node → servers on TCP 22, and servers → board on the syslog port.
- **NetBird**: an access policy between the board's group and the servers' group, same ports.
- **Cloudflare One**: Split Tunnels must include (Include mode) or not exclude the servers' private ranges, and a
  device enrollment rule must allow the service token. `cloudflared access ssh` as an SSH ProxyCommand is not
  supported: the board's SSH runs inside a container.

Auth and setup keys typed into the installer are used once to join and never stored.
