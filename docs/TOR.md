# Optional Tor client

Tor is an opt-in client container for Subfinder/Assetfinder provider requests
and website checks + Gowitness. No provider account or manually entered proxy
URL is needed. The scanner uses `socks5h://tor:9050` on a dedicated Compose
bridge. The Tor SOCKS port is not published on the host; its cookie-authenticated
control socket is only inside its own data volume. This configuration is a
client, not a relay or exit server.

## Start from standalone

Wait for an active scan to finish before recreating the monitor. These commands
preserve the existing application data volume and the port/resolver settings
used in this project. Run them yourself; the application never launches Docker.

```bash
cd "$HOME/Downloads/chatgpt projects/typo squat/repository/standalone"

TYPO_STANDALONE_PORT=5057 \
TYPO_MAX_CANDIDATES=1000000 \
TYPO_DNS_RESOLVERS="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4" \
TYPO_DNS_RESOLVER_MODE=balanced \
TYPO_WEB_TIMEOUT=15 \
docker compose --profile tor up --build -d --force-recreate monitor tor

docker compose --profile tor ps
docker compose --profile tor logs -f tor
```

Tor bootstrap can take a few minutes. Wait for `tor` to show **healthy** before
starting a scan. Its healthcheck checks bootstrap progress and an established
circuit over a local Unix socket; it does not fetch a test website. The monitor
can start independently while Tor bootstraps. `Ctrl+C` exits log following.
`TYPO_WEB_TIMEOUT=15` allows longer website checks than the usual 3 seconds;
adjust it for your connection. It does not change DNS or browser worker counts.

In the UI, open **Proxy routes**, choose **Use Tor · preset address** for
discovery and/or website capture, turn that stage's switch on, and save.
Custom proxy fields are hidden while Tor is selected, and any previously saved
custom URL stays available when switching back. DNS has no Tor option.
Choosing the preset does not start its container or contact the network.

The same profile is available from `monitor/`, using `build: ./tor` and the
existing monitor port/data configuration. The standalone build uses the same
Tor Dockerfile from `monitor/tor/`.

## Scope and lifecycle

- The `tor` profile is off by default. Ordinary `docker compose up` does not
  create a new Tor service unless its profile or service is explicitly selected.
- The Tor container has `restart: "no"`. It will not restart automatically when
  Docker starts. After stopping it or restarting Docker, start it explicitly:
  `docker compose --profile tor up -d tor`.
- The Tor state volume retains guard/state information across recreation.
  There is no need to delete the scanner's data volume to use Tor.
- Tor runs as UID/GID 10002 with a read-only root filesystem, no extra Linux
  capabilities, and a private writable state volume.
- Enabled Tor routes fail without a direct fallback. Turning a switch off uses
  the direct route for newly queued scans. Disable Tor routes before stopping
  the service with `docker compose --profile tor stop tor`.
- Queued and running scans retain their selected route; settings changes affect
  scans queued afterward. Saved reports label Tor routes explicitly.

Tor does **not** support SOCKS5 UDP ASSOCIATE. The current MassDNS and DNS parking
transport needs that command, so DNS remains direct unless you separately
configure a UDP-capable custom SOCKS5 proxy. Discovery proxying also skips Amass
4.2, whose internal DNS traffic is not covered by the provider HTTP proxy.
The UI shows both limitations.

Tor does not assign a different exit IP to every request. It adds latency, and
websites can restrict access from its exits; it is not a guarantee against
throttling or blocking. Keep concurrency settings reasonable for the workload.

For a native scanner, the preset defaults to `socks5h://127.0.0.1:9050` and needs
an already running local Tor client. `TYPO_TOR_PROXY_URL` can override that
credential-free preset before starting the application. Compose sets its
default to `socks5h://tor:9050`; `localhost` inside the scanner container refers
to the scanner itself.

References: [Tor SOCKS support](https://spec.torproject.org/socks-extensions.html),
[Tor configuration](https://manpages.debian.org/bookworm/tor/tor.1.en.html),
[Tor control protocol](https://spec.torproject.org/control-spec/commands.html),
[Compose profiles](https://docs.docker.com/compose/how-tos/profiles/).
