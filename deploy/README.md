# astral-monitor

External probes for the astral infrastructure. The same static Go binary runs on two
vantage points that are not the proxy:

| vantage   | host          | role      | notes                                                  |
|-----------|---------------|-----------|--------------------------------------------------------|
| frankfurt | 78.17.115.31  | primary   | always sends to Telegram                               |
| astral-id | 87.58.213.25  | secondary | sends only while frankfurt has been silent ≥ 5 cycles  |

Source: `Astral-projects/astral-monitor` on the Mac (`main.go`, `deploy/`). Built on the Mac:
`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/astral-monitor .`
then copied here. Nothing is built on the servers.

## Files

| path                                   | what                                                      |
|----------------------------------------|-----------------------------------------------------------|
| `/opt/astral-monitor/astral-monitor`   | binary (also `/usr/local/bin/astral-monitor`)             |
| `/opt/astral-monitor/config.json`      | checks + thresholds, re-read every cycle (no restart)     |
| `/opt/astral-monitor/telegram.env`     | `TG_BOT_TOKEN`, `TG_CHAT_ID` (600, root) — astralVPN bot  |
| `/opt/astral-monitor/peer_key`         | SSH key that can only `cat` the peer's status.json        |
| `/opt/astral-monitor/known_hosts`      | the peer's pinned host key                                |
| `/opt/astral-monitor/silence`          | present = Telegram muted (see below)                      |
| `/var/lib/astral-monitor/status.json`  | this vantage's latest results (read by the peer)          |
| `/var/lib/astral-monitor/engine.json`  | alert state (down/up, mutes, heartbeat day)               |
| `/etc/systemd/system/astral-monitor.service` | the service                                         |

The peer reads status.json over SSH with a forced command in `/root/.ssh/authorized_keys`
(`command="cat /var/lib/astral-monitor/status.json",no-pty,…,from="<peer ip>"`).

## Checks (every 60 s, one quick retry per failure)

- HTTPS (status code, certificate days left): panel `/` (200/302), panel `/api/health`
  (401 "unauthorized" = the VPN backend answers), MSK direct (401, bypasses the proxy;
  frankfurt `89.125.214.37:8443/api/health`, astral-id `10.20.0.11:8443/api/health` over awg-mgmt —
  MSK tcp/8443 is open only to awg-mgmt and Frankfurt since 2026-10-03), sub `/`, the VPN client portal `sub /portal/api/status` (200 with `"enabled":true` — DOWN also when the portal is switched off), haproxy `/` (200 from frankfurt; 403 from astral-id — the
  panel is behind the "VPN" access list), id `/readyz` (`ready:true`), console `/` (302),
  status `/` and `/status.json`.
- SMTP: `mx.astralnet.io:25` banner + STARTTLS (both vantages), `mail.astralnet.io:587`
  banner + STARTTLS (frankfurt only — astral-id would be probing itself).
- DNS via 1.1.1.1 and via 8.8.8.8: MX astralnet.io → mx.astralnet.io; A mx/panel/id →
  95.181.212.217; A mail → 87.58.213.25.
- Site and mail clients (both vantages): `https://astralnet.io/` (200), IMAPS
  `mail.astralnet.io:993` and submissions `mail.astralnet.io:465` (type `tls`: verified TLS
  handshake + greeting `* OK` / `220`), `https://mailbox.astralnet.io/account/` (200, where
  users create app passwords; the Stalwart web UI behind astralProxy since 2026-10-03 —
  `mail.astralnet.io:443` is closed to the public).
- Local on astral-id only: the astral-notify hub `http://127.0.0.1:9311/healthz`
  (`"ok":true`), and backup freshness (type `file-age`): the newest
  `/var/backups/astral-id/astral-id-*` and `/var/backups/stalwart/stalwart-*.tar.gz.age`
  must be under 26 h old.

## Alert rules (one Telegram chat: the astralVPN bot's admin chat)

- **DOWN** — every vantage that runs the check failed it 3 times in a row. A peer whose
  status is stale/unreachable drops out, so the remaining vantage decides alone.
- **RECOVERED** — every such vantage passed 2 times in a row (with the downtime).
- **STILL DOWN** — reminder every 6 h.
- **FLAPPING** — 4 transitions within an hour mute that check for an hour; when the mute ends
  the current state is sent if it differs from the last message.
- **PARTIAL** — one vantage fails 15 cycles in a row while the other passes (route problem).
- **CERT** — certificate under 14 days: one message per check per day.
- **probe silent** — the peer's status is stale 5 cycles in a row (and recovery of it).
- **takeover** — the secondary decides alerts all the time but drops them while the primary
  is sending. When it becomes the sender (primary silent ≥ 5 cycles) it re-announces every
  check that is DOWN at that moment ("re-announced by astral-id after taking over"), so a
  DOWN decided during the hand-over is not lost.
- **daily** — 09:00 MSK summary: "all green" or what is down, nearest cert expiry,
  incidents in the last 24 h.

Messages whose check has `"test": true` are prefixed `[test]`.

## Operate

```sh
astral-monitor once                 # run all checks now, print results (no alerts)
astral-monitor status               # last results + alert state
journalctl -u astral-monitor -f     # cycle log, what was sent / skipped
astral-monitor silence 2h           # mute Telegram for 2 h (also 30m, forever)
astral-monitor silence off          # unmute
systemctl stop astral-monitor       # pause this vantage completely
```

A silence set on either vantage is published in its status.json and honoured by the other
one too, so one command mutes the channel. State keeps updating while muted: unmuting does
not replay what happened meanwhile.

Disable a single check: set `"disabled": true` on it in `config.json` (picked up on the
next cycle). Change the bot token: rewrite `telegram.env` here and on the other vantage,
`systemctl restart astral-monitor`.

## Delivery through astral-notify (astral-id vantage only)

If `/opt/astral-monitor/hub.env` exists (600; `HUB_URL=http://127.0.0.1:9311`, `HUB_TOKEN=…`),
the monitor sends through the astral-notify hub (`/opt/astral-notify/README.md`) as source
`monitor`. Severity comes from the message kind: DOWN/STILL DOWN → critical,
WARN/FLAPPING/PARTIAL/CERT → warning, everything else → info. If the hub is down or refuses,
the monitor falls back to direct Telegram with `telegram.env`. Frankfurt has no hub.env, because
it is not in the AWG tunnel, so it keeps sending directly. Both vantages run the same binary
(the hub code is inert without HUB_URL). Both vantages run the same build since 2026-10-02 (takeover + mail/backup probes).
