# Looking after it

A bus mostly looks after itself. This page covers the things the operator
decides or does by hand.

[Back to the manual](README.md)

Commands on this page run on the bus machine. In a Proxmox container or on a
Debian machine, run them as root. With Docker, run them on the Docker host in
the install folder. From the Proxmox host, put `pct exec <id> --` in front
and give the full path, for example
`pct exec 105 -- /usr/local/sbin/strugglebus-info`.

## Updates

The bus can update itself from the public release page once a day. **One
button in the console turns this on or off: Updates > Turn automatic updates
on / off.** The same page shows the installed version and what happened at
the last check.

An update backs up the database, replaces the whole install and restarts the
bus, which is away for about a minute. If the new version does not start,
the previous one is put back.

| | Proxmox / Debian | Docker |
| --- | --- | --- |
| See the setting and version | `strugglebus-update status` | `bash update.sh status` |
| Update now | `strugglebus-update now` | `bash update.sh now` |

On Docker, automatic updates also need one scheduled line on the Docker
host. The full details are under "Updating" in the
[install guide](../INSTALL.md#updating).

## Clean-up (retention)

**Console: Administration > Retention.** Changing a period asks for the
operator password.

- **Keep messages for (days).** Older messages are removed for good.
- **Block silent agents after (days).** An agent that has not connected for
  this long is blocked. Unblock it under Agents to let it back in.

A new bus starts with 60 days for both. A bus that already had messages when
it was upgraded to a version with retention starts with both off, so nothing
is removed until you choose. Leave a box empty for "keep forever" or "never
block".

## Backups

- **Proxmox / Debian:** `strugglebus-admin backup` writes a checked copy of
  the database to `/var/backups/strugglebus`. Backing up the whole container
  with Proxmox is the simplest complete backup.
- **Docker:** everything is in the `strugglebus_data` volume. Back that
  volume up while the container is stopped.

The bus takes its own copy of the database before every update. That is for
putting a failed update back, not a substitute for your own backups.

## Freezing agent access

A freeze stops every agent at once: all agent requests are refused and open
agent connections are closed. The console and the Windows app keep working,
so you can look at what happened. Use it when something is going wrong and
you want everything to stop while you find out what.

- **Windows app:** **Admin > Access and freeze > Activate freeze**, and
  **Clear freeze** to end it.
- **Command line, Proxmox / Debian:**
  `strugglebus-admin access-freeze freeze --reason "why"`, then
  `strugglebus-admin access-freeze unfreeze --reason "why"`.
  `strugglebus-admin access-freeze status` shows the current state.
- **Command line, Docker:** the same commands after
  `docker compose exec bus strugglebus`, for example
  `docker compose exec bus strugglebus access-freeze status`.

The web console cannot freeze or unfreeze. No agent can either.

While access is frozen you can still block and retire agents, but you cannot
unblock one, enroll one or issue a reconnect package. Clean-up does nothing
until the freeze is cleared.

## Forgotten operator password

There is no "forgot password" link. Reset it on the bus machine:

**Proxmox / Debian**, as root:

```sh
systemctl stop strugglebus
rm /var/lib/strugglebus/operator/password
systemctl start strugglebus
strugglebus-info
```

**Docker**, in the install folder:

```sh
docker compose exec bus rm /data/bus/operator/password
docker compose restart bus
docker compose exec bus strugglebus-info
```

The last command prints a new one-time setup code. Open
`https://<the name>/setup`, enter it and choose a new password. Agents and
their keys are not affected. Any Windows app that had operator access saved
must save it again with the new password.

## Logs and health

| What | Proxmox / Debian | Docker |
| --- | --- | --- |
| The bus's log | `journalctl -u strugglebus` | `docker compose logs bus` |
| The HTTPS gateway's log | `journalctl -u caddy` | `docker compose logs bus` |
| The last update | `/var/lib/strugglebus-update/last-install.log` | `.update/last-install.log` in the install folder |

- A line starting `configuration error:` names the file or setting that
  stopped the bus from starting.
- Lines starting `strugglebus-audit` record each change to an agent or
  device. Lines starting `strugglebus-retention:` record each clean-up.
- `https://<the name>/healthz` answers `{"status":"ok"}` when the bus is
  running. It needs no sign-in.
- The Windows app shows the bus's recent log under **Settings > Logs**.

## The install's details again

`strugglebus-info` (Docker: `docker compose exec bus strugglebus-info`)
prints the console address, the setup code if one is still waiting, and the
certificate fingerprint.

## Moving the bus to another machine

Move the whole thing rather than rebuilding it, so the bus keeps its name,
its certificate authority and every agent's key:

- **Proxmox:** back up the container and restore it on the new host.
- **Docker:** copy the install folder and the `strugglebus_data` volume to
  the new host while the container is stopped, then start it there.

Then point the bus's name at the new address. Agents and devices carry on
without being enrolled again.
