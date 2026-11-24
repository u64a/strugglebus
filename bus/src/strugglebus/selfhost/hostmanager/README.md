# Host-manager starter kit

This kit sets up an AI agent that looks after one **Proxmox VE server** or one
**Docker host** and reports what it sees on the bus. It is written for GitHub
Copilot CLI. You do not need to be an expert. Do the steps in order and run the
commands as written.

The agent can only **look** unless you decide otherwise. It cannot start, stop,
change or delete anything with the access this kit gives it by default.

## What is in this folder

| File | What it is for |
| --- | --- |
| `AGENTS.md` | The agent's instructions. You copy it into the agent's folder and fill in the blanks. |
| `proxmox/create-readonly-token.sh` | Run on the Proxmox host. Makes a read-only key for the agent. |
| `proxmox/create-lifecycle-role.sh` | Optional. Lets the agent start and stop the guests in one pool. |
| `docker/socket-proxy.compose.yaml` | Run on the Docker host. Gives the agent a read-only view of Docker. |
| `ROE-ADDENDUM.md` | Rules for the bus operator to add to the bus's rules of engagement. |

## Before you start

- The bus is installed and **the agent has joined the bus (see INSTALL.md)**.
- GitHub Copilot CLI works on the PC where the agent will run.
- You can log in to the Proxmox host as root, or run `docker` on the Docker host.

**Do steps 1 to 3 yourself, in your own terminal.** Do not ask the agent to do
them. That way the agent's key never appears in its chat.

The examples use `pve.home.arpa` and `docker.home.arpa`. Use your own host's
name or address instead.

## Step 1. Make two folders on the agent's PC

One folder is where the agent works. The other holds its key and stays private.

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force "$HOME\host-manager", "$HOME\host-manager-private"
```

Linux or macOS:

```sh
mkdir -p ~/host-manager ~/host-manager-private
chmod 700 ~/host-manager-private
```

Never put either folder under source control.

## Step 2. Copy AGENTS.md into the working folder

Copy `AGENTS.md` from this kit into `host-manager`. Open the copy in a text
editor and replace every placeholder in angle brackets, such as `<HOST NAME>`,
with your own details. Delete the block for the kind of host you do not have.

## Step 3. Give the agent read-only access

Do 3A for Proxmox VE, or 3B for Docker.

### 3A. Proxmox VE

1. Copy the script to the Proxmox host and run it as root:

   ```sh
   scp proxmox/create-readonly-token.sh root@pve.home.arpa:/root/
   ssh root@pve.home.arpa bash /root/create-readonly-token.sh
   ```

   It prints a table. The `value` row is the key's **secret**. Proxmox shows it
   once and can never show it again. It also prints the token ID
   (`busagent@pve!bus`) and the API address.

2. Save the secret on the agent's PC as one line in the file
   `host-manager-private/pve-token-secret.txt`. Do not save it anywhere else.

3. Copy the Proxmox certificate root to the agent's PC. The agent uses it to
   check that it is really talking to your host:

   ```sh
   scp root@pve.home.arpa:/etc/pve/pve-root-ca.pem ~/host-manager-private/
   ```

   In Windows PowerShell write the folder as `$HOME\host-manager-private\`.

4. Test it. Windows PowerShell:

   ```powershell
   $env:PVE_API_URL = "https://pve.home.arpa:8006/api2/json"
   $env:PVE_TOKEN_ID = "busagent@pve!bus"
   $env:PVE_TOKEN_SECRET = (Get-Content "$HOME\host-manager-private\pve-token-secret.txt" -Raw).Trim()
   $env:PVE_CA_FILE = "$HOME\host-manager-private\pve-root-ca.pem"
   curl.exe --silent --show-error --ssl-revoke-best-effort --cacert $env:PVE_CA_FILE -H "Authorization: PVEAPIToken=$($env:PVE_TOKEN_ID)=$($env:PVE_TOKEN_SECRET)" "$($env:PVE_API_URL)/version"
   ```

   Linux or macOS:

   ```sh
   export PVE_API_URL="https://pve.home.arpa:8006/api2/json"
   export PVE_TOKEN_ID='busagent@pve!bus'
   export PVE_TOKEN_SECRET="$(cat ~/host-manager-private/pve-token-secret.txt)"
   export PVE_CA_FILE="$HOME/host-manager-private/pve-root-ca.pem"
   curl --silent --show-error --cacert "$PVE_CA_FILE" -H "Authorization: PVEAPIToken=$PVE_TOKEN_ID=$PVE_TOKEN_SECRET" "$PVE_API_URL/version"
   ```

   A line that contains `"version"` means it works.

   On Windows, `--ssl-revoke-best-effort` skips only the online lookup that
   asks whether a certificate has been withdrawn. A home server cannot answer
   that lookup. The certificate itself is still checked against the file from
   item 3. Never use `-k` or `--insecure`: those turn the check off.

### 3B. Docker

1. Copy `docker/socket-proxy.compose.yaml` to the Docker host and start it
   there:

   ```sh
   docker compose -f socket-proxy.compose.yaml up -d
   ```

2. Test it on the Docker host. The first command must print `200` and the
   second must print `403`, which means reading works and changing is refused:

   ```sh
   curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:2375/version
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:2375/containers/prune
   ```

3. If the agent runs on **another machine**, open a tunnel from the agent's PC
   and leave that window open while the agent works:

   ```sh
   ssh -N -L 2375:127.0.0.1:2375 <your user>@docker.home.arpa
   ```

   The compose file explains the other way (listening on the LAN) and why it is
   less safe.

4. On the agent's PC, point Docker tools at the proxy. Windows PowerShell:

   ```powershell
   $env:DOCKER_HOST = "tcp://127.0.0.1:2375"
   ```

   Linux or macOS:

   ```sh
   export DOCKER_HOST=tcp://127.0.0.1:2375
   ```

   If the PC has no `docker` command, the agent can read the same information
   with `curl http://127.0.0.1:2375/containers/json?all=true`.

## Step 4. Start Copilot in the working folder

Use the **same terminal** in which you set the variables in step 3, so the
agent inherits them. Set them again each time you open a new terminal.

Go to the working folder and start Copilot CLI with the launcher that joining
the bus created. Use the agent's name on the bus in place of `<agent name>`.

Windows PowerShell:

```powershell
cd "$HOME\host-manager"
& "$HOME\.strugglebus\<agent name>\bus-copilot.cmd"
```

Linux or macOS:

```sh
cd ~/host-manager
~/.strugglebus/<agent name>/bus-copilot
```

The launcher connects Copilot to the bus. Copilot reads `AGENTS.md` from the
folder it starts in. As your first message type:

```text
Read AGENTS.md and start your session.
```

Leave Copilot's approval prompts on. Do not start it with `--allow-all-tools`
or `--yolo`. The prompts are how you see each command before it runs.

## The two access levels

| | Level 1: read-only (default) | Level 2: power in one pool (optional, Proxmox only) |
| --- | --- | --- |
| Set up by | `create-readonly-token.sh` or the Docker proxy | `create-lifecycle-role.sh --pool <pool>` |
| Can | See guests or containers, their state and settings, node health, storage and disk use, pools, network settings, logs (Docker) | Everything in level 1, and start, shut down, stop, reboot, reset, suspend and resume the guests **in that one pool** |
| Cannot | Start, stop, change or delete anything. Open a console. Run commands inside a guest or container. | Anything outside that pool. Create or delete guests. Change settings. Roll back snapshots. Move guests. Touch backups. Open a console. |

Things to know:

- **Read-only can still see private details.** Guest settings, container
  settings and container logs often contain passwords. The Docker proxy also
  lets a reader download files from inside containers, and can pass typed
  input to a container that was started with an open terminal. Treat the
  agent's key and the proxy port as sensitive.
- **Proxmox level 1** uses the built-in role `PVEAuditor`. On newer Proxmox VE
  versions that role can also ask a VM's guest agent for basic facts such as
  its IP addresses.
- **Docker has no level 2 in this kit.** If a container needs a restart, the
  agent tells you and you do it.
- **If Copilot runs on the Docker host itself**, under an account that can run
  `docker`, the proxy cannot hold it back. The approval prompts and `AGENTS.md`
  are then the only limit. Run the agent on another PC if you can.

### Turning on level 2 (Proxmox only)

Only do this if you want the agent to be able to restart things, and only
after level 1 works.

1. In the Proxmox web interface open Datacenter, Permissions, Pools and create
   a pool, for example `agent-managed`. Add **only** the guests the agent may
   start and stop. Leave out the guest that runs the bus, and anything else
   that must stay up, such as a router or firewall guest.
2. Run on the Proxmox host as root:

   ```sh
   scp proxmox/create-lifecycle-role.sh root@pve.home.arpa:/root/
   ssh root@pve.home.arpa bash /root/create-lifecycle-role.sh --pool agent-managed
   ```

3. Update the "Access level" line in the agent's `AGENTS.md`.

The agent still has to ask you in the Copilot session before each start or
stop. Copilot's approval prompt shows you the command. "Stop" cuts the power to
a guest without a clean shutdown, so prefer "shut down".

## Taking the access away

Proxmox, level 2 only (the agent goes back to read-only):

```sh
ssh root@pve.home.arpa bash /root/create-lifecycle-role.sh --remove --pool agent-managed
```

Proxmox, everything (the key stops working and the user is deleted):

```sh
ssh root@pve.home.arpa bash /root/create-readonly-token.sh --remove
```

If you used level 2, remove it first, then remove everything.

Docker, on the Docker host:

```sh
docker compose -f socket-proxy.compose.yaml down
```

Then delete the `host-manager-private` folder on the agent's PC.

If you think the key has leaked, take the access away at once, then start
again from step 3 to make a new key.

## When something goes wrong

| What you see | What to do |
| --- | --- |
| `run this as root on the Proxmox host` | Log in to the Proxmox host as root and run it again. |
| `the 'pveum' command was not found` | You ran the script on the wrong machine. Run it on the Proxmox host. |
| `token ... already exists` | Nothing was changed. If you lost the secret, run the script with `--remove`, then run it again. |
| `user ... already exists and was not created by this script` | Choose another name: add `--user busagent2@pve`. |
| `pool '...' does not exist` | Create the pool first (level 2, item 1). |
| curl says the certificate name does not match | Use the Proxmox host's full name in `PVE_API_URL`. `hostname -f` on the Proxmox host prints it. Do not switch the check off. |
| curl prints `401` or `authentication failure` | The token ID or secret is wrong. Check for a missing character or an extra space. |
| curl prints `403` from Proxmox | The key works but the action is not allowed. For level 1 that is correct for anything except reading. |
| Docker commands answer `403 Forbidden` | Correct for anything except reading. |
| Docker commands cannot connect | The proxy or the tunnel is not running, or `DOCKER_HOST` is not set in this terminal. |
