# Red Line - Server PC setup: Tailscale + PostgreSQL

This guide sets up the **server PC**: the one PC that holds the shared database and (usually) runs the phone server.
Every other PC and every phone reaches it through **Tailscale**, a private encrypted network. Nothing is opened to the public internet.

```
  Counter PC ──┐
  Other PCs  ──┼── Tailscale (private, encrypted) ──►  SERVER PC  (PostgreSQL + redline_api.py)
  Phones/APK ──┘
```

Do the steps in order. All commands for Windows. Where it says **admin PowerShell**, right-click PowerShell and choose **Run as administrator**.

---

## Fill this in as you go (keep it somewhere safe)

| Item | Your value |
|---|---|
| Server PC Tailscale address (`100.x.x.x`) | |
| Tailscale account e-mail | |
| PostgreSQL version installed | |
| `postgres` (admin) password | |
| `redline` database user password | |
| Windows user that runs Red Line | |

---

## Part 1 - Tailscale

### 1.1 Install and sign in
1. Create a free account at https://tailscale.com (sign in with Google, Microsoft or similar).
2. On the server PC download and install Tailscale from https://tailscale.com/download
3. Open Tailscale from the system tray and sign in with your account.

### 1.2 Find the server's address
In PowerShell:
```
tailscale ip -4
```
It prints an address like `100.101.22.5`. **Write it down.** Every PC and phone uses this address to reach the server. (You can also use the device's Tailscale name, e.g. `server-pc`, if MagicDNS is enabled.)

### 1.3 Keep the server connected
1. In the Tailscale admin page (https://login.tailscale.com/admin/machines) find the server PC, click the **...** menu and choose **Disable key expiry**. Otherwise it can silently drop off the network after a few months.
2. In the Tailscale tray menu open **Preferences** and tick **Run unattended** (if shown), so it stays connected when nobody is logged in.
3. In Windows power settings set the PC to **never sleep**.

### 1.4 Connect the other devices
- **Your own PCs and phones:** install Tailscale on each and sign in with the **same account**.
- **A client or staff member with their own Tailscale account:** in the admin page use **Users > Invite**, or share just the server PC with them (**Machines > ... > Share**). Check Tailscale's current plan limits for how many users and devices are included.

### 1.5 Test
From any other device on your Tailscale network:
```
tailscale ping 100.101.22.5
```
(use your server's address). Replies mean the network is working.

---

## Part 2 - PostgreSQL

### 2.1 Install
1. Download the Windows installer from https://www.postgresql.org/download/windows/ (version 16 or 17 is fine).
2. Run it and keep the defaults: install folder, port **5432**, default locale.
3. Keep **PostgreSQL Server** and **Command Line Tools** ticked. pgAdmin is optional; you can untick Stack Builder.
4. When asked for the **`postgres` superuser password**, choose one and write it in the table above.

### 2.2 Create the database and the app's user
1. Open **SQL Shell (psql)** from the Start menu.
2. Press Enter at Server, Database, Port and Username to accept the defaults, then type the `postgres` password (nothing shows as you type).
3. Run these one at a time, including the semicolons:
   ```sql
   CREATE USER redline WITH PASSWORD 'choose-a-strong-password';
   CREATE DATABASE redline OWNER redline;
   \q
   ```
   The user **must own** the database: Red Line creates its own tables and update triggers and needs to be the owner to do that.

### 2.3 Allow connections from other devices (Tailscale only)
Skip this step if the database is only ever used from this one PC.

1. Find the config folder. In SQL Shell (as `postgres`) run:
   ```sql
   SHOW config_file;
   SHOW hba_file;
   ```
   Both files are in the same `data` folder (usually `C:\Program Files\PostgreSQL\<version>\data`).
2. Open `postgresql.conf` in Notepad **run as administrator**. Find `listen_addresses` and set:
   ```
   listen_addresses = '*'
   ```
   (`'*'` is used so PostgreSQL still starts at boot even if Tailscale is not up yet. The two rules below are what limit access to Tailscale.)
3. Add this line at the very bottom of `pg_hba.conf`:
   ```
   host  redline  redline  100.64.0.0/10  scram-sha-256
   ```
4. Restart the service. In admin PowerShell run `Get-Service *postgres*` to see its name, then:
   ```
   Restart-Service postgresql-x64-17
   ```
   (use the name `Get-Service` showed you).
5. Open the firewall for Tailscale traffic only (admin PowerShell, **one line**):
   ```
   New-NetFirewallRule -DisplayName "PostgreSQL Tailscale" -Direction Inbound -Protocol TCP -LocalPort 5432 -RemoteAddress 100.64.0.0/10 -Action Allow
   ```
6. **Do not** forward port 5432 on your router.

### 2.4 Test
On the server PC:
```
& "C:\Program Files\PostgreSQL\17\bin\psql.exe" -h 127.0.0.1 -U redline -d redline -c "SELECT 1;"
```
(change `17` to your version). Enter the `redline` password. A table showing `1` means it works.

From another Tailscale device that has the PostgreSQL command-line tools, run the same command with `-h 100.101.22.5` (your server's address).

---

## Part 3 - Connect Red Line

### 3.1 First run of the desktop app (on the server PC)
Start the Red Line desktop app. On the very first run it asks for the server details (it asks only once):

| Field | Value on the server PC | Value on other PCs |
|---|---|---|
| Server address | `127.0.0.1` | the server's Tailscale address |
| Port | 5432 | 5432 |
| Database | redline | redline |
| User | redline | redline |
| Password | the `redline` password | the `redline` password |

Click **Test**, then **Save & connect**. The app creates all its tables itself. No SQL needed.
Then enter the product key when asked. It must have been issued for **this PC's** machine code.

The saved details are in `C:\Users\<name>\GameCafeManager\server.json`. To make the app ask again, delete that file.

### 3.2 Phone server (optional, for the APK)
See `PHONE_SETUP.md`. In short: keep `redline_api.py`, `redline_db.py` and `licensing.py` together, run `python redline_api.py` once to create the admin login, then `python redline_api.py install` to run it hidden. Open port 8080 for Tailscale only (admin PowerShell, one line):
```
New-NetFirewallRule -DisplayName "RedLine Phone" -Direction Inbound -Protocol TCP -LocalPort 8080 -RemoteAddress 100.64.0.0/10 -Action Allow
```

---

## Part 4 - Looking after it

- **Backups:** use **Settings > Backup now** in the app, and/or:
  ```
  & "C:\Program Files\PostgreSQL\17\bin\pg_dump.exe" -h 127.0.0.1 -U redline redline -f redline_backup.sql
  ```
  Keep copies on another drive or PC, not only on the server.
- **Keep the server on:** if it is off or asleep, every PC and phone stops working.
- **Never delete** `phone_key.txt`, `server.json`, `license.key` and `license_state.json`.
- **Windows updates:** schedule restarts outside opening hours. PostgreSQL and the phone server start again by themselves after a restart (the phone server once the Windows user logs in).

---

## Troubleshooting

| Message / symptom | Likely cause and fix |
|---|---|
| `password authentication failed` | Wrong user name or password. Reset: as `postgres` run `ALTER USER redline WITH PASSWORD 'new-password';` |
| `no pg_hba.conf entry` | The line in 2.3 step 3 is missing or misspelled, or the service was not restarted. |
| `connection timed out` | Firewall rule missing (2.3 step 5), or Tailscale is off on this device or the server. |
| `connection refused` | PostgreSQL is not running, or `listen_addresses` was not changed/saved. |
| `permission denied` when the app starts | The database owner is not `redline`. Fix as `postgres`: `ALTER DATABASE redline OWNER TO redline;` |
| Cannot find the `data` folder | Run: `Get-CimInstance Win32_Service \| Where-Object Name -like "*postgres*" \| Select Name, PathName \| Format-List` The `-D "..."` path is the data folder. |
| Other PCs can ping the server but the app cannot connect | Check the address and port in `server.json`, and that the firewall rule exists: `Get-NetFirewallRule -DisplayName "PostgreSQL Tailscale"` |
| Tailscale shows the server as offline | PC asleep or logged out, or key expiry not disabled (1.3). |

---

## Security notes

- Use a strong password for both the `postgres` and `redline` users and do not share them in chat or e-mail.
- Never expose port 5432 or 8080 to the internet. Only the Tailscale range `100.64.0.0/10` is allowed by the rules above.
- Keep your key generator and its private signing key off client machines.
