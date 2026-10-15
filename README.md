# 🌐 iitg-connect

Stay logged in to the IIT Guwahati internet without keeping a browser tab open. Works on 🐧 Linux, 🍎 macOS and 🪟 Windows, even with Cloudflare WARP on.

## 📥 Install

### 1️⃣ Install Rust

Get it from **[rustup.rs](https://rustup.rs)** (one-time setup).

> 🪟 On Windows, accept the installer's offer to install the Visual Studio C++ Build Tools.
>
> 🐧 On Ubuntu/Debian, also run `sudo apt install libsecret-tools` so your password can go in the keyring.

### 2️⃣ Download this repo

```bash
git clone https://github.com/ABHILESH1412/iitg-connect.git
cd iitg-connect
```

### 3️⃣ Run the installer

🐧 **Linux** / 🍎 **macOS**

```bash
./install.sh
```

🪟 **Windows** (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

✅ Done! Open a new terminal and the commands below are ready to use.

## 🚀 Usage

| Command | What it does |
|---|---|
| `iitg-connect` | 🔌 Log in and stay logged in, quietly in the background |
| `iitg-stop` | 🛑 Stop it and log out |
| `iitg-update` | 🔑 Change your saved username/password |
| `iitg-status` | 📊 Check whether it's running |

### 🔐 First run

```bash
iitg-connect
```

It asks for your IITG username and password **once** and saves them securely in your system's password store (🐧 GNOME Keyring / KWallet, 🍎 Keychain, 🪟 Credential Manager). After that, just type `iitg-connect` and you're online. You can close the terminal; it keeps running. 🎉

### 🔁 Changed your password?

```bash
iitg-update
```

### ⏱️ Refresh interval (optional)

It refreshes your session every 10 minutes. To change that:

```bash
IITG_INTERVAL=15 iitg-connect           # 🐧 🍎
```

```powershell
$env:IITG_INTERVAL=15; iitg-connect     # 🪟
```

## 🔄 Updating

```bash
git pull
iitg-stop
./install.sh      # 🪟 Windows: powershell -ExecutionPolicy Bypass -File install.ps1
iitg-connect
```
