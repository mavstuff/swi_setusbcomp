# swi_setusbcomp

Query and change the **USB composition** of Sierra Wireless cellular modems when the device is stuck in **MBIM-only** mode and no AT or QMI serial ports are available.

Originally written by [Bjørn Mork](https://git.mork.no/?p=wwan.git;a=blob_plain;f=scripts/swi_setusbcomp.pl) (2015, GPLv2) as a one-off hack. The same functionality is now built into [`qmicli`](https://www.freedesktop.org/software/libqmi/man/latest/qmicli.1.html) via `--dms-swi-get-usb-composition` and `--dms-swi-set-usb-composition`, but this standalone Perl script remains useful on minimal systems or when you want a single file with no build dependencies beyond Perl modules.

---

## Table of Contents

- [The Problem](#the-problem)
- [What This Script Does](#what-this-script-does)
- [Supported Hardware](#supported-hardware)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Usage on Android (via ADB)](#usage-on-android-via-adb)
- [USB Composition Reference](#usb-composition-reference)
- [How It Works](#how-it-works)
- [After Changing Composition](#after-changing-composition)
- [Troubleshooting](#troubleshooting)
- [Alternatives](#alternatives)
- [References](#references)
- [License](#license)

---

## The Problem

Sierra Wireless (now Semtech) Qualcomm-based modems expose multiple USB interfaces to the host. Which interfaces appear — diagnostic (DM), NMEA/GPS, AT command port, QMI, MBIM, RMNET, ECM, etc. — is controlled by a setting called **USB composition**.

Common scenarios where composition becomes a problem on Linux:

| Scenario | Symptom |
|----------|---------|
| Windows driver or Sierra application changed composition | Modem enumerates as MBIM-only; no `/dev/ttyUSB*` or AT port |
| Firmware defaults to composition 9 (MBIM only) | `NetworkManager`/`ModemManager` works, but `qmicli` and AT tools cannot run |
| MBIM-only PID lock (some EM7455/MC7455 units) | Even after reset, only `/dev/cdc-wdm0` appears |

Normally you would fix this with AT commands:

```
AT!USBCOMP=1,1,100D    # newer MC/EM series (bitmask style)
AT!UDUSBCOMP=8         # older modules (index style)
AT!RESET
```

But if the modem is in MBIM-only mode, **there is no AT port**. The QMI control channel is also gone. What remains is the MBIM control device (`/dev/cdc-wdm*`), driven by the Linux `cdc_mbim` kernel driver.

This script reaches the modem through that MBIM channel by tunneling QMI messages inside a vendor-specific MBIM service — the same mechanism later adopted by libqmi's `--device-open-mbim` mode.

---

## What This Script Does

1. Opens an MBIM control device (default `/dev/cdc-wdm0`) and verifies it is served by the `cdc_mbim` driver.
2. Establishes an MBIM session (OPEN / OPEN_DONE).
3. Tunnels QMI over MBIM using the Qualcomm **EXT_QMUX** vendor service.
4. Allocates a QMI DMS (Device Management Service) client ID.
5. Sends **QMI_DMS_SWI_GET_USB_COMPOSITION** (`0x555B`) to read the current composition and the list of supported compositions.
6. Optionally sends **QMI_DMS_SWI_SET_USB_COMPOSITION** (`0x555C`) to change the composition.
7. Cleans up (releases DMS client, MBIM CLOSE) and exits.

**Without `--usbcomp`**, the script only displays the current and supported compositions. **With `--usbcomp=N`**, it attempts to switch to composition `N` if the modem reports it as supported.

---

## Supported Hardware

Tested and documented primarily on Qualcomm-based Sierra Wireless modules in the **MC/EM series**, including:

- MC7354, MC7710, MC7455
- EM7455, EM7565
- Similar modules exposing MBIM via `cdc_mbim`

The script requires:

- An MBIM control character device (`/dev/cdc-wdm*`)
- The Qualcomm **EXT_QMUX** MBIM vendor service (UUID `d1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3`)

You can verify the QMI-over-MBIM service is present:

```bash
mbimcli -d /dev/cdc-wdm0 --query-device-services
```

Look for a service named `qmi` with the UUID above and CID `msg (1)`.

**Not supported:** modems that only expose a QMI (`qmi_wwan`) interface with no MBIM channel, or modems lacking the EXT_QMUX service.

---

## Requirements

### System

- Linux with the `cdc_mbim` kernel driver
- Root privileges (the `/dev/cdc-wdm*` device is typically restricted)
- Perl 5 with these modules:
  - `UUID::Tiny`
  - `IPC::Shareable`
  - `JSON`
  - `Getopt::Long` (core)
  - `Fcntl` (core)
  - `sys/ioctl.ph` (from `perl-base` / `perl-dev` on Debian/Ubuntu)

### Optional tools (for diagnosis, not required by the script)

- `mbimcli` — from [libmbim](https://www.freedesktop.org/software/libmbim/)
- `qmicli` — from [libqmi](https://www.freedesktop.org/software/libqmi/)
- `mmcli` — from [ModemManager](https://modemmanager.org/)

---

## Installation

### 1. Get the script

```bash
git clone https://github.com/mavstuff/swi_setusbcomp.git
cd swi_setusbcomp
chmod +x scripts_swi_setusbcomp.pl
```

Or download the script directly from the [original upstream](https://git.mork.no/?p=wwan.git;a=blob_plain;f=scripts/swi_setusbcomp.pl).

### 2. Install dependencies

Pick the instructions for your distribution. All examples assume you run the script as root (or with `sudo`).

#### Debian, Ubuntu, Raspberry Pi OS, Armbian

```bash
sudo apt update
sudo apt install perl libuuid-tiny-perl libipc-shareable-perl libjson-perl
```

#### OpenWrt

Ensure MBIM kernel support is present, then install Perl and core modules:

```bash
opkg update
opkg install perl perlbase-essential perlbase-json-pp perlbase-getopt perlbase-fcntl \
             kmod-usb-net-cdc-mbim
```

`UUID::Tiny` and `IPC::Shareable` are not packaged in the default OpenWrt feeds. Options:

- **Entware** (recommended on routers with USB storage) — see below
- **cpanminus on device** — needs extra flash/RAM and build tools:

```bash
opkg install perlbase-extutils perlbase-io make gcc
curl -L https://cpanmin.us | perl - --notest UUID::Tiny IPC::Shareable
```

Copy the script to the router (`scp`) or download it with `wget` if space is tight.

#### Entware (OpenWrt, DD-WRT, AsusWRT-Merlin, Synology, …)

[Entware](https://github.com/Entware/Entware) provides `opkg` packages for embedded devices with more storage than stock OpenWrt.

```bash
/opt/bin/opkg update
/opt/bin/opkg install perl perl-json
```

Install the remaining modules via CPAN (see [Entware Perl wiki](https://github.com/Entware/Entware/wiki/Self-installation-of-perl-modules)):

```bash
/opt/bin/opkg install perl-dev make gcc
/opt/bin/perl -MCPAN -e 'install UUID::Tiny'
/opt/bin/perl -MCPAN -e 'install IPC::Shareable'
```

Run the script with `/opt/bin/perl scripts_swi_setusbcomp.pl`.

#### Alpine Linux

Common in containers, industrial gateways, and minimal embedded images:

```bash
apk add perl perl-json perl-dev make gcc musl-dev
cpanm --notest UUID::Tiny IPC::Shareable
```

Alpine ships `perl-json` but not `perl-uuid-tiny` or `perl-ipc-shareable`; `cpanm` (from `perl-app-cpanminus`) is the shortest path.

#### Arch Linux

Most modules are in the official `extra` repository; `UUID::Tiny` is AUR-only.

```bash
sudo pacman -S perl perl-json perl-ipc-shareable cpanminus
cpanm --notest UUID::Tiny
```

Or install `perl-uuid-tiny` from the AUR (`yay -S perl-uuid-tiny` / `paru -S perl-uuid-tiny`).

#### CentOS, Rocky Linux, AlmaLinux, RHEL

**CentOS 7 / RHEL 7** — enable EPEL first, then install:

```bash
sudo yum install epel-release
sudo yum install perl perl-JSON perl-UUID-Tiny perl-IPC-Shareable
```

If `yum` cannot find a module, use CPAN:

```bash
sudo yum install perl-CPAN gcc make
sudo cpan UUID::Tiny IPC::Shareable
```

**CentOS Stream 8/9, Rocky 8/9, AlmaLinux 8/9, RHEL 8/9** — `dnf` can resolve packages by Perl module name:

```bash
sudo dnf install perl 'perl(UUID::Tiny)' 'perl(IPC::Shareable)' 'perl(JSON)'
```

Enable EPEL on RHEL if packages are missing: `sudo dnf install epel-release`.

#### Fedora

```bash
sudo dnf install perl 'perl(UUID::Tiny)' 'perl(IPC::Shareable)' 'perl(JSON)'
```

#### openSUSE Leap / Tumbleweed

```bash
sudo zypper refresh
sudo zypper install perl perl-JSON perl-UUID-Tiny perl-IPC-Shareable
```

Search if a package name differs on your release: `zypper search perl-IPC-Shareable`.

#### SUSE Linux Enterprise (SLES)

Base SLES images ship a minimal Perl set. Enable [SUSE Package Hub](https://packagehub.suse.com/) for community packages:

```bash
sudo SUSEConnect -p sle-packagehub/<version>/x86_64   # adjust version/arch
sudo zypper refresh
sudo zypper install perl perl-JSON perl-UUID-Tiny
```

`perl-IPC-Shareable` may not be in Package Hub for every SLES release. If `zypper install perl-IPC-Shareable` fails:

```bash
sudo zypper install perl-CPAN gcc make
sudo cpan IPC::Shareable
```

Alternatively, add the `devel:languages:perl` OBS repository for your SLE service pack (see [software.opensuse.org](https://software.opensuse.org/)).

#### Yocto / Buildroot / custom embedded images

These build systems do not share one package manager. Typical approaches:

- **Yocto:** add `perl`, `perl-module-json`, and CPAN recipes (or a custom layer) for `UUID::Tiny` and `IPC::Shareable` to your image; ensure `cdc_mbim` is enabled in the kernel config (`CONFIG_USB_NET_CDC_MBIM`).
- **Buildroot:** enable `BR2_PACKAGE_PERL` and required Perl module packages in `menuconfig`, or install modules at first boot with `cpanm` if your rootfs is writable.
- **Prebuilt vendor SDK:** many LTE gateway BSPs ship Debian- or OpenWrt-based rootfs — use the matching section above.

If Perl module installation on the target is impractical, run the script from a chroot or NFS root with a fuller userspace, or use `qmicli --device-open-mbim` from a cross-built [libqmi](https://www.freedesktop.org/software/libqmi/) instead.

---

## Usage

```
scripts_swi_setusbcomp.pl [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--device=<path>` | MBIM control device (default: `/dev/cdc-wdm0`) |
| `--usbcomp=<num>` | Change USB composition to index `<num>` |
| `--verbose` | Print QMI subsystem versions and composition table (default: on) |
| `--noverbose` | Suppress extra output |
| `--debug` | Hex-dump all MBIM/QMI traffic and decode message headers |
| `--help` | Show usage and exit |

### Examples

**Show current composition and all supported modes** (read-only):

```bash
sudo ./scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0
```

Example output:

```
MBIM OPEN succeeded
MBIM QMI support verified
supports 12 QMI subsystems:
  QMI_CTL (1.0)
  QMI_WDS (1.67)
  ...
Got QMI DMS client ID '1'
Current USB composition: 9
USB compositions:
    6 - DM   NMEA  AT    QMI                              SUPPORTED
    8 - DM   NMEA  AT    MBIM                             SUPPORTED
  * 9 - MBIM                                                  SUPPORTED
```

**Switch from MBIM-only (9) to DM+NMEA+AT+QMI (6)** — common fix for MC7354:

```bash
sudo ./scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0 --usbcomp=6
```

**Switch to DM+NMEA+AT+MBIM (8)** — keeps MBIM networking while restoring AT/QMI ports:

```bash
sudo ./scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0 --usbcomp=8
```

**Debug a failing session:**

```bash
sudo ./scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0 --debug
```

After any composition change, **reset or power-cycle the modem** for the new USB layout to take effect (see [After Changing Composition](#after-changing-composition)).

---

## Usage on Android (via ADB)

This script can run on Android when the device exposes a Linux-style `/dev/cdc-wdm*` node backed by the `cdc_mbim` kernel driver. That is common on **embedded/industrial Android** boards and **rooted** setups with an external USB LTE modem (OTG), but **not** on typical consumer phones where the built-in modem is managed by the proprietary RIL stack.

### When it works

| Setup | Likely to work? |
|-------|-----------------|
| AOSP / industrial tablet with USB or M.2 LTE modem | Yes, if `cdc_mbim` is in the kernel and `ueventd` creates `/dev/cdc-wdm*` |
| Rooted phone/tablet + USB LTE dongle (OTG) | Yes, with root and kernel driver support |
| Stock phone, internal modem only | No — no `/dev/cdc-wdm0` for userspace; use a PC instead |
| Termux without root | No — this script opens `/dev/cdc-wdm0` directly; `termux-usb` cannot substitute without code changes |

The script is **not** Termux-USB compatible as-is: it expects a standard character device node, not an Android USB file descriptor.

### Prerequisites

On the **host PC**:

- [Android platform-tools](https://developer.android.com/tools/releases/platform-tools) (`adb`)
- USB debugging enabled on the Android device

On the **Android device**:

- Root (`su`) or an eng/userdebug build with `adb root` — required to open `/dev/cdc-wdm*`
- Kernel modules `cdc_mbim` and `cdc_wdm` (check with `lsmod` or `cat /proc/modules`)
- Perl 5 with `UUID::Tiny`, `IPC::Shareable`, and `JSON` — [Termux](https://termux.dev/) is the practical way to get these on Android

### 1. Connect and verify the modem

From your PC:

```bash
adb devices
adb shell getprop ro.build.type          # userdebug/eng helps for adb root
```

Check that the MBIM control device exists:

```bash
adb shell su -c 'ls -l /dev/cdc-wdm*'
adb shell su -c 'readlink -f /sys/class/usbmisc/cdc-wdm0/device/driver'
```

The driver symlink should end in `cdc_mbim`. If you see `/sys/class/usbmisc/cdc-wdm0` in sysfs but **no** `/dev/cdc-wdm0`, the Android `ueventd` rules are missing. Add to `ueventd.rc` (custom ROM / vendor image):

```
/dev/cdc-wdm*  0660  radio  radio
```

See [cdc-wdm support on AOSP](http://paldan.altervista.org/cdc-wdm-support-now-added-in-aosp-hikey/) and vendor guides (e.g. [Quectel Android RIL](https://www.quectel.com/content/uploads/2024/02/Quectel_Android_RIL_Driver_User_Guide_V2.0-1-4.pdf)).

Confirm the modem enumerates:

```bash
adb shell su -c 'lsusb'
adb shell su -c 'dmesg | grep -i mbim'
```

### 2. Install Perl in Termux

Install [Termux](https://github.com/termux/termux-app/releases) on the device (GitHub build recommended if you need `run-as` from `adb`). Inside Termux:

```bash
pkg update
pkg install perl make clang
curl -L https://cpanmin.us | perl - App::cpanminus
cpanm --notest UUID::Tiny IPC::Shareable JSON
```

To drive Termux from `adb` without typing on the device (rooted, or debuggable Termux build):

```bash
adb shell -tt run-as com.termux \
  files/usr/bin/env \
    PATH=/data/data/com.termux/files/usr/bin \
    LD_PRELOAD=/data/data/com.termux/files/usr/lib/libtermux-exec.so \
    HOME=/data/data/com.termux/files/home \
    bash -lic 'cpanm --notest UUID::Tiny IPC::Shareable JSON'
```

### 3. Copy the script to the device

From your PC, in the repository directory:

```bash
adb push scripts_swi_setusbcomp.pl /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/scripts_swi_setusbcomp.pl'
```

### 4. Release the modem from the Android telephony stack

The RIL daemon (`rild`) may hold the modem open. Stop it before running the script (embedded devices only — this disables cellular on the device until reboot):

```bash
adb root                              # eng/userdebug builds only
adb shell stop ril-daemon
# or, with su:
adb shell su -c 'setprop ctl.stop ril-daemon'
```

On SELinux-enforced builds you may need permissive mode for testing:

```bash
adb shell su -c 'setenforce 0'
```

### 5. Run the script

Using Termux's Perl as root (typical path):

```bash
# Query current composition
adb shell su -c '/data/data/com.termux/files/usr/bin/perl /data/local/tmp/scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0'

# Change composition (example: switch to DM+NMEA+AT+MBIM)
adb shell su -c '/data/data/com.termux/files/usr/bin/perl /data/local/tmp/scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0 --usbcomp=8'
```

If Perl is installed elsewhere, adjust the path. Debug output:

```bash
adb shell su -c '/data/data/com.termux/files/usr/bin/perl /data/local/tmp/scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0 --debug'
```

### 6. Reset the modem

Power-cycle the USB modem or reset via AT/QMI if available, then reboot the Android device or restart `rild`:

```bash
adb shell su -c 'setprop ctl.start ril-daemon'
adb reboot
```

Verify the new composition after re-enumeration:

```bash
adb shell su -c '/data/data/com.termux/files/usr/bin/perl /data/local/tmp/scripts_swi_setusbcomp.pl --device=/dev/cdc-wdm0'
```

### Android-specific troubleshooting

| Symptom | What to try |
|---------|-------------|
| `Permission denied` on `/dev/cdc-wdm0` | Run via `su`; check node owner (`radio` group) and SELinux context (`radio_device`) |
| No `/dev/cdc-wdm0` node | Fix `ueventd.rc`; confirm `cdc_mbim` bound in `dmesg` |
| `only MBIM devices are supported` | Driver is `qmi_wwan`, not `cdc_mbim` — wrong USB composition or driver |
| `Failed to verify QMI vendor specific MBIM service` | Modem firmware lacks EXT_QMUX over MBIM; try `mbimcli --query-device-services` via cross-built libmbim |
| `open /dev/cdc-wdm0: Device or resource busy` | Stop `rild`, ModemManager-like services, or other apps using the modem |
| Termux Perl not found from `su` | Use the full path `/data/data/com.termux/files/usr/bin/perl` (shown above) |
| `run-as com.termux` fails | Install the debuggable Termux APK from GitHub releases, or use root |

### Easier alternative on Android

If you can move the modem to a Linux PC (or the Android device runs a Linux chroot/VM with USB passthrough), use `qmicli` there instead:

```bash
qmicli -d /dev/cdc-wdm0 --device-open-mbim --dms-swi-get-usb-composition
qmicli -d /dev/cdc-wdm0 --device-open-mbim --dms-swi-set-usb-composition=8
```

---

## USB Composition Reference

The script embeds Sierra Wireless composition indices 0–22. The modem firmware reports which indices are actually supported; unsupported ones are marked `NOT SUPPORTED` in the listing.

| Index | Interfaces | Typical use |
|------:|------------|-------------|
| 0 | HIP, DM, NMEA, AT, MDM1, MDM2, MDM3, MS | Legacy |
| 1 | HIP, DM, NMEA, AT, MDM1, MS | Legacy |
| 2 | HIP, DM, NMEA, AT, NIC1, MS | Legacy |
| 3 | HIP, DM, NMEA, AT, MDM1, NIC1, MS | Legacy |
| 4 | HIP, DM, NMEA, AT, NIC1, NIC2, NIC3, MS | Legacy |
| 5 | HIP, DM, NMEA, AT, ECM1, MS | Legacy ECM |
| **6** | **DM, NMEA, AT, QMI** | **Classic Linux QMI setup** |
| 7 | DM, NMEA, AT, RMNET1, RMNET2, RMNET3 | RMNET data channels |
| **8** | **DM, NMEA, AT, MBIM** | **MBIM + management ports (recommended on modern kernels)** |
| **9** | **MBIM** | **MBIM-only (problematic if you need AT/QMI)** |
| 10 | NMEA, MBIM | GPS + MBIM |
| 11 | DM, MBIM | Diagnostic + MBIM |
| 12 | DM, NMEA, MBIM | Diagnostic + GPS + MBIM |
| 13–22 | Dual-config (comp6/comp7 paired with comp8–comp12) | Boot-time composition switching |

### Interface abbreviations

| Abbr | Meaning |
|------|---------|
| HIP | Host Interface Protocol (legacy Sierra) |
| DM | Diagnostic / DM port (`/dev/ttyUSB*`, often first port) |
| NMEA | GPS NMEA output |
| AT | AT command port |
| MDM1–3 | Modem network interfaces (QMI/WWAN) |
| NIC1–3 | Network interface (CDC-NCM/ECM) |
| ECM1 | CDC-ECM network |
| QMI | QMI control (`/dev/cdc-wdm*` via `qmi_wwan`) |
| MBIM | MBIM control + data (`/dev/cdc-wdm*` + `wwan0` via `cdc_mbim`) |
| RMNET1–3 | Qualcomm RMNET data channels |
| MS | Mass Storage (firmware update mode) |

On newer firmware (MC7455/EM7455 and later), Sierra also documents compositions via **bitmask** with `AT!USBCOMP`. The numeric indices above (6, 8, 9, etc.) map to the same logical layouts but use the older index scheme understood by the QMI vendor commands.

---

## How It Works

### Architecture overview

```
┌─────────────┐     MBIM protocol      ┌──────────────────┐
│   Script    │ ◄──────────────────►  │  /dev/cdc-wdm0   │
│  (parent)   │   read/write           │  (cdc_mbim drv)  │
└──────┬──────┘                        └────────┬─────────┘
       │ fork()                               │
┌──────▼──────┐                               │
│   Reader    │ ◄── async MBIM responses ─────┘
│   (child)   │
└──────┬──────┘
       │ IPC::Shareable
       ▼
  lastmbim / lastqmi  (shared between processes)
```

The parent process writes MBIM requests; a forked child continuously reads responses and decodes them into shared memory. This avoids blocking on bidirectional I/O on a single file descriptor.

### MBIM layer

The script implements a minimal MBIM client:

- **OPEN** / **OPEN_DONE** — negotiate `MaxControlTransfer` size (default 4096 bytes, overridden by `IOCTL_WDM_MAX_COMMAND` ioctl when available)
- **COMMAND** / **COMMAND_DONE** — send service requests
- **CLOSE** / **CLOSE_DONE** — tear down session

### QMI-over-MBIM tunnel (EXT_QMUX)

Qualcomm defines a vendor MBIM service that carries raw QMUX/QMI payloads:

| Property | Value |
|----------|-------|
| Service name | EXT_QMUX |
| UUID | `d1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3` |
| CID | 1 |
| Operation | MBIM Set (type=1) with QMUX buffer as InformationBuffer |
| Response | Raw QMUX response in COMMAND_DONE InformationBuffer |

This tunnel is documented in the [libmbim MBIM protocol notes](https://modemmanager.org/docs/libmbim/mbim-protocol/) and was reverse-engineered for the MC7710 by Bjørn Mork ([Sierra Wireless forum discussion](https://forum.sierrawireless.com/t/my-mc7710-cant-work-on-linux-after-plug-in-it-to-windows8/7986)).

### Sierra Wireless QMI DMS vendor messages

| Message | ID | Direction | TLVs |
|---------|-----|-----------|------|
| SWI Get USB Composition | `0x555B` | Request: none | Response: `0x10` = current (uint8), `0x11` = supported list (count + uint8[]) |
| SWI Set USB Composition | `0x555C` | Request: `0x01` = new index (uint8) | Response: standard QMI result TLV `0x02` |
| SWI Set FCC Authentication | `0x555F` | (referenced in code comments, not implemented) | — |

These messages were added to libqmi in October 2017 ([libqmi-devel patch](https://lists.freedesktop.org/archives/libqmi-devel/2017-October/002504.html)), vendor ID `0x1199` (Sierra Wireless).

### Execution flow

1. Validate `$device` is a character device with `cdc_mbim` driver.
2. `fork()` — child runs `read_mbim()` loop until CLOSE_DONE.
3. Parent sends MBIM OPEN, waits for OPEN_DONE (`0x80000001`).
4. Parent sends QMI_CTL GET_VERSION_INFO (`0x0021`) via EXT_QMUX to verify tunnel works.
5. Parent sends QMI_CTL GET_CLIENT_ID (`0x0022`, TLV `0x01` = DMS service) → stores DMS CID.
6. Parent sends DMS SWI GET USB COMPOSITION (`0x555B`) → prints current + supported list.
7. If `--usbcomp=N` given and valid: sends DMS SWI SET USB COMPOSITION (`0x555C`, TLV `0x01` = N).
8. `quit()`: releases DMS CID (`0x0023`), sends MBIM CLOSE, waits for child exit.

---

## After Changing Composition

A composition change is stored in modem NVRAM but **does not re-enumerate USB interfaces immediately**. You must reset the module:

### Using qmicli (if available after reset)

```bash
sudo qmicli -d /dev/cdc-wdm0 --dms-set-operating-mode=offline
sudo qmicli -d /dev/cdc-wdm0 --dms-set-operating-mode=reset
```

### Using ModemManager

```bash
sudo mmcli -m 0 --reset
```

### Physical reset

- USB disconnect/reconnect
- Module power cycle
- Laptop embedded modem hard reset

After reset, verify with `lsusb`, `mmcli -L`, or run the script again without `--usbcomp` to confirm the new composition is active. You should see additional `/dev/ttyUSB*` ports and/or a `qmi_wwan` interface depending on the chosen mode.

---

## Troubleshooting

### `'/dev/cdc-wdm0' is not a character device`

The MBIM device node does not exist. Check `ls -l /dev/cdc-wdm*` and `dmesg` for USB enumeration errors. The modem may be in QDL/firmware-download mode (PID `0x9070`) instead of runtime mode.

### `only MBIM devices are supported` (wrong driver)

The device is not handled by `cdc_mbim` — it may be in QMI mode (`qmi_wwan`) or serial-only mode. In that case you can use `qmicli` or AT commands directly and do not need this script.

### `Failed to verify QMI vendor specific MBIM service`

The modem's MBIM stack does not expose EXT_QMUX. Run `mbimcli -d /dev/cdc-wdm0 --query-device-services` to confirm. Some non-Qualcomm or heavily locked firmware builds omit this service.

### `USB composition 'N' is not supported`

The firmware only allows a subset of compositions (often 6, 8, and 9 on MC7455/EM7455). The script refuses to send an unsupported value. Use the read-only listing to see what your module reports.

### `Failed to change USB composition`

The QMI request returned an error. Run with `--debug` to inspect the raw response. Common causes: modem busy (stop NetworkManager/ModemManager first), insufficient permissions, or firmware restrictions.

### Composition reverts after reboot

Some units have **USB PID–locked compositions** stored in NV memory. If `qmicli --dms-swi-set-usb-composition` and this script both succeed but the modem returns to MBIM-only, the module may need an NVU profile change. See [MC7455 stuck in MBIM-only USB composition](https://forum.sierrawireless.com/t/mc7455-stuck-in-mbim-only-usb-composition/8499) for advanced recovery (custom NVU files, `parsecwe.pl`, etc.).

### Stop ModemManager from interfering

```bash
sudo systemctl stop ModemManager
# run script
sudo systemctl start ModemManager
```

---

## Alternatives

### qmicli (recommended for most users)

Since libqmi 1.20, the officially supported approach:

```bash
# Query (works in MBIM mode)
sudo qmicli -d /dev/cdc-wdm0 --device-open-mbim --dms-swi-get-usb-composition

# Set
sudo qmicli -d /dev/cdc-wdm0 --device-open-mbim --dms-swi-set-usb-composition=8

# Reset
sudo qmicli -d /dev/cdc-wdm0 --device-open-mbim --dms-set-operating-mode=reset
```

With a recent libqmi, `--device-open-mbim` is often the default when the device is MBIM-capable.

### AT commands (when AT port is available)

```
AT!ENTERCND="A710"       # unlock protected commands (password varies by module)
AT!UDUSBCOMP=?           # list compositions (older modules)
AT!UDUSBCOMP=8           # set composition 8
AT!USBCOMP=?             # list compositions (MC7455/EM7455+)
AT!USBCOMP=1,1,100D      # set via bitmask (diag,nmea,modem,mbim)
AT!RESET
```

### Sierra Wireless tools

- **SWI Connect / Skylight** (Windows) — can change composition via GUI
- **Sierra Linux QMI SDK** — documents `USBCompParams()` / `USBCompConfig()` vendor APIs

---

## References

| Resource | URL |
|----------|-----|
| Original script (Bjørn Mork) | https://git.mork.no/?p=wwan.git;a=blob_plain;f=scripts/swi_setusbcomp.pl |
| libqmi patch adding SWI USB composition support | https://lists.freedesktop.org/archives/libqmi-devel/2017-October/002504.html |
| Author's disclaimer (not a supported tool) | https://lists.freedesktop.org/archives/libqmi-devel/2017-June/002364.html |
| MC7710 MBIM-only recovery (EXT_QMUX discovery) | https://forum.sierrawireless.com/t/my-mc7710-cant-work-on-linux-after-plug-in-it-to-windows8/7986 |
| MC7455 MBIM-only PID lock discussion | https://forum.sierrawireless.com/t/mc7455-stuck-in-mbim-only-usb-composition/8499 |
| Osmocom Sierra Wireless wiki | https://projects.osmocom.org/projects/quectel-modems/wiki/Sierra_Wireless_Modems |
| MBIM protocol + Qualcomm QMI tunnel | https://modemmanager.org/docs/libmbim/mbim-protocol/ |
| qmicli man page | https://www.freedesktop.org/software/libqmi/man/latest/qmicli.1.html |
| AT!UDUSBCOMP reference | https://m2msupport.net/m2msupport/atudusbcomp-set-the-usb-interface-configuration-for-the-sierra-wireless-modems/ |
| Sierra USB customization (Legato) | https://source.sierrawireless.com/resources/legato/howtos/customizeusb/ |
| cdc-wdm device nodes on AOSP | http://paldan.altervista.org/cdc-wdm-support-now-added-in-aosp-hikey/ |
| Quectel Android RIL / ueventd setup | https://www.quectel.com/content/uploads/2024/02/Quectel_Android_RIL_Driver_User_Guide_V2.0-1-4.pdf |
| Termux Perl setup | https://www.perlmonks.org/?node_id=1211709 |
| Termux via adb (`run-as`) | https://android.stackexchange.com/questions/225260/termux-running-termux-via-adb-without-any-direct-interaction-with-the-device |

### Author's note

Bjørn Mork described this script as a *"simple run-once hack"* that was *"never intended to be a tool"*, and wrote: *"I don't recommend it ;-)"*. It has nonetheless proven invaluable for recovering modems stranded in MBIM-only mode and served as the reference implementation for the libqmi vendor commands.

---

## License

**Script:** GPLv2 — Copyright (c) 2015 Bjørn Mork \<bjorn@mork.no\>

**Documentation:** GPLv2 — Copyright (c) 2026 Artem Moroz \<artem.moroz@gmail.com\>
