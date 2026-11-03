# Presence Lock

ESP32-S3 firmware that locks your Windows PC when your iPhone leaves the room.

- Watches for your iPhone over Bluetooth LE, recognising it through its IRK
  (Identity Resolving Key), so it works even though the phone's address rotates.
- Presses Win+L over USB (the board acts as a keyboard) when the phone goes from
  present to away.
- Reports presence and signal strength to Home Assistant over MQTT (discovery).

The board never listens on the network: no web server, no OTA, no MQTT subscribe.
Settings are changed only over the local USB serial port.

## Hardware

An ESP32-S3 board with native USB, e.g. ESP32-S3-DevKitC-1. Plug in the USB port
that is wired to the S3 (often labelled "USB"), not the UART bridge.

## Build and flash

Needs [PlatformIO](https://platformio.org/).

```powershell
.\flash.ps1
```

The script builds, switches the running firmware into its bootloader, uploads and
resets. If it can't find the board, hold BOOT while plugging it in and run it again.

Optional: copy `include/secrets.example.h` to `include/secrets.h` to bake in Wi-Fi
and MQTT defaults. Settings saved from the settings page take precedence.

## Settings page

Open `ui/index.html` in Edge or Chrome (Web Serial is needed), click **Connect** and
choose the board's serial port. From there you can:

- pair your iPhone (or paste its IRK by hand),
- set the in-room threshold, the margin and the away delay,
- turn locking on or off and test it,
- set Wi-Fi and Home Assistant (MQTT) details.

`ui/open-settings.cmd` serves the same page from `http://127.0.0.1:8765/` if you
prefer that.

## Presence logic

- The phone counts as **in the room** once its smoothed signal reaches the threshold.
- Once in the room, it stays there while the signal is above threshold minus the
  margin, so a signal hovering at the threshold doesn't flicker.
- With no strong reading for the away delay, it goes **away** and the PC locks.
- When it comes back after being gone for at least 30 seconds, the board presses
  Up arrow twice to wake the lock screen.

## Serial commands

Type `help` over the serial port (115200 baud) for the full list: `status`, `watch`,
`enroll`, `irk`, `fixirk`, `threshold`, `margin`, `away`, `lock`, `testlock`, `testwake`, `set`,
`reconnect`.

## License

MIT, see [LICENSE](LICENSE).
