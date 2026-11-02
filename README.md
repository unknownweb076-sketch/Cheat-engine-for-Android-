# MemScan — Android app memory debugger (arm64)

Root-assisted memory inspection for an installed Android app selected in the app picker. Use it only with apps you own or have explicit permission to test, and keep game testing offline. Android root access, SELinux policy, and process protections may still prevent attachment.

## Features
- Magisk root-shell startup and installed-app process selection
- Numeric scans: byte, word, dword, qword, float, double
- Refinement: equals, not equal, greater, less, changed, unchanged, increased, decreased
- Result listing, numeric value writes, freeze/unfreeze, and a 1–64 byte hex editor for String/AOB hits
- UTF-8 string search (up to 256 bytes)
- AOB byte-pattern search with `??` wildcards (example: `48 8B ?? 24`)
- Pointer inspection and single-level pointer-reference scan (64-bit aligned pointers)
- Optional floating MemScan launcher chip; Android's "display over other apps" permission is required
- GitHub Actions debug APK build

## Build
Push to GitHub. Actions uploads `MemScan-debug-apk` under the workflow run's artifacts.

## Install and use
1. Build/install the debug APK on an arm64 Android device.
2. Open MemScan and grant root when Magisk prompts.
3. Tap **Choose target app**, then select an installed app you own or are authorized to test.
4. Use numeric, String, AOB, and Pointer controls. Tap a String/AOB hit to open the byte editor. Pointer scan is a single-level reference search, not a multi-level pointer-chain resolver.
5. Tap **Overlay** and grant Android's overlay permission to show the floating launcher. Tap the chip to reopen MemScan; long-press it to dismiss.

## Limitations
- arm64 and root required; Android versions and OEM security policy may restrict `/proc/<pid>/mem`
- The app picker exposes installed launchable apps; successful attachment still depends on root permissions and Android process protections
- String/AOB/pointer results are capped at 500 matches per scan; dialogs display at most 100
- The overlay is a floating launcher, not a full floating memory editor
- No universal speed hack, anti-cheat bypass, or online-game modification
- C syntax can be checked locally; a full Gradle/Android APK build and on-device runtime test still need to be run in GitHub Actions/device environment
