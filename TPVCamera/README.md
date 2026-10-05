# Kingdom Come: Deliverance - Third Person Camera

A third-person camera mod for the first **Kingdom Come: Deliverance**.

This is a raw port of my KCD2 mod, [Proper Third Person View (TPV Camera)](https://www.nexusmods.com/kingdomcomedeliverance2/mods/3263), to the first game. It is the same mod, design, and INI: only the game and its binary addresses differ. To avoid maintaining two copies of the same documentation, this page stays minimal and points to the KCD2 mod page for the full feature list, controls, and configuration details.

## Installation

This is an `.asi` plugin and requires an **ASI loader**, which is **not bundled** in the download.

### Find the installation folder

Open your KC:D installation folder, then open the `Bin/Win64` subfolder that contains **`WHGame.dll`** and `KingdomCome.exe`. On Steam this is:

```text
<KC:D installation folder>/Bin/Win64/
```

Use `WHGame.dll` to identify the correct folder. The loader and mod files go directly into this folder.

If you previously installed **KCD1_TPVToggle**, remove `KCD1_TPVToggle.asi` and `KCD1_TPVToggle.ini` first. TPVCamera replaces it, and running both camera mods at once will conflict. To keep a backup, move the old ASI outside the game folder or rename its extension to `.asi.bak`.

### Step 1: Install an ASI loader (once)

If you already have a working ASI loader for KC:D, skip to Step 2. The same loader can load TPVCamera and other ASI mods.

Download **one x64** variant of [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) by ThirteenAG:

| Download | When to use it |
| --- | --- |
| [dinput8-x64.zip](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/dinput8-x64.zip) | Usual choice if `dinput8.dll` is unused. |
| [version-x64.zip](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/version-x64.zip) | Alternative when `dinput8.dll` is already used, including by KCSE. |
| [winmm-x64.zip](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/winmm-x64.zip) | Another alternative if `version.dll` is also used or does not load. |

Extract the DLL from the chosen ZIP directly beside `WHGame.dll`. Use the **x64** build, not Win32, and install only one Ultimate ASI Loader variant. Do not overwrite a DLL belonging to another mod.

> **Using [Kingdom Come Script Extender (KCSE)](https://www.nexusmods.com/kingdomcomedeliverance/mods/2244)?** KCSE uses `dinput8.dll`. Keep KCSE's file and install Ultimate ASI Loader as **`version.dll`** or **`winmm.dll`** in the same folder. Choose an unused name from the downloads above; do not rename or replace KCSE's DLL.

### Step 2: Install the mod

Download the TPVCamera release archive from [GitHub Releases](https://github.com/tkhquang/KCD1Tools/releases) or the mod's Nexus Files tab. Extract its contents directly into the **same folder** beside `WHGame.dll` and your loader DLL, without an extra archive-named subfolder.

- `KCD1_TPVCamera.asi` is the mod.
- `KCD1_TPVCamera.ini` contains hotkeys and global settings.
- `KCD1_TPVCamera_presets.json` is created on first run; it is not included in the archive.

TPVCamera does not use the `Mods` folder.

```text
Bin/Win64/
|-- WHGame.dll                         (game file, already present)
|-- dinput8.dll                        (ASI loader; see KCSE note above)
|-- KCD1_TPVCamera.asi                  (this mod)
|-- KCD1_TPVCamera.ini                  (settings)
|-- KCD1_TPVCamera_presets.json         (created on first run)
\-- KCD1_TPVCamera.log                  (created when the mod loads)
```

With KCSE, `dinput8.dll` in this example belongs to KCSE; your chosen ASI loader, `version.dll` or `winmm.dll`, sits alongside it.

### Step 3: Launch and verify

Launch the game; third-person turns on automatically once you reach gameplay. Press **F3** or hold **LB + RB** on a controller to toggle back to first-person.

Check for `KCD1_TPVCamera.log` beside the ASI. If it is missing, check that the ASI and x64 loader DLL are directly beside `WHGame.dll`, then try another unused loader variant and relaunch. Replace only the Ultimate ASI Loader DLL you installed; keep KCSE and other mods' DLLs. On Wine/Proton, also check the override below.

When updating, back up your customized INI before extracting the new archive, then reapply your settings to the supplied INI. Keep `KCD1_TPVCamera_presets.json` to retain your saved camera presets.

### Linux / Steam Deck (Wine/Proton)

Add an override for your chosen loader DLL in the game's **Properties -> Launch Options** on Steam:

```text
WINEDLLOVERRIDES="dinput8=n,b" %command%
```

Use `version=n,b` or `winmm=n,b` instead when using that loader name. If you also use KCSE's `dinput8.dll` with the `version.dll` loader, retain both overrides:

```text
WINEDLLOVERRIDES="dinput8,version=n,b" %command%
```

For a command-line launch, set the same `WINEDLLOVERRIDES` value before your launch command. Keep any overrides your other mods need.

## Controls and configuration

Defaults: toggle third-person `F3` (or hold `LB + RB`), free-look orbit `F4`, preset overlay `Home`. Every key is rebindable and every setting is documented in `KCD1_TPVCamera.ini`.

For the full controls, the per-situation preset system, the collision options, the hotkey format, controller notes, and troubleshooting, see the **KCD2 mod page**: [Proper Third Person View (TPV Camera)](https://www.nexusmods.com/kingdomcomedeliverance2/mods/3263). The two mods share the same INI layout and overlay, so that documentation applies here as well; the only differences are the game (KC:D 1) and the binary folder above.

### Repairing a broken signature

If a game build breaks a feature, the log names the signature that stopped resolving (`Anchor <name> unresolved`) and the feature that turned off (`Feature gate: <name> Fail`). The rest of the mod keeps working. A broken signature can be repaired without a new build of the mod:

1. Set `ExportSignatures = true` in `[Advanced]` and start the game once. The mod writes every built-in signature to `KCD1_TPVCamera.signatures.captured.ini`.
2. Copy the broken `[sig.<name>]` section and its `.rung.<N>` sections into a new `KCD1_TPVCamera.signatures.ini` beside the ASI, under the same `[manifest]` header.
3. Change the `pattern` to match the new game build, and delete the `fingerprint`, `image_identity` and `winning_bytes` lines of that section.
4. A repair of a signature the mod only calls or reads takes effect at the next start. A repair of a hook target also needs its baselines: start the game once more with `ExportSignatures = true`, then copy the repaired section, with its new baseline lines, from the captured file into `KCD1_TPVCamera.signatures.ini`.

The log reports each repair (`Signatures: <name> uses the repair from the signature file`) and refuses one that it cannot trust. A file written for another signature revision is ignored.

## Building from Source

Requires Visual Studio 2022 (MSVC) and CMake 3.28+. DetourModKit v4.3.0 is the `external/DetourModKit` submodule; initialize submodules first (the build requires it).

```bash
git submodule update --init --recursive
cmake --preset msvc-release
cmake --build --preset msvc-release
# -> build/release-msvc/KCD1_TPVCamera.asi
```

### Developer hot-reload build (optional)

The `msvc-dev` preset builds a resident loader (`KCD1_TPVCamera.asi`) and the mod logic (`KCD1_TPVCamera.logic.dll`) that the loader replaces in the running game. It follows DetourModKit's staged-generation pattern ([hot-reload guide](https://github.com/tkhquang/DetourModKit/blob/main/docs/guides/hot-reload/README.md)). Set `TPVCAMERA_GAME_DIR` to the game's `Bin/Win64` folder (the preset defaults it to the standard Steam install folder).

```bash
cmake --preset msvc-dev -DTPVCAMERA_GAME_DIR="<game>/Bin/Win64"
cmake --build --preset msvc-dev
```

The build deploys the loader beside the game and the logic DLL with its PDB to `staging/` in the game folder. Release Numpad 0 while the game window has focus to reload:

1. The live generation's `Shutdown()` joins the mod's threads, disables every hook, waits until no game thread is inside a detour, restores the hooked code, and drains DetourModKit's input and config callbacks. It refuses retirement when any step fails, and the old generation then stays mapped.
2. The loader promotes the staged build and maps a copy under a unique name (`KCD1_TPVCamera.genNNNN.logic.dll`), so a rebuild never collides with a mapped image.
3. A generation that retires with a retained resource stays mapped, within a budget of 32 images and 128 MiB. A full budget or an unproven retirement stops further reloads until the game restarts.

`KCD1_TPVCamera_Loader.log` beside the ASI records each generation, its build identity, and the retirement verdict. A change to `src/dev/protocol.h` or `src/dev/mod_loader.cpp` needs a game restart, because the loader itself is never reloaded.

The C++ sources follow DetourModKit's coding conventions ([AGENTS.md](https://github.com/tkhquang/DetourModKit/blob/main/AGENTS.md)).

## Dependencies

- An **ASI loader**, such as [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader) by [**ThirteenAG**](https://github.com/ThirteenAG). It is **not bundled**; install it yourself (see [Installation](#installation)).
- [DetourModKit](https://github.com/tkhquang/DetourModKit) - a lightweight C++ toolkit for game modding (SafetyHook, AOB scanning, logging, configuration).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Credits

- [ThirteenAG](https://github.com/ThirteenAG) - for the Ultimate ASI Loader
- [cursey](https://github.com/cursey) - for SafetyHook
- [Brodie Thiesfield](https://github.com/brofield) - for SimpleIni
- [Frans 'Otis_Inf' Bouma](https://opm.fransbouma.com/intro.htm) - for his camera tools and inspiration
- Warhorse Studios - for Kingdom Come: Deliverance

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
