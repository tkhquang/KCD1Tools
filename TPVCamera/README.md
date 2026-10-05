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

## Building from Source

Requires Visual Studio 2022 (MSVC) and CMake 3.28+. DetourModKit v4.3.0 is the `external/DetourModKit` submodule; initialize submodules first (the build requires it).

```bash
git submodule update --init --recursive
cmake --preset msvc-release
cmake --build --preset msvc-release
# -> build/release-msvc/KCD1_TPVCamera.asi
```

### Developer hot-reload build (optional)

The `msvc-dev` preset builds DetourModKit's staged-reload pair: a resident loader (`KCD1_TPVCamera.asi`) and the mod logic (`KCD1_TPVCamera.logic.dll`). Set `TPVCAMERA_GAME_DIR` to the game's `Bin/Win64` folder and both deploy there (the preset defaults it to the standard Steam install folder).

```bash
cmake --preset msvc-dev -DTPVCAMERA_GAME_DIR="<game>/Bin/Win64"
cmake --build --preset msvc-dev
```

Rebuild while the game runs, then press **Numpad 0** with the game focused. The loader retires the current generation and loads a uniquely named copy of the new build (`KCD1_TPVCamera.genNNNN.logic.dll`). It records each decision, including the build revision, in `KCD1_TPVCamera.loader.log`. A generation that cannot prove its hooks and workers quiescent stays loaded but inert. The loader never re-initializes it, and asks for a game restart when its retention budget runs out. See DetourModKit's [hot-reload guide](https://github.com/tkhquang/DetourModKit/blob/main/docs/guides/hot-reload/README.md).

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
