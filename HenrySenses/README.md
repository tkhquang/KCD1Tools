# Kingdom Come: Deliverance - Henry's Senses

A loot and object highlighting mod for Kingdom Come: Deliverance, ported from the KCD2 mod of the same name.

## Overview

Press a key to highlight nearby loot, herbs, creatures and other objects with outlines, including through walls and grass.

The KCD1 version uses the game's own silhouette effect, a CryEngine feature that Kingdom Come: Deliverance still ships but never uses. The KCD2 version has to rebuild that effect; KCD1 only has to switch it on for each object.

> [!NOTE]
> This port is in early development. If something doesn't work properly, please [report it](https://github.com/tkhquang/KCD1Tools/issues) with your game/mod versions, settings and log.

## Features

- Highlight lootable bodies, animal carcasses, dropped items, containers and herbs
- Optional highlighting for living NPCs, animals and interactive objects such as doors, beds and workstations
- Configurable colours, range, duration and hotkeys per highlight group
- Pulse, Toggle, Hold and Always activation modes, with keyboard and controller bindings
- Filters for stolen, empty, locked and other tagged objects, using the game's own loot checks
- Live configuration reload when you save the INI

Set `[Render] SeeThrough = false` to highlight only visible surfaces.

## Installation

Built around **KCD1 Steam 1.9.8**. This is an `.asi` plugin and requires an **ASI loader**, which is **not bundled** in the download.

### Find the installation folder

Open your KC:D installation folder, then open the `Bin/Win64` subfolder that contains **`WHGame.dll`** and `KingdomCome.exe`. On Steam this is:

```text
<KC:D installation folder>/Bin/Win64/
```

Use `WHGame.dll` to identify the correct folder. The loader and mod files go directly into this folder.

### Step 1: Install an ASI loader (once)

If you already have a working ASI loader for KC:D, skip to Step 2. The same loader can load Henry's Senses, TPVCamera and other ASI mods.

Download **one x64** variant of [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) by ThirteenAG:

| Download | When to use it |
| --- | --- |
| [dinput8-x64.zip](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/dinput8-x64.zip) | Usual choice if `dinput8.dll` is unused. |
| [version-x64.zip](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/version-x64.zip) | Alternative when `dinput8.dll` is already used, including by KCSE. |
| [winmm-x64.zip](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/winmm-x64.zip) | Another alternative if `version.dll` is also used or does not load. |

Extract the DLL from the chosen ZIP directly beside `WHGame.dll`. Use the **x64** build, not Win32, and install only one Ultimate ASI Loader variant. Do not overwrite a DLL belonging to another mod.

> **Using [Kingdom Come Script Extender (KCSE)](https://www.nexusmods.com/kingdomcomedeliverance/mods/2244)?** KCSE uses `dinput8.dll`. Keep KCSE's file and install Ultimate ASI Loader as **`version.dll`** or **`winmm.dll`** in the same folder. Choose an unused name from the downloads above; do not rename or replace KCSE's DLL.

### Step 2: Install the mod

Extract the Henry's Senses release archive directly into the **same folder** beside `WHGame.dll` and your loader DLL, without an extra archive-named subfolder.

- `KCD1_HenrySenses.asi` is the mod.
- `KCD1_HenrySenses.ini` contains the settings.
- `KCD1_HenrySenses.particles.xml` supplies optional custom particle effects. Keep it beside the ASI if you use a `HenrySenses.*` effect in a group; no group uses particles by default.

Henry's Senses does not use the `Mods` folder.

```text
Bin/Win64/
|-- WHGame.dll                         (game file, already present)
|-- dinput8.dll                        (ASI loader; see KCSE note above)
|-- KCD1_HenrySenses.asi                (this mod)
|-- KCD1_HenrySenses.ini                (settings)
|-- KCD1_HenrySenses.particles.xml      (optional particle effects)
\-- KCD1_HenrySenses.log                (created when the mod loads)
```

### Step 3: Launch and verify

Launch the game, load a save and press **H** (or hold **RB + press Start**) to highlight loot. **Left Shift + H** (or hold **RB + press Back**) highlights herbs.

Check for `KCD1_HenrySenses.log` beside the ASI. If it is missing, check that the ASI and x64 loader DLL are directly beside `WHGame.dll`, then try another unused loader variant and relaunch.

### Linux / Steam Deck (Wine/Proton)

Add an override for your chosen loader DLL in the game's **Properties -> Launch Options** on Steam:

```text
WINEDLLOVERRIDES="dinput8=n,b" %command%
```

Use `version=n,b` or `winmm=n,b` instead when using that loader name.

## Controls

All keys are rebindable in `KCD1_HenrySenses.ini`. Defaults:

| Action | Keyboard | Controller |
| --- | --- | --- |
| Highlight loot | `H` | Hold `RB` + press `Start` |
| Highlight herbs | `Left Shift + H` | Hold `RB` + press `Back` |

Highlights pulse for **5 seconds**, then fade over **1 second**, within **20 metres**. Loot and Herbs start enabled; the other groups start disabled. The Loot group excludes empty and stolen targets. Highlights hide during **dialogue** by default.

## Configuration

`KCD1_HenrySenses.ini` documents every setting. Each `[Highlight.<Name>]` section is one group with its own targets, filters, colours, hotkey, mode and range; add, remove or rename groups freely. The file reloads when you save it.

## How It Works

The mod runs on the game's main thread after each game update. It scans nearby creatures, items, containers, herbs and interactive objects, classifies them with the game's own loot checks, and applies your groups. A highlighted object gets a colour in its render proxy, and the game's silhouette effect draws the outline and fill. When a highlight ends, the mod clears the colour and puts the effect's settings back.

Herbs, other plants, static scenery and items drawn with the vegetation shader cannot carry that colour. For these, the mod draws an invisible copy of the object each frame with a material the silhouette effect accepts, and the copy carries the outline. The mod also lifts the effect's depth test and its fade near the camera, so outlines show through walls and right up close.

Engine addresses are located through AOB pattern scanning with fallback signatures. Each feature depends only on its own addresses, so a missing signature disables that feature alone.

## Known Limitations

Compared with the KCD2 version:

- **One fill for everything.** The effect draws one interior fill for every highlighted object, so the `Style` of a group only switches the shared fill on or off.
- **No corner brackets or focus.** The `Box` style and the `Focus` darkening have no effect in KCD1.
- **No butchering.** KCD1 has no butcherable carcasses, so there is no Butcher group.
- **Helper triggers.** Interactive spots without a model of their own (wash tubs, benches) cannot be outlined.

## Building from Source

Requires Visual Studio 2022 (MSVC) and CMake 3.28+. DetourModKit v4.3.0 is the `external/DetourModKit` submodule; initialize submodules first.

```bash
git submodule update --init --recursive
cmake --preset msvc-release
cmake --build --preset msvc-release
# -> build/release-msvc/KCD1_HenrySenses.asi
```

### Developer hot-reload build (optional)

The `msvc-dev` preset builds a resident loader (`KCD1_HenrySenses.asi`) and the mod logic (`KCD1_HenrySenses.logic.dll`) that the loader replaces in the running game, following DetourModKit's staged-generation pattern. Set `HENRYSENSES_GAME_DIR` to the game's `Bin/Win64` folder (the preset defaults it to the standard Steam install folder).

```bash
cmake --preset msvc-dev -DHENRYSENSES_GAME_DIR="<game>/Bin/Win64"
cmake --build --preset msvc-dev
```

The build deploys the loader beside the game and stages the logic DLL with its PDB in `staging/`. Release **Numpad 9** while the game window has focus to reload, or create `staging/KCD1_HenrySenses.reload` (for example from a build script) to reload without touching the game. `KCD1_HenrySenses_Loader.log` records each generation and its retirement verdict. A change to `src/dev/` needs a game restart, because the loader itself is never reloaded.

The C++ sources follow DetourModKit's coding conventions ([AGENTS.md](https://github.com/tkhquang/DetourModKit/blob/main/AGENTS.md)).

## Dependencies

- An **ASI loader**, such as [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader) by [**ThirteenAG**](https://github.com/ThirteenAG). It is **not bundled**; install it yourself (see [Installation](#installation)).
- [DetourModKit](https://github.com/tkhquang/DetourModKit) - a lightweight C++ toolkit for game modding (SafetyHook, AOB scanning, logging, configuration).

## Credits

- [ThirteenAG](https://github.com/ThirteenAG) - for the Ultimate ASI Loader
- [cursey](https://github.com/cursey) - for SafetyHook
- [Brodie Thiesfield](https://github.com/brofield) - for SimpleIni
- Warhorse Studios - for Kingdom Come: Deliverance

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
