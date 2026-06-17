# Kingdom Come: Deliverance - Third Person Camera

A third-person camera mod for the first **Kingdom Come: Deliverance**.

This is a raw port of my KCD2 mod, [Proper Third Person View (TPV Camera)](https://www.nexusmods.com/kingdomcomedeliverance2/mods/3263),
to the first game. It is the same mod, design, and INI: only the game and its binary
addresses differ. To avoid maintaining two copies of the same documentation, this page
stays minimal and points to the KCD2 mod page for the full feature list, controls, and
configuration details.

## Installation

This mod is an `.asi` plugin, so it needs an **ASI loader** to run. The loader is **not
bundled** in the download; you install it once yourself (Step 1). If you already have an
ASI loader for KC:D from another mod, skip that step.

1. **Install an ASI loader.** Download [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases)
   by **ThirteenAG** and place one of these DLLs in your game's binary folder (the
   `Bin/Win64` folder that contains `WHGame.dll` and `KingdomCome.exe`):
   - [`dinput8.dll`](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/dinput8-x64.zip) - recommended
   - [`version.dll`](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/version-x64.zip) - alternative if `dinput8.dll` does not work
   - [`winmm.dll`](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/winmm-x64.zip) - another alternative

   Each link downloads a ZIP; extract just the DLL next to `WHGame.dll`.
2. **Install the mod.** Extract all files from this mod's archive into that **same** binary
   folder (next to `WHGame.dll` and the loader DLL). On Steam this is
   `<KC:D installation folder>/Bin/Win64/`.
3. **Launch and play.** Third-person turns on automatically once you reach gameplay. Press
   `F3` (default), or hold `LB + RB` on a controller, to toggle back to first-person.

To check the loader is working, launch once and look for a `KCD1_TPVCamera.log` file in the
binary folder. If it is missing, the loader is not loading the mod; try the other loader
DLL above (rename it if needed) and relaunch.

## Controls and configuration

Defaults: toggle third-person `F3` (or hold `LB + RB`), free-look orbit `F4`, preset overlay
`Home`. Every key is rebindable and every setting is documented in `KCD1_TPVCamera.ini`.

For the full controls, the per-situation preset system, the collision options, the hotkey
format, controller notes, and troubleshooting, see the **KCD2 mod page**:
[Proper Third Person View (TPV Camera)](https://www.nexusmods.com/kingdomcomedeliverance2/mods/3263).
The two mods share the same INI layout and overlay, so that documentation applies here as
well; the only differences are the game (KC:D 1) and the binary folder above.

## Building from Source

Requires Visual Studio 2022 (MSVC) and CMake 3.28+. DetourModKit is reused from the sibling
checkout until a per-mod `external/DetourModKit` submodule is added; initialize submodules
first or pass `-DKCD1_DMK_DIR=<path>`.

```bash
git submodule update --init --recursive
cmake --preset msvc-release
cmake --build --preset msvc-release
# -> build/release-msvc/KCD1_TPVCamera.asi
```

The C++ sources follow DetourModKit's coding conventions
([AGENTS.md](https://github.com/tkhquang/DetourModKit/blob/main/AGENTS.md)).

## Dependencies

- An **ASI loader**, such as [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader)
  by [**ThirteenAG**](https://github.com/ThirteenAG). It is **not bundled**; install it
  yourself (see [Installation](#installation)).
- [DetourModKit](https://github.com/tkhquang/DetourModKit) - a lightweight C++ toolkit for
  game modding (SafetyHook, AOB scanning, logging, configuration).

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
