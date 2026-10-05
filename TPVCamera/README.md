# Kingdom Come: Deliverance - Third Person Camera

A third-person camera mod for the first **Kingdom Come: Deliverance**.

This is a raw port of my KCD2 mod, [Proper Third Person View (TPV Camera)](https://www.nexusmods.com/kingdomcomedeliverance2/mods/3263), to the first game. It is the same mod, design, and INI: only the game and its binary addresses differ. To avoid maintaining two copies of the same documentation, this page stays minimal and points to the KCD2 mod page for the full feature list, controls, and configuration details.

## Installation

This mod is an `.asi` plugin, so it needs an **ASI loader** to run. The loader is **not bundled** in the download; you install it once yourself (Step 1). If you already have an ASI loader for KC:D from another mod, skip that step.

1. **Install an ASI loader.** Download [Ultimate ASI Loader](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) by **ThirteenAG** and place one of these DLLs in your game's binary folder (the `Bin/Win64` folder that contains `WHGame.dll` and `KingdomCome.exe`):
   - [`dinput8.dll`](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/dinput8-x64.zip) - recommended
   - [`version.dll`](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/version-x64.zip) - alternative if `dinput8.dll` does not work
   - [`winmm.dll`](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/winmm-x64.zip) - another alternative

   Each link downloads a ZIP; extract just the DLL next to `WHGame.dll`.
2. **Install the mod.** Extract all files from this mod's archive into that **same** binary folder (next to `WHGame.dll` and the loader DLL). On Steam this is `<KC:D installation folder>/Bin/Win64/`.
3. **Launch and play.** Third-person turns on automatically once you reach gameplay. Press `F3` (default), or hold `LB + RB` on a controller, to toggle back to first-person.

To check the loader is working, launch once and look for a `KCD1_TPVCamera.log` file in the binary folder. If it is missing, the loader is not loading the mod; try the other loader DLL above (rename it if needed) and relaunch.

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
