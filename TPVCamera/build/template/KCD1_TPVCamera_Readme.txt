KINGDOM COME: DELIVERANCE - THIRD PERSON CAMERA
Version 1.0.1

A raw port of the KCD2 mod "Proper Third Person View (TPV Camera)" to the first
Kingdom Come: Deliverance. It is the same mod and INI; only the game and its binary
addresses differ. For the full feature, control, and configuration
details, see the KCD2 mod page:
https://www.nexusmods.com/kingdomcomedeliverance2/mods/3263

This mod is an .asi plugin, so it needs an ASI loader to run. The loader is NOT
included in this download - you install it once, yourself (see Step 1). If you
already have an ASI loader for KC:D from another mod, skip Step 1.

INSTALLATION

Find the installation folder:
  Open your KC:D installation folder, then the Bin/Win64 subfolder that contains
  WHGame.dll and KingdomCome.exe. On Steam:
    <KC:D installation folder>/Bin/Win64/
  Use WHGame.dll to identify the correct folder. The loader and mod files go
  directly into this folder.

  If you previously installed KCD1_TPVToggle, remove KCD1_TPVToggle.asi and
  KCD1_TPVToggle.ini first. Running both camera mods at once will conflict.
  To keep a backup, move the old ASI outside the game folder or rename its
  extension to .asi.bak.

Step 1 - Install an ASI loader (one time):
  If you already have a working ASI loader, skip to Step 2. The same loader can
  load TPVCamera and other ASI mods.
  Download ONE x64 variant of Ultimate ASI Loader by ThirteenAG:
    - dinput8.dll  (usual choice if this name is unused)
        https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/dinput8-x64.zip
    - version.dll  (alternative when dinput8.dll is used, including by KCSE)
        https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/version-x64.zip
    - winmm.dll    (alternative if version.dll is used or does not load)
        https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases/download/x64-latest/winmm-x64.zip
  Extract the DLL from the chosen ZIP directly beside WHGame.dll. Use x64, not
  Win32, and install only one Ultimate ASI Loader variant. Do not overwrite a
  DLL belonging to another mod.
  All loader variants: https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases

  USING KINGDOM COME SCRIPT EXTENDER (KCSE)?
  KCSE uses dinput8.dll. Keep KCSE's file and install Ultimate ASI Loader as
  version.dll or winmm.dll in the same folder. Choose an unused name from the
  downloads above; do not rename or replace KCSE's DLL.
  KCSE: https://www.nexusmods.com/kingdomcomedeliverance/mods/2244

Step 2 - Install the mod:
  Extract this archive directly into that SAME binary folder, next to WHGame.dll
  and the loader DLL, without an extra archive-named subfolder.
  KCD1_TPVCamera.asi is the mod; KCD1_TPVCamera.ini contains the settings.
  KCD1_TPVCamera_presets.json is created on first run, not included in the archive.
  Nothing goes into the Mods folder.

Step 3 - Launch and play:
  Start the game; third-person turns on automatically once you reach gameplay.
  Press F3 (default), or hold LB + RB on a controller, to toggle first/third person.

VERIFY THE LOADER IS WORKING:
  After launching once, look for KCD1_TPVCamera.log beside the ASI.
  If it is missing, check that the ASI and x64 loader DLL are directly beside
  WHGame.dll, then try another unused loader variant and relaunch. Replace only
  the Ultimate ASI Loader DLL you installed; keep KCSE and other mods' DLLs.
  On Wine/Proton, also check the override below.

FOLDER LAYOUT (Steam):
  Bin/Win64/
  |-- WHGame.dll                         (game file, already present)
  |-- dinput8.dll                        (ASI loader; see KCSE note above)
  |-- KCD1_TPVCamera.asi                  (this mod)
  |-- KCD1_TPVCamera.ini                  (settings)
  |-- KCD1_TPVCamera_presets.json         (created on first run)
  \-- KCD1_TPVCamera.log                  (created when the mod loads)
  With KCSE, dinput8.dll belongs to KCSE; your ASI loader, version.dll or
  winmm.dll, sits alongside it.

UPDATING:
  Back up your customized INI before extracting the new archive, then reapply
  your settings to the supplied INI. Keep KCD1_TPVCamera_presets.json to retain
  your saved camera presets.

LINUX / STEAM DECK (WINE/PROTON):
  In Steam's Properties -> Launch Options, add an override for your loader:
    WINEDLLOVERRIDES="dinput8=n,b" %command%
  Use version=n,b or winmm=n,b instead when using that loader name. With KCSE's
  dinput8.dll and the version.dll loader, retain both overrides:
    WINEDLLOVERRIDES="dinput8,version=n,b" %command%
  For a command-line launch, set the same WINEDLLOVERRIDES value before your
  launch command. Keep any overrides your other mods need.

Hotkeys and settings are in KCD1_TPVCamera.ini. Full details and support:
https://github.com/tkhquang/KCD1Tools
