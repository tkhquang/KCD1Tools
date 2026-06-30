# Changelog

All notable changes to the TPVCamera mod will be documented in this file.

## [1.0.1] - Compatibility

- Locates everything it hooks at runtime, so it is more likely to keep working across game versions and builds without a mod update

## [1.0.0] - Initial Port

- Raw port of the KCD2 TPVCamera mod to the first Kingdom Come: Deliverance: the same design, INI layout, and in-game preset overlay as the KCD2 mod
- Third-person camera with over-the-shoulder framing, camera collision, automatic view switching by situation (combat, aiming, dialogue, minigames, riding, menus), an in-game preset manager, and an experimental free-look orbit
- Game addresses are located patch-resiliently through AOB cascades plus reverse-RTTI self-healing offsets, so common game updates do not break it before a mod update
- Free-look orbit: KCD1's sprint runs forward-only (unlike KCD2), so a new OrbitSprintFullTurn option (on by default) turns your character to run the way you point while sprinting, on both keyboard and controller
- See the KCD2 mod page for the full feature, control, and configuration details

[1.0.1]: https://github.com/tkhquang/KCD1Tools/releases/tag/TPVCamera-v1.0.1
[1.0.0]: https://github.com/tkhquang/KCD1Tools/releases/tag/TPVCamera-v1.0.0
