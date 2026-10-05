# Changelog

All notable changes to the TPVCamera mod will be documented in this file.

## [1.1.0] - Turn Animation and Steadier Camera

- Henry now turns on the spot with the game's own turn animations in third person, and the camera stays still while he turns
- The turn animation is on by default, adjustable in the INI, and switched off automatically in combat, aiming, riding, conversations, minigames and while sitting or lying
- Crouched turns on the spot play cleanly, with no pose glitches and no forward-and-back slide
- If a game update breaks one feature, only that feature turns off and the log names it
- Steadier camera: it no longer sways with Henry's head bob, hits and landings (new StableAimBasis and AimBasisSmoothing options, both on by default)
- The camera no longer ends up inside Henry's head in tight spots such as low doorways, and switches to first person until there is room again
- Fixed nearby people vanishing in third person, such as someone asleep in a house or standing inside a shop
- Smoother camera movement, most noticeable when turning slowly with a controller
- Camera collision against cloth roofs now costs less performance
- Updated the bundled modding toolkit (DetourModKit) to v4.3.0 for extra stability and future compatibility

## [1.0.1] - Compatibility

- Locates everything it hooks at runtime, so it is more likely to keep working across game versions and builds without a mod update

## [1.0.0] - Initial Port

- Raw port of the KCD2 TPVCamera mod to the first Kingdom Come: Deliverance: the same design, INI layout, and in-game preset overlay as the KCD2 mod
- Third-person camera with over-the-shoulder framing, camera collision, automatic view switching by situation (combat, aiming, dialogue, minigames, riding, menus), an in-game preset manager, and an experimental free-look orbit
- Game addresses are located patch-resiliently through AOB cascades plus reverse-RTTI self-healing offsets, so common game updates do not break it before a mod update
- Free-look orbit: KCD1's sprint runs forward-only (unlike KCD2), so a new OrbitSprintFullTurn option (on by default) turns your character to run the way you point while sprinting, on both keyboard and controller
- See the KCD2 mod page for the full feature, control, and configuration details

[1.1.0]: https://github.com/tkhquang/KCD1Tools/releases/tag/TPVCamera-v1.1.0
[1.0.1]: https://github.com/tkhquang/KCD1Tools/releases/tag/TPVCamera-v1.0.1
[1.0.0]: https://github.com/tkhquang/KCD1Tools/releases/tag/TPVCamera-v1.0.0
