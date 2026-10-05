## Turn Animation and Steadier Camera

- Henry now turns on the spot with the game's own turn animations in third person, and the camera stays still while he turns
- The turn animation is on by default, adjustable in the INI, and switched off automatically in combat, aiming, riding, conversations, minigames and while sitting or lying
- Steadier camera: it no longer sways with Henry's head bob, hits and landings (new StableAimBasis and AimBasisSmoothing options, both on by default)
- The camera no longer ends up inside Henry's head in tight spots such as low doorways, and switches to first person until there is room again
- Fixed nearby people vanishing in third person, such as someone asleep in a house or standing inside a shop
- Smoother camera movement, most noticeable when turning slowly with a controller
- Camera collision against cloth roofs now costs less performance
- Updated the bundled modding toolkit (DetourModKit) to v4.3.0 for extra stability and future compatibility
