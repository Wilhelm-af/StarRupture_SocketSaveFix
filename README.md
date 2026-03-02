# Collaboration :D

So we were two idiots starting at this at the same time, Comming up with idea and such to how to solve problems. After some time now https://github.com/AlienXAXS has made a more "Stable" thought thru modloader with this mod implemented that works for both Client And Server. So with that, im deprecating this project and will help AlienXAXS with his projects to have a more uniformed solution to the users out there.

Makeing it simple for people to select one modloader and one place to find mods for everything instead of having to choose between one and another and or using both. Here is the link to the [ModLoader](https://github.com/AlienXAXS/StarRupture-ModLoader) and ill see you there.

# StarRupture — SocketSaveFix

A mod for StarRupture that fixes broken 3-way and 5-way rail junctions so they save and load
correctly between sessions.

> **Note:** This mod prevents new junctions from breaking. It does **not** retroactively fix
> junctions that are already broken. You will need to rebuild or use my [online tool](https://wilhelm-af.github.io/StarRupture-JunctionFixer/)

---

## Installation

Place the mod folder into your `Mods` directory using
[Wilhelm-af's StarRupture ModLoader](https://github.com/Wilhelm-af/StarRupture-ModLoader).

Other mod loaders may work, but are not officially tested or supported.
Add modloaders that are not working in Issues and ill look at them to make it work.

---

## What it fixes

Multi-rail junctions (3-way and 5-way) in StarRupture fail to save their socket/connection state
properly. After a save/load cycle, these junctions break and require manual rebuilding. This mod
patches the save logic to correctly preserve junction states so your rail networks survive
restarts.

---

## Issues or Bugs

If you run into unexpected behavior, please open an issue on the
[GitHub Issues page](https://github.com/Wilhelm-af/StarRupture_SocketSaveFix/issues).
Any and all reports are welcome and appreciated.

---

## Disclaimer

This mod is provided as-is. I have no way of knowing how future game updates may affect its
behavior, and compatibility is not guaranteed across patches.

This mod was made purely to fix a personal annoyance — having to break and rebuild 3-way and
5-way multi-rail/junctions after every session.

As per the [GNU GPL v3 license](LICENSE), I am not liable for any loss of saves, game
instability, or other issues arising from use of this mod.

This mod was **not** made by or in cooperation with CreepyJar (the developers of StarRupture).
They are not responsible for any issues caused by this mod.

---

## Credits

| Role | Person |
|---|---|
| Author | [Wilhelm-af](https://github.com/Wilhelm-af) |
| Collaboration & Big thanks | [@AlienXAXS](https://github.com/AlienXAXS/) |

Huge thanks to [@AlienXAXS](https://github.com/AlienXAXS/) for patiently discussing ways to look at the problem, tips and tools
with me until we cracked it — the best kind of rubber duck debugging.

---

## License

[GNU General Public License v3.0](LICENSE)
