# Boot Event Detector

IDA Pro plugin that detects CPU mode transitions, UEFI boot services, and bootloader patterns in firmware binaries.

## Build

```
nmake /f Makefile.msvc clean
nmake /f Makefile.msvc
nmake /f Makefile.msvc install
```

Requires IDA SDK 9.0 and MSVC (Developer Command Prompt).

## Hotkeys

| Key | Action |
|-----|--------|
| `Ctrl+Shift+B` | Open / scan |
| `Ctrl+Shift+R` | Rescan |
| `Ctrl+Shift+F` | Toggle suppressed events |
| `Ctrl+Shift+T` | Timeline |
| `Ctrl+Shift+G` | Graph overlay |
| `Ctrl+Shift+S` | Statistics |
| `Ctrl+Shift+E` | Export JSON |
| `Ctrl+Alt+H` | Export HTML |
| `Ctrl+Alt+D` | Diff |
| `Ctrl+Alt+B` | Add bookmarks |

## Detects

GDT/IDT loads, protected mode entry, paging enable, long mode transitions, A20 gate, BIOS disk reads, video mode switches, E820 memory maps, segment/stack setup, UEFI boot services, UEFI protocol GUIDs, Multiboot headers, PE/COFF images, boot stage classification.