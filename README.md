# UC Browser Bookmark Exporter

Exports your UC Browser `.db` bookmark files to HTML, CSV, JSON, TXT, and SQLite.

## Usage

**GUI**
1. Double-click `UCExport.exe`.
2. Select a `.db` file or folder (or drag and drop it into the window).
3. Check the formats you want and click **Export Selected Formats**.

**Quick Export**
* Drag and drop a `.db` file or folder directly onto `UCExport.exe` in File Explorer to export all formats into the same folder.

**CLI**
```powershell
# Export all formats
UCExport.exe ucbook.db

# Choose output folder and specific formats
UCExport.exe "C:\backups" -o "C:\out" -f html,csv

# Use a custom key
UCExport.exe ucbookmark.db -k <your key>

```

* `-o <dir>`: Output folder (default: same as input).
* `-f <list>`: Formats to save: `html,csv,json,txt,sqlite` (default: `all`).
* `-k <key>`: Custom key (hex or text).

## Build (MSYS2 UCRT64)

Install dependencies:

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-sqlite3

```

Compile:

```bash
windres manifest.rc -o manifest.o

g++ -std=c++20 -O2 -s -static \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    main.cpp manifest.o -o UCExport.exe \
    -lsqlite3 -lcomdlg32 -lshell32 -lole32 -lcomctl32 -lgdi32 -luser32

```

```
