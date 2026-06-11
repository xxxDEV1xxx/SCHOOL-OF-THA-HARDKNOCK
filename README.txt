CTW-11 GNSS COORDINATE MAPPER
Made by Christopher Williams
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

OVERVIEW
â”€â”€â”€â”€â”€â”€â”€â”€
A forensic-grade C/GTK3 application that parses GNSS/NMEA data
files and plots every GPS coordinate found on a pixel-accurate
cartographic grid where 1 screen inch = 1 real mile.

Each coordinate is stored in its own named folder with complete
metadata, raw NMEA records, satellite constellation data, and
RINEX observation blocks.


BUILD REQUIREMENTS
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  â€¢ GCC (C11 or newer)
  â€¢ GTK+ 3 development libraries
  â€¢ pkg-config

  Debian/Ubuntu:   sudo apt-get install libgtk-3-dev build-essential pkg-config
  Fedora/RHEL:     sudo dnf install gtk3-devel gcc pkg-config
  Arch Linux:      sudo pacman -S gtk3 gcc pkg-config


BUILD
â”€â”€â”€â”€â”€
  make

  Or directly:
  gcc -O2 -o ctw11_gnss_mapper ctw11_gnss_mapper.c \
      $(pkg-config --cflags --libs gtk+-3.0) -lm


USAGE
â”€â”€â”€â”€â”€
  ./ctw11_gnss_mapper

  On launch, two dialogs appear in sequence:

  1. Ground Truth Dialog
     â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
     Enter a GPS latitude/longitude. This becomes the green-dot
     center of the map and the reference point for the grid.
     (Default: Perris, CA â€” 33.853000, -117.228000)

  2. Parse Folder Dialog
     â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
     Type the FULL PATH to the folder containing your GNSS data.
     The dialog disappears and parsing begins immediately.

     Recognized files:
       gnss_log.txt    â€” embedded NMEA or CSV (timestamp,lat,lon)
       rnx_data.txt    â€” RINEX 3 observation file
       *.nmea, *.nma   â€” standard NMEA sentence files
       *.rnx, *.obs    â€” RINEX observation files (e.g. .21o)
       *.log, *.txt    â€” generic files scanned for NMEA sentences


MAP CONTROLS
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Left-click on dot        â†’ scrollable detail popup for that coordinate
  Right-click on dot       â†’ context menu: Export / View Detail
  Middle-button drag       â†’ pan the map
  Scroll wheel up/down     â†’ zoom in / zoom out
  Menu â†’ Map â†’ Reset View  â†’ return to center, zoom 1:1


VISUAL DESIGN
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  Background  : 75% translucent black
  Minor grid  : white lines every 1 mile (30% opacity)
  Major grid  : white lines every 5 miles (70% opacity)
  Ground truth: bright green crosshair dot with label
  Data dots   : neon orange outer ring
                white circumference border
                black center dot
  Scale bar   : bottom-left corner, labeled "1 mile"


OUTPUT FOLDER STRUCTURE
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  ./gnss_output/
    <LAT>_<LON>/            â† one folder per unique coordinate
      raw_nmea.txt          â† all raw lines for this coordinate
      metadata.txt          â† full structured field dump
      satellite_info.txt    â† GSV satellite constellation records
      EXPORT_<LAT>_<LON>.txt  â† generated on right-click export


PARSED SENTENCE TYPES
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  GGA   â€” fix data, altitude, HDOP, satellites used
  RMC   â€” position, speed, course, date
  GLL   â€” position, time
  GSV   â€” satellite PRN, elevation, azimuth, SNR
  GSA   â€” DOP values, active satellites
  VTG   â€” course over ground, speed
  RINEX â€” ECEFâ†’geodetic position + epoch observation blocks
  GNSSLOG â€” CSV-embedded coordinates from gnss_log.txt


CHAIN OF CUSTODY
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  All parsed data is written to disk immediately after parsing.
  Raw lines are preserved verbatim. Source file paths are stored
  in every record. Export files are timestamped UTC.


â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
CTW-11 GNSS COORDINATE MAPPER  â€”  Made by Christopher Williams
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
