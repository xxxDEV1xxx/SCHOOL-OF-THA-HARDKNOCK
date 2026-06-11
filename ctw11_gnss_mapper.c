/*
 * ============================================================
 *  CTW-11 GNSS COORDINATE MAPPER
 *  Made by Christopher Williams
 * ============================================================
 *  Grid scale : 1 inch = 1 mile  (pixel-accurate to screen DPI)
 *  Background : 75% translucent black
 *  Grid lines : white (minor 1-mile, major 5-mile)
 *  Ground truth: bright-green crosshair dot (center of map)
 *  Data dots   : neon-orange, white border, black center
 *
 *  Parses:  gnss_log.txt, rnx_data.txt, *.nmea, *.rnx, *.obs
 *  Stores:  per-coordinate folders with full record metadata
 *
 *  Build:
 *    gcc -O2 -o ctw11_gnss_mapper ctw11_gnss_mapper.c \
 *        $(pkg-config --cflags --libs gtk+-3.0) -lm
 *
 *  Controls:
 *    Left-click dot   → scrollable detail popup
 *    Right-click dot  → context menu → export to file
 *    Middle-drag      → pan map
 *    Scroll wheel     → zoom in/out
 *    Menu → File → Parse GNSS Folder…  (folder path dialog)
 *    Menu → Map  → Set Ground Truth…   (GPS reference point)
 * ============================================================
 */

#include <gtk/gtk.h>
#include <cairo.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

/* ─── Constants ─────────────────────────────────────────────────────────── */

#define MAX_COORDS       8192
#define MAX_LINE         2048
#define MAX_REC_PER_COORD 2048
#define MAX_FIELDS        64
#define DOT_RADIUS        9.0
#define HIT_RADIUS        14.0

#define APP_TITLE \
    "CTW-11 GNSS Coordinate Mapper  —  Made by Christopher Williams"

/* ─── Types ──────────────────────────────────────────────────────────────── */

typedef struct {
    char raw_line[MAX_LINE];
    char sentence_type[16];
    char timestamp[24];
    char date[16];
    char fix_quality[8];
    char satellites[8];
    char hdop[16];
    char altitude[24];
    char alt_unit[8];
    char speed_kts[24];
    char course_deg[24];
    char mag_var[16];
    /* GSV satellite constellation */
    char sv_prn[512];
    char sv_elev[512];
    char sv_azim[512];
    char sv_snr[512];
    /* RINEX observation fields */
    char rinex_epoch[64];
    char rinex_obs[1024];
    /* provenance */
    char source_file[512];
} NMEARecord;

typedef struct {
    double lat;
    double lon;
    char   key[64];          /* "LAT_LON" canonical string */
    char   folder[1024];     /* output directory for this coord */
    NMEARecord *recs;        /* heap array */
    int    rec_count;
    int    rec_cap;
} GPSCoord;

/* ─── Globals ────────────────────────────────────────────────────────────── */

static GPSCoord  *coords      = NULL;
static int        coord_count = 0;
static int        coord_cap   = 0;

/* Map state */
static double SCREEN_DPI      = 96.0;   /* detected at runtime */
static double ground_lat      = 33.8530;
static double ground_lon      = -117.2280;
static double pan_x           = 0.0;
static double pan_y           = 0.0;
static double zoom_level      = 1.0;

/* Drag state */
static gboolean dragging      = FALSE;
static double   drag_sx, drag_sy, drag_px, drag_py;

/* Widgets */
static GtkWidget *main_window   = NULL;
static GtkWidget *drawing_area  = NULL;
static GtkWidget *popup_window  = NULL;

static char output_base[1024]   = "./gnss_output";

/* ─── Utilities ──────────────────────────────────────────────────────────── */

static void make_dir_p(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void trim_crlf(char *s)
{
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r'))
        s[--n] = '\0';
}

/* Split CSV into fields; returns field count */
static int csv_split(char *buf, char **fields, int max_fields)
{
    int n = 0;
    char *p = buf;
    while (n < max_fields) {
        fields[n++] = p;
        p = strchr(p, ',');
        if (!p) break;
        *p++ = '\0';
    }
    return n;
}

/* NMEA DDmm.mmmm → decimal degrees */
static double nmea_to_dd(const char *val, const char *dir)
{
    if (!val || strlen(val) < 4) return 0.0;
    double raw = atof(val);
    int    deg = (int)(raw / 100);
    double min = raw - deg * 100.0;
    double dd  = deg + min / 60.0;
    if (dir && (dir[0] == 'S' || dir[0] == 'W')) dd = -dd;
    return dd;
}

/* ECEF → geodetic (WGS-84 approximate) */
static void ecef_to_lla(double x, double y, double z,
                         double *lat_deg, double *lon_deg, double *alt_m)
{
    double a  = 6378137.0;
    double e2 = 0.00669437999014;
    double p  = sqrt(x*x + y*y);
    double th = atan2(z * a, p * (a * sqrt(1-e2)));
    *lon_deg  = atan2(y, x) * 180.0 / M_PI;
    *lat_deg  = atan2(z + e2/(1-e2) * a * pow(sin(th),3),
                      p - e2 * a * pow(cos(th),3)) * 180.0 / M_PI;
    double N  = a / sqrt(1 - e2 * pow(sin(*lat_deg * M_PI/180.0), 2));
    *alt_m    = p / cos(*lat_deg * M_PI/180.0) - N;
}

/* ─── Coordinate Storage ─────────────────────────────────────────────────── */

static GPSCoord *get_or_create_coord(double lat, double lon)
{
    char key[64];
    snprintf(key, sizeof(key), "%.6f_%.6f", lat, lon);

    for (int i = 0; i < coord_count; i++)
        if (strcmp(coords[i].key, key) == 0)
            return &coords[i];

    /* grow array */
    if (coord_count >= coord_cap) {
        coord_cap = coord_cap ? coord_cap * 2 : 256;
        coords = realloc(coords, coord_cap * sizeof(GPSCoord));
        if (!coords) { fprintf(stderr, "OOM\n"); exit(1); }
    }

    GPSCoord *c = &coords[coord_count++];
    memset(c, 0, sizeof(*c));
    c->lat = lat;
    c->lon = lon;
    strncpy(c->key, key, sizeof(c->key)-1);
    snprintf(c->folder, sizeof(c->folder), "%s/%s", output_base, key);
    make_dir_p(c->folder);
    return c;
}

static void push_record(GPSCoord *c, NMEARecord *r)
{
    if (!c) return;
    if (c->rec_count >= c->rec_cap) {
        c->rec_cap = c->rec_cap ? c->rec_cap * 2 : 64;
        c->recs = realloc(c->recs, c->rec_cap * sizeof(NMEARecord));
        if (!c->recs) { fprintf(stderr, "OOM rec\n"); exit(1); }
    }
    c->recs[c->rec_count++] = *r;
}

/* ─── NMEA Parser ────────────────────────────────────────────────────────── */

/* Global GSV accumulator (flushed on next GGA/RMC with position) */
static char gsv_prn[512]  = "";
static char gsv_elev[512] = "";
static char gsv_azim[512] = "";
static char gsv_snr[512]  = "";
static double last_lat = 0, last_lon = 0;

static void accum_gsv_field(char *buf, size_t sz, const char *val)
{
    if (val && strlen(val)) {
        strncat(buf, val, sz - strlen(buf) - 2);
        strncat(buf, " ", 2);
    }
}

static void parse_nmea_line(const char *line, const char *src)
{
    char buf[MAX_LINE];
    strncpy(buf, line, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    /* Strip optional checksum  *XX */
    char *ast = strrchr(buf, '*');
    if (ast) *ast = '\0';

    char *fields[MAX_FIELDS];
    int   nf = csv_split(buf, fields, MAX_FIELDS);
    if (nf < 1) return;

    const char *sent = fields[0];

    NMEARecord rec;
    memset(&rec, 0, sizeof(rec));
    strncpy(rec.raw_line,    line, sizeof(rec.raw_line)-1);
    strncpy(rec.source_file, src,  sizeof(rec.source_file)-1);

    /* ── GGA ─────────────────────────────────────────── */
    if (strstr(sent, "GGA") && nf >= 10) {
        strncpy(rec.sentence_type, "GGA", 4);
        if (nf > 1)  strncpy(rec.timestamp,   fields[1], sizeof(rec.timestamp)-1);
        if (nf > 6)  strncpy(rec.fix_quality,  fields[6], sizeof(rec.fix_quality)-1);
        if (nf > 7)  strncpy(rec.satellites,   fields[7], sizeof(rec.satellites)-1);
        if (nf > 8)  strncpy(rec.hdop,         fields[8], sizeof(rec.hdop)-1);
        if (nf > 9)  strncpy(rec.altitude,     fields[9], sizeof(rec.altitude)-1);
        if (nf > 10) strncpy(rec.alt_unit,     fields[10],sizeof(rec.alt_unit)-1);

        if (nf > 4 && fields[2][0]) {
            double lat = nmea_to_dd(fields[2], nf>3 ? fields[3] : "N");
            double lon = nmea_to_dd(fields[4], nf>5 ? fields[5] : "E");
            if (lat != 0.0 || lon != 0.0) {
                last_lat = lat; last_lon = lon;
                strncpy(rec.sv_prn,  gsv_prn,  sizeof(rec.sv_prn)-1);
                strncpy(rec.sv_elev, gsv_elev, sizeof(rec.sv_elev)-1);
                strncpy(rec.sv_azim, gsv_azim, sizeof(rec.sv_azim)-1);
                strncpy(rec.sv_snr,  gsv_snr,  sizeof(rec.sv_snr)-1);
                push_record(get_or_create_coord(lat, lon), &rec);
            }
        }
    }
    /* ── RMC ─────────────────────────────────────────── */
    else if (strstr(sent, "RMC") && nf >= 9) {
        strncpy(rec.sentence_type, "RMC", 4);
        if (nf > 1) strncpy(rec.timestamp,  fields[1], sizeof(rec.timestamp)-1);
        if (nf > 7) strncpy(rec.speed_kts,  fields[7], sizeof(rec.speed_kts)-1);
        if (nf > 8) strncpy(rec.course_deg, fields[8], sizeof(rec.course_deg)-1);
        if (nf > 9) strncpy(rec.date,       fields[9], sizeof(rec.date)-1);

        if (nf > 5 && fields[3][0]) {
            double lat = nmea_to_dd(fields[3], fields[4]);
            double lon = nmea_to_dd(fields[5], fields[6]);
            if (lat != 0.0 || lon != 0.0) {
                last_lat = lat; last_lon = lon;
                push_record(get_or_create_coord(lat, lon), &rec);
            }
        }
    }
    /* ── GLL ─────────────────────────────────────────── */
    else if (strstr(sent, "GLL") && nf >= 5) {
        strncpy(rec.sentence_type, "GLL", 4);
        if (nf > 5) strncpy(rec.timestamp, fields[5], sizeof(rec.timestamp)-1);
        if (fields[1][0]) {
            double lat = nmea_to_dd(fields[1], fields[2]);
            double lon = nmea_to_dd(fields[3], fields[4]);
            if (lat != 0.0 || lon != 0.0) {
                last_lat = lat; last_lon = lon;
                push_record(get_or_create_coord(lat, lon), &rec);
            }
        }
    }
    /* ── GSV (satellite constellation) ──────────────── */
    else if (strstr(sent, "GSV")) {
        strncpy(rec.sentence_type, "GSV", 4);
        for (int i = 4; i + 3 < nf; i += 4) {
            accum_gsv_field(gsv_prn,  sizeof(gsv_prn),  fields[i]);
            accum_gsv_field(gsv_elev, sizeof(gsv_elev), fields[i+1]);
            accum_gsv_field(gsv_azim, sizeof(gsv_azim), fields[i+2]);
            accum_gsv_field(gsv_snr,  sizeof(gsv_snr),  fields[i+3]);
        }
        /* attach to last known position */
        if (last_lat != 0.0 || last_lon != 0.0)
            push_record(get_or_create_coord(last_lat, last_lon), &rec);
    }
    /* ── GSA (DOP + active sats) ─────────────────────── */
    else if (strstr(sent, "GSA")) {
        strncpy(rec.sentence_type, "GSA", 4);
        if (last_lat != 0.0 || last_lon != 0.0)
            push_record(get_or_create_coord(last_lat, last_lon), &rec);
    }
    /* ── VTG (course/speed) ──────────────────────────── */
    else if (strstr(sent, "VTG") && nf >= 9) {
        strncpy(rec.sentence_type, "VTG", 4);
        if (nf > 1) strncpy(rec.course_deg, fields[1], sizeof(rec.course_deg)-1);
        if (nf > 7) strncpy(rec.speed_kts,  fields[7], sizeof(rec.speed_kts)-1);
        if (last_lat != 0.0 || last_lon != 0.0)
            push_record(get_or_create_coord(last_lat, last_lon), &rec);
    }
}

static void parse_nmea_file(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);
        if (strlen(line) < 6) continue;
        if (line[0] == '$')
            parse_nmea_line(line, filepath);
    }
    fclose(f);
}

/* ─── RINEX 3 Parser (observation file) ──────────────────────────────────── */

static void parse_rinex_file(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    char   line[MAX_LINE];
    int    in_header   = 1;
    double approx_lat  = 0.0, approx_lon = 0.0, approx_alt = 0.0;
    char   epoch[64]   = "";
    char   obs_buf[1024] = "";

    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);

        if (in_header) {
            if (strstr(line, "END OF HEADER")) { in_header = 0; continue; }
            if (strstr(line, "APPROX POSITION XYZ")) {
                double x = 0, y = 0, z = 0;
                sscanf(line, "%lf %lf %lf", &x, &y, &z);
                if (x || y || z)
                    ecef_to_lla(x, y, z, &approx_lat, &approx_lon, &approx_alt);
            }
            continue;
        }

        /* Epoch record starts with '>' */
        if (line[0] == '>') {
            /* flush previous epoch */
            if ((approx_lat || approx_lon) && epoch[0] && obs_buf[0]) {
                NMEARecord rec;
                memset(&rec, 0, sizeof(rec));
                strncpy(rec.sentence_type, "RINEX",       6);
                strncpy(rec.rinex_epoch,   epoch,         sizeof(rec.rinex_epoch)-1);
                strncpy(rec.rinex_obs,     obs_buf,       sizeof(rec.rinex_obs)-1);
                strncpy(rec.source_file,   filepath,      sizeof(rec.source_file)-1);
                snprintf(rec.altitude, sizeof(rec.altitude), "%.2f", approx_alt);
                strncpy(rec.alt_unit, "m", 2);
                push_record(get_or_create_coord(approx_lat, approx_lon), &rec);
            }
            strncpy(epoch, line + 2, sizeof(epoch)-1);
            obs_buf[0] = '\0';
        } else {
            /* observation line */
            strncat(obs_buf, line,  sizeof(obs_buf) - strlen(obs_buf) - 3);
            strncat(obs_buf, " | ", 4);
        }
    }
    /* flush final epoch */
    if ((approx_lat || approx_lon) && epoch[0] && obs_buf[0]) {
        NMEARecord rec;
        memset(&rec, 0, sizeof(rec));
        strncpy(rec.sentence_type, "RINEX",  6);
        strncpy(rec.rinex_epoch,   epoch,    sizeof(rec.rinex_epoch)-1);
        strncpy(rec.rinex_obs,     obs_buf,  sizeof(rec.rinex_obs)-1);
        strncpy(rec.source_file,   filepath, sizeof(rec.source_file)-1);
        push_record(get_or_create_coord(approx_lat, approx_lon), &rec);
    }
    fclose(f);
}

/* ─── gnss_log.txt Parser ────────────────────────────────────────────────── */

static void parse_gnss_log(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);
        if (!line[0]) continue;

        /* Embedded NMEA sentence */
        char *nmea = strstr(line, "$G");
        if (!nmea) nmea = strstr(line, "$P");
        if (nmea) {
            parse_nmea_line(nmea, filepath);
            continue;
        }

        /* CSV-style:  timestamp,lat,lon[,...] */
        double lat, lon;
        char   ts[32] = "";
        int matched = sscanf(line, "%31[^,],%lf,%lf", ts, &lat, &lon);
        if (matched == 3 && fabs(lat) <= 90.0 && fabs(lon) <= 180.0) {
            NMEARecord rec;
            memset(&rec, 0, sizeof(rec));
            strncpy(rec.sentence_type, "GNSSLOG", 8);
            strncpy(rec.timestamp,     ts,        sizeof(rec.timestamp)-1);
            strncpy(rec.raw_line,      line,      sizeof(rec.raw_line)-1);
            strncpy(rec.source_file,   filepath,  sizeof(rec.source_file)-1);
            push_record(get_or_create_coord(lat, lon), &rec);
        }
    }
    fclose(f);
}

/* ─── Folder Scanner ─────────────────────────────────────────────────────── */

static int ext_is(const char *name, const char *ext)
{
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    return strcasecmp(dot, ext) == 0;
}

static int is_nmea_file(const char *name)
{
    return ext_is(name, ".nmea") || ext_is(name, ".nma") ||
           ext_is(name, ".log")  || ext_is(name, ".txt");
}

static int is_rinex_file(const char *name)
{
    if (ext_is(name, ".rnx") || ext_is(name, ".obs")) return 1;
    const char *dot = strrchr(name, '.');
    /* RINEX obs: e.g. site001s.21o */
    if (dot && strlen(dot) == 3 && tolower((unsigned char)dot[2]) == 'o') return 1;
    return 0;
}

static void scan_folder(const char *folder)
{
    char path[2048];

    /* Known filenames first */
    snprintf(path, sizeof(path), "%s/gnss_log.txt", folder);
    parse_gnss_log(path);

    snprintf(path, sizeof(path), "%s/rnx_data.txt", folder);
    parse_rinex_file(path);

    /* Scan all other files */
    DIR *dir = opendir(folder);
    if (!dir) {
        fprintf(stderr, "[CTW-11] Cannot open folder: %s\n", folder);
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.') continue;
        /* skip already-parsed known files */
        if (strcmp(ent->d_name, "gnss_log.txt") == 0) continue;
        if (strcmp(ent->d_name, "rnx_data.txt")  == 0) continue;

        snprintf(path, sizeof(path), "%s/%s", folder, ent->d_name);

        if (is_rinex_file(ent->d_name))
            parse_rinex_file(path);
        else if (is_nmea_file(ent->d_name))
            parse_nmea_file(path);
    }
    closedir(dir);
}

/* ─── Persist per-coord data to disk ─────────────────────────────────────── */

static void save_coord_data(GPSCoord *c)
{
    if (!c) return;
    char fpath[2048];

    /* raw_nmea.txt */
    snprintf(fpath, sizeof(fpath), "%s/raw_nmea.txt", c->folder);
    FILE *f = fopen(fpath, "w");
    if (f) {
        fprintf(f, "# RAW RECORDS  %.6f, %.6f\n\n", c->lat, c->lon);
        for (int i = 0; i < c->rec_count; i++)
            fprintf(f, "%s\n", c->recs[i].raw_line);
        fclose(f);
    }

    /* metadata.txt */
    snprintf(fpath, sizeof(fpath), "%s/metadata.txt", c->folder);
    f = fopen(fpath, "w");
    if (f) {
        fprintf(f,
            "====================================================\n"
            "  CTW-11 GNSS Mapper — Coordinate Metadata\n"
            "  Made by Christopher Williams\n"
            "====================================================\n"
            "  Lat:     %.8f\n"
            "  Lon:     %.8f\n"
            "  Records: %d\n"
            "====================================================\n\n",
            c->lat, c->lon, c->rec_count);

        for (int i = 0; i < c->rec_count; i++) {
            NMEARecord *r = &c->recs[i];
            fprintf(f, "--- Record %d [%s] ---\n", i+1, r->sentence_type);
            if (r->timestamp[0])   fprintf(f, "  Time:     %s\n", r->timestamp);
            if (r->date[0])        fprintf(f, "  Date:     %s\n", r->date);
            if (r->fix_quality[0]) fprintf(f, "  Fix:      %s\n", r->fix_quality);
            if (r->satellites[0])  fprintf(f, "  Sats:     %s\n", r->satellites);
            if (r->hdop[0])        fprintf(f, "  HDOP:     %s\n", r->hdop);
            if (r->altitude[0])    fprintf(f, "  Alt:      %s %s\n", r->altitude, r->alt_unit);
            if (r->speed_kts[0])   fprintf(f, "  Speed:    %s kts\n", r->speed_kts);
            if (r->course_deg[0])  fprintf(f, "  Course:   %s°\n", r->course_deg);
            if (r->sv_prn[0])      fprintf(f, "  SV PRN:   %s\n", r->sv_prn);
            if (r->sv_snr[0])      fprintf(f, "  SV SNR:   %s\n", r->sv_snr);
            if (r->sv_elev[0])     fprintf(f, "  SV Elev:  %s\n", r->sv_elev);
            if (r->sv_azim[0])     fprintf(f, "  SV Azim:  %s\n", r->sv_azim);
            if (r->rinex_epoch[0]) fprintf(f, "  RNX Epch: %s\n", r->rinex_epoch);
            if (r->rinex_obs[0])   fprintf(f, "  RNX Obs:  %s\n", r->rinex_obs);
            fprintf(f, "  Source:   %s\n\n", r->source_file);
        }
        fclose(f);
    }

    /* satellite_info.txt  (GSV records only) */
    snprintf(fpath, sizeof(fpath), "%s/satellite_info.txt", c->folder);
    f = fopen(fpath, "w");
    if (f) {
        fprintf(f, "# SATELLITE DATA  %.6f, %.6f\n\n", c->lat, c->lon);
        for (int i = 0; i < c->rec_count; i++) {
            NMEARecord *r = &c->recs[i];
            if (strcmp(r->sentence_type, "GSV") == 0) {
                fprintf(f, "PRN:  %s\n", r->sv_prn);
                fprintf(f, "Elev: %s\n", r->sv_elev);
                fprintf(f, "Azim: %s\n", r->sv_azim);
                fprintf(f, "SNR:  %s\n\n", r->sv_snr);
            }
        }
        fclose(f);
    }
}

/* ─── Export: single structured file ────────────────────────────────────── */

static void export_coord(GPSCoord *c)
{
    if (!c) return;
    char fpath[2048];
    snprintf(fpath, sizeof(fpath), "%s/EXPORT_%.6f_%.6f.txt",
             c->folder, c->lat, c->lon);
    FILE *f = fopen(fpath, "w");
    if (!f) return;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));

    fprintf(f,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║   CTW-11 GNSS MAPPER — COORDINATE EXPORT                 ║\n"
        "║   Made by Christopher Williams                            ║\n"
        "║   Exported: %-44s ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║   Latitude  : %-42.8f ║\n"
        "║   Longitude : %-42.8f ║\n"
        "║   Records   : %-42d ║\n"
        "║   Output    : %-42s ║\n"
        "╚══════════════════════════════════════════════════════════╝\n\n",
        ts, c->lat, c->lon, c->rec_count, c->folder);

    for (int i = 0; i < c->rec_count; i++) {
        NMEARecord *r = &c->recs[i];
        fprintf(f, "┌─ Record %d ── [%s] ", i+1, r->sentence_type);
        for (int j = strlen(r->sentence_type) + (int)log10(i+1.1) + 14; j < 56; j++) fputc('─', f);
        fprintf(f, "┐\n");
        fprintf(f, "│  Raw      : %s\n", r->raw_line);
        fprintf(f, "│  Source   : %s\n", r->source_file);
        if (r->timestamp[0])   fprintf(f, "│  Time     : %s\n", r->timestamp);
        if (r->date[0])        fprintf(f, "│  Date     : %s\n", r->date);
        if (r->fix_quality[0]) fprintf(f, "│  Fix Qual : %s\n", r->fix_quality);
        if (r->satellites[0])  fprintf(f, "│  Sats     : %s\n", r->satellites);
        if (r->hdop[0])        fprintf(f, "│  HDOP     : %s\n", r->hdop);
        if (r->altitude[0])    fprintf(f, "│  Altitude : %s %s\n", r->altitude, r->alt_unit);
        if (r->speed_kts[0])   fprintf(f, "│  Speed    : %s kts\n", r->speed_kts);
        if (r->course_deg[0])  fprintf(f, "│  Course   : %s°\n", r->course_deg);
        if (r->mag_var[0])     fprintf(f, "│  Mag Var  : %s\n", r->mag_var);
        if (r->sv_prn[0])      fprintf(f, "│  SV PRN   : %s\n", r->sv_prn);
        if (r->sv_snr[0])      fprintf(f, "│  SV SNR   : %s\n", r->sv_snr);
        if (r->sv_elev[0])     fprintf(f, "│  SV Elev  : %s\n", r->sv_elev);
        if (r->sv_azim[0])     fprintf(f, "│  SV Azim  : %s\n", r->sv_azim);
        if (r->rinex_epoch[0]) fprintf(f, "│  RNX Epch : %s\n", r->rinex_epoch);
        if (r->rinex_obs[0])   fprintf(f, "│  RNX Obs  : %s\n", r->rinex_obs);
        fprintf(f, "└────────────────────────────────────────────────────────┘\n\n");
    }
    fclose(f);

    GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(main_window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "✅ Exported coordinate data to:\n\n%s", fpath);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

/* ─── Coordinate → Screen Pixel ─────────────────────────────────────────── */

#define MILES_PER_DEG_LAT 69.0946

static void coord_to_px(double lat, double lon, int w, int h,
                         double *px, double *py)
{
    double ref_lat_rad = ground_lat * M_PI / 180.0;
    double ppm = SCREEN_DPI * zoom_level;               /* pixels per mile */
    double dx  = (lon - ground_lon) * cos(ref_lat_rad) * MILES_PER_DEG_LAT * ppm;
    double dy  = (lat - ground_lat) *                    MILES_PER_DEG_LAT * ppm;
    *px = w / 2.0 + pan_x + dx;
    *py = h / 2.0 + pan_y - dy;
}

/* ─── Drawing ────────────────────────────────────────────────────────────── */

static gboolean on_draw(GtkWidget *widget, cairo_t *cr, gpointer user_data)
{
    int W = gtk_widget_get_allocated_width(widget);
    int H = gtk_widget_get_allocated_height(widget);

    /* ── Background: 75% opaque black ── */
    cairo_set_source_rgba(cr, 0.0, 0.0, 0.0, 0.75);
    cairo_paint(cr);

    double cell = SCREEN_DPI * zoom_level;   /* pixels per 1-mile cell */
    double ox   = W / 2.0 + pan_x;
    double oy   = H / 2.0 + pan_y;

    /* ── Minor grid lines (every 1 mile) ── */
    cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.30);
    cairo_set_line_width(cr, 0.5);

    double sx = fmod(ox, cell); if (sx < 0) sx += cell;
    for (double x = sx; x <= W; x += cell) {
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, H); cairo_stroke(cr);
    }
    double sy = fmod(oy, cell); if (sy < 0) sy += cell;
    for (double y = sy; y <= H; y += cell) {
        cairo_move_to(cr, 0, y); cairo_line_to(cr, W, y); cairo_stroke(cr);
    }

    /* ── Major grid lines (every 5 miles) ── */
    double cell5 = cell * 5.0;
    cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.70);
    cairo_set_line_width(cr, 1.0);

    sx = fmod(ox, cell5); if (sx < 0) sx += cell5;
    for (double x = sx; x <= W; x += cell5) {
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, H); cairo_stroke(cr);
    }
    sy = fmod(oy, cell5); if (sy < 0) sy += cell5;
    for (double y = sy; y <= H; y += cell5) {
        cairo_move_to(cr, 0, y); cairo_line_to(cr, W, y); cairo_stroke(cr);
    }

    cairo_select_font_face(cr, "monospace",
        CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);

    /* ── Ground truth crosshair ── */
    double gx, gy;
    coord_to_px(ground_lat, ground_lon, W, H, &gx, &gy);

    /* outer glow */
    cairo_set_source_rgba(cr, 0.0, 1.0, 0.25, 0.25);
    cairo_arc(cr, gx, gy, 16.0, 0, 2*M_PI);
    cairo_fill(cr);
    /* green fill */
    cairo_set_source_rgba(cr, 0.0, 1.0, 0.25, 1.0);
    cairo_arc(cr, gx, gy, 7.0, 0, 2*M_PI);
    cairo_fill(cr);
    /* white border */
    cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 1.0);
    cairo_set_line_width(cr, 1.5);
    cairo_arc(cr, gx, gy, 7.0, 0, 2*M_PI);
    cairo_stroke(cr);
    /* crosshair lines */
    cairo_set_source_rgba(cr, 0.0, 1.0, 0.25, 0.9);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, gx-18, gy); cairo_line_to(cr, gx+18, gy); cairo_stroke(cr);
    cairo_move_to(cr, gx, gy-18); cairo_line_to(cr, gx, gy+18); cairo_stroke(cr);
    /* label */
    cairo_set_source_rgba(cr, 0.0, 1.0, 0.25, 0.95);
    cairo_set_font_size(cr, 10.5);
    cairo_move_to(cr, gx + 14, gy - 6); cairo_show_text(cr, "GROUND TRUTH");
    char gll[64];
    snprintf(gll, sizeof(gll), "%.6f, %.6f", ground_lat, ground_lon);
    cairo_move_to(cr, gx + 14, gy + 8); cairo_show_text(cr, gll);

    /* ── Data dots ── */
    for (int i = 0; i < coord_count; i++) {
        double px, py;
        coord_to_px(coords[i].lat, coords[i].lon, W, H, &px, &py);
        if (px < -20 || px > W+20 || py < -20 || py > H+20) continue;

        /* neon orange fill */
        cairo_set_source_rgba(cr, 1.0, 0.40, 0.0, 0.95);
        cairo_arc(cr, px, py, DOT_RADIUS, 0, 2*M_PI);
        cairo_fill(cr);
        /* white circumference border */
        cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 1.0);
        cairo_set_line_width(cr, 1.8);
        cairo_arc(cr, px, py, DOT_RADIUS, 0, 2*M_PI);
        cairo_stroke(cr);
        /* black center dot */
        cairo_set_source_rgba(cr, 0.0, 0.0, 0.0, 1.0);
        cairo_arc(cr, px, py, 2.8, 0, 2*M_PI);
        cairo_fill(cr);
    }

    /* ── Scale bar (bottom-left) ── */
    double bar = SCREEN_DPI * zoom_level;
    cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.9);
    cairo_set_line_width(cr, 2.0);
    cairo_move_to(cr, 20,       H-20); cairo_line_to(cr, 20+bar, H-20); cairo_stroke(cr);
    cairo_move_to(cr, 20,       H-14); cairo_line_to(cr, 20,     H-26); cairo_stroke(cr);
    cairo_move_to(cr, 20+bar,   H-14); cairo_line_to(cr, 20+bar, H-26); cairo_stroke(cr);
    cairo_set_font_size(cr, 10.0);
    cairo_move_to(cr, 20 + bar/2 - 16, H-28);
    cairo_show_text(cr, "1 mile");

    /* ── Coord count badge ── */
    cairo_set_source_rgba(cr, 1.0, 0.40, 0.0, 0.85);
    cairo_set_font_size(cr, 10.5);
    char badge[64];
    snprintf(badge, sizeof(badge), "Coords: %d", coord_count);
    cairo_move_to(cr, 20, H-36);
    cairo_show_text(cr, badge);

    /* ── Watermark ── */
    cairo_set_source_rgba(cr, 1.0, 0.40, 0.0, 0.40);
    cairo_set_font_size(cr, 9.5);
    cairo_move_to(cr, W - 370, H - 6);
    cairo_show_text(cr, "CTW-11 GNSS COORDINATE MAPPER  —  Made by Christopher Williams");

    return FALSE;
}

/* ─── Popup Detail Window ────────────────────────────────────────────────── */

static void on_export_btn(GtkButton *btn, gpointer data)
{
    export_coord((GPSCoord *)data);
}

static void show_detail_popup(GPSCoord *c)
{
    if (!c) return;
    if (popup_window) { gtk_widget_destroy(popup_window); popup_window = NULL; }

    popup_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[128];
    snprintf(title, sizeof(title), "📍 %.6f, %.6f  [%d records]",
             c->lat, c->lon, c->rec_count);
    gtk_window_set_title(GTK_WINDOW(popup_window), title);
    gtk_window_set_default_size(GTK_WINDOW(popup_window), 620, 520);
    gtk_window_set_transient_for(GTK_WINDOW(popup_window), GTK_WINDOW(main_window));
    gtk_window_set_position(GTK_WINDOW(popup_window), GTK_WIN_POS_CENTER_ON_PARENT);
    g_signal_connect(popup_window, "destroy",
                     G_CALLBACK(gtk_widget_destroyed), &popup_window);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(popup_window), vbox);

    /* Header label */
    char hdr[192];
    snprintf(hdr, sizeof(hdr),
             "Latitude: %.8f    Longitude: %.8f    Records: %d\nFolder: %s",
             c->lat, c->lon, c->rec_count, c->folder);
    GtkWidget *lbl = gtk_label_new(hdr);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), lbl, FALSE, FALSE, 0);

    /* Scrolled text view */
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 4);

    GtkWidget *tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(tv), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tv), GTK_WRAP_WORD_CHAR);
    gtk_container_add(GTK_CONTAINER(scroll), tv);

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv));
    GString *txt = g_string_new(NULL);

    g_string_append_printf(txt,
        "══════════════════════════════════════════════════════════\n"
        "  CTW-11 GNSS Coordinate Detail\n"
        "  Made by Christopher Williams\n"
        "══════════════════════════════════════════════════════════\n"
        "  Latitude  : %.8f\n"
        "  Longitude : %.8f\n"
        "  Records   : %d\n"
        "  Folder    : %s\n"
        "══════════════════════════════════════════════════════════\n\n",
        c->lat, c->lon, c->rec_count, c->folder);

    for (int i = 0; i < c->rec_count; i++) {
        NMEARecord *r = &c->recs[i];
        g_string_append_printf(txt,
            "┌── Record %-4d  [%-8s]"
            " ───────────────────────────────────\n",
            i+1, r->sentence_type);
        g_string_append_printf(txt, "│  Raw      : %s\n", r->raw_line);
        g_string_append_printf(txt, "│  Source   : %s\n", r->source_file);
        if (r->timestamp[0])
            g_string_append_printf(txt, "│  Time     : %s\n", r->timestamp);
        if (r->date[0])
            g_string_append_printf(txt, "│  Date     : %s\n", r->date);
        if (r->fix_quality[0])
            g_string_append_printf(txt, "│  Fix Qual : %s\n", r->fix_quality);
        if (r->satellites[0])
            g_string_append_printf(txt, "│  Sats Used: %s\n", r->satellites);
        if (r->hdop[0])
            g_string_append_printf(txt, "│  HDOP     : %s\n", r->hdop);
        if (r->altitude[0])
            g_string_append_printf(txt, "│  Altitude : %s %s\n",
                                   r->altitude, r->alt_unit);
        if (r->speed_kts[0])
            g_string_append_printf(txt, "│  Speed    : %s kts\n", r->speed_kts);
        if (r->course_deg[0])
            g_string_append_printf(txt, "│  Course   : %s°\n", r->course_deg);
        if (r->mag_var[0])
            g_string_append_printf(txt, "│  Mag Var  : %s\n", r->mag_var);
        if (r->sv_prn[0])
            g_string_append_printf(txt, "│  SV PRN   : %s\n", r->sv_prn);
        if (r->sv_snr[0])
            g_string_append_printf(txt, "│  SV SNR   : %s\n", r->sv_snr);
        if (r->sv_elev[0])
            g_string_append_printf(txt, "│  SV Elev  : %s\n", r->sv_elev);
        if (r->sv_azim[0])
            g_string_append_printf(txt, "│  SV Azim  : %s\n", r->sv_azim);
        if (r->rinex_epoch[0])
            g_string_append_printf(txt, "│  RNX Epoch: %s\n", r->rinex_epoch);
        if (r->rinex_obs[0])
            g_string_append_printf(txt, "│  RNX Obs  : %s\n", r->rinex_obs);
        g_string_append(txt,
            "└────────────────────────────────────────────────────────────\n\n");
    }

    gtk_text_buffer_set_text(buf, txt->str, -1);
    g_string_free(txt, TRUE);

    /* Export button */
    GtkWidget *btn = gtk_button_new_with_label(
        "⬇  Export This Coordinate — Structured Single File");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_export_btn), c);
    gtk_box_pack_start(GTK_BOX(vbox), btn, FALSE, FALSE, 0);

    gtk_widget_show_all(popup_window);
}

/* ─── Hit Test ───────────────────────────────────────────────────────────── */

static GPSCoord *hit_test(double mx, double my, int W, int H)
{
    double best = HIT_RADIUS * HIT_RADIUS;
    GPSCoord *found = NULL;
    for (int i = 0; i < coord_count; i++) {
        double px, py;
        coord_to_px(coords[i].lat, coords[i].lon, W, H, &px, &py);
        double d2 = (mx-px)*(mx-px) + (my-py)*(my-py);
        if (d2 < best) { best = d2; found = &coords[i]; }
    }
    return found;
}

/* ─── Mouse Events ───────────────────────────────────────────────────────── */

static gboolean on_button_press(GtkWidget *widget, GdkEventButton *ev, gpointer ud)
{
    int W = gtk_widget_get_allocated_width(widget);
    int H = gtk_widget_get_allocated_height(widget);

    if (ev->button == 1) {
        /* Left click → detail popup */
        GPSCoord *c = hit_test(ev->x, ev->y, W, H);
        if (c) show_detail_popup(c);
    }
    else if (ev->button == 2) {
        /* Middle button → start pan drag */
        dragging = TRUE;
        drag_sx = ev->x; drag_sy = ev->y;
        drag_px = pan_x; drag_py = pan_y;
    }
    else if (ev->button == 3) {
        /* Right click → context menu */
        GPSCoord *c = hit_test(ev->x, ev->y, W, H);
        if (c) {
            GtkWidget *menu = gtk_menu_new();
            char lbl[128];
            snprintf(lbl, sizeof(lbl),
                     "Export  %.6f, %.6f", c->lat, c->lon);
            GtkWidget *item = gtk_menu_item_new_with_label(lbl);
            g_signal_connect(item, "activate",
                             G_CALLBACK(on_export_btn), c);
            gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);

            GtkWidget *sep  = gtk_separator_menu_item_new();
            gtk_menu_shell_append(GTK_MENU_SHELL(menu), sep);

            GtkWidget *view = gtk_menu_item_new_with_label("View Detail…");
            g_signal_connect_swapped(view, "activate",
                                     G_CALLBACK(show_detail_popup), c);
            gtk_menu_shell_append(GTK_MENU_SHELL(menu), view);

            gtk_widget_show_all(menu);
            gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent *)ev);
        }
    }
    return TRUE;
}

static gboolean on_button_release(GtkWidget *w, GdkEventButton *ev, gpointer ud)
{
    if (ev->button == 2) dragging = FALSE;
    return TRUE;
}

static gboolean on_motion(GtkWidget *widget, GdkEventMotion *ev, gpointer ud)
{
    if (dragging) {
        pan_x = drag_px + (ev->x - drag_sx);
        pan_y = drag_py + (ev->y - drag_sy);
        gtk_widget_queue_draw(widget);
    }
    return TRUE;
}

static gboolean on_scroll(GtkWidget *widget, GdkEventScroll *ev, gpointer ud)
{
    double factor = (ev->direction == GDK_SCROLL_UP) ? 1.18 : 1.0/1.18;
    zoom_level *= factor;
    if (zoom_level < 0.005) zoom_level = 0.005;
    if (zoom_level > 500.0) zoom_level = 500.0;
    gtk_widget_queue_draw(widget);
    return TRUE;
}

/* ─── Ground Truth Dialog ────────────────────────────────────────────────── */

static void show_ground_truth_dialog(void)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Set Ground Truth GPS Coordinate",
        GTK_WINDOW(main_window), GTK_DIALOG_MODAL,
        "_Set", GTK_RESPONSE_OK, "_Cancel", GTK_RESPONSE_CANCEL, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 400, 200);

    GtkWidget *ca  = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 16);
    gtk_container_add(GTK_CONTAINER(ca), grid);

    GtkWidget *lbl_lat = gtk_label_new("Latitude  (decimal):");
    GtkWidget *lbl_lon = gtk_label_new("Longitude (decimal):");
    GtkWidget *ent_lat = gtk_entry_new();
    GtkWidget *ent_lon = gtk_entry_new();
    gtk_widget_set_hexpand(ent_lat, TRUE);
    gtk_widget_set_hexpand(ent_lon, TRUE);

    char buf[32];
    snprintf(buf, sizeof(buf), "%.6f", ground_lat);
    gtk_entry_set_text(GTK_ENTRY(ent_lat), buf);
    snprintf(buf, sizeof(buf), "%.6f", ground_lon);
    gtk_entry_set_text(GTK_ENTRY(ent_lon), buf);

    gtk_grid_attach(GTK_GRID(grid), lbl_lat, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ent_lat, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), lbl_lon, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ent_lon, 1, 1, 1, 1);

    GtkWidget *note = gtk_label_new(
        "This coordinate becomes the green-dot center of the map.");
    gtk_label_set_xalign(GTK_LABEL(note), 0.0);
    gtk_grid_attach(GTK_GRID(grid), note, 0, 2, 2, 1);

    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        double lat = atof(gtk_entry_get_text(GTK_ENTRY(ent_lat)));
        double lon = atof(gtk_entry_get_text(GTK_ENTRY(ent_lon)));
        if (fabs(lat) <= 90.0 && fabs(lon) <= 180.0) {
            ground_lat = lat;
            ground_lon = lon;
        }
    }
    gtk_widget_destroy(dlg);
    gtk_widget_queue_draw(drawing_area);
}

/* ─── Folder / Parse Dialog ──────────────────────────────────────────────── */

static void show_parse_dialog(void)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Parse GNSS Data Folder",
        GTK_WINDOW(main_window), GTK_DIALOG_MODAL,
        "_Parse", GTK_RESPONSE_OK, "_Cancel", GTK_RESPONSE_CANCEL, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 560, 160);

    GtkWidget *ca  = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *vb  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 14);
    gtk_container_add(GTK_CONTAINER(ca), vb);

    GtkWidget *lbl = gtk_label_new(
        "Enter the FULL PATH to the folder containing GNSS data.\n"
        "Parsed:  gnss_log.txt  ·  rnx_data.txt  ·  *.nmea  ·  *.rnx  ·  *.obs  ·  *.log");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(vb), lbl, FALSE, FALSE, 0);

    GtkWidget *ent = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ent), "/full/path/to/gnss/data");
    gtk_entry_set_width_chars(GTK_ENTRY(ent), 60);
    gtk_box_pack_start(GTK_BOX(vb), ent, FALSE, FALSE, 0);

    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *path = gtk_entry_get_text(GTK_ENTRY(ent));
        if (path && path[0]) {
            int prev = coord_count;
            gtk_widget_destroy(dlg);  dlg = NULL;

            /* Parse (blocking — acceptable for forensic tool) */
            scan_folder(path);

            /* Persist new coords to disk */
            for (int i = prev; i < coord_count; i++)
                save_coord_data(&coords[i]);

            gtk_widget_queue_draw(drawing_area);

            GtkWidget *info = gtk_message_dialog_new(GTK_WINDOW(main_window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                "✅ Parse complete\n\n"
                "New coordinates found : %d\n"
                "Total on map          : %d\n"
                "Output folder         : %s",
                coord_count - prev, coord_count, output_base);
            gtk_dialog_run(GTK_DIALOG(info));
            gtk_widget_destroy(info);
            return;
        }
    }
    if (dlg) gtk_widget_destroy(dlg);
}

/* ─── Menu Callbacks ─────────────────────────────────────────────────────── */

static void cb_parse  (GtkMenuItem *i, gpointer d) { show_parse_dialog(); }
static void cb_ground (GtkMenuItem *i, gpointer d) { show_ground_truth_dialog(); }
static void cb_quit   (GtkMenuItem *i, gpointer d) { gtk_main_quit(); }

static void cb_reset_view(GtkMenuItem *i, gpointer d)
{
    pan_x = pan_y = 0.0; zoom_level = 1.0;
    gtk_widget_queue_draw(drawing_area);
}

/* ─── Menu Bar ───────────────────────────────────────────────────────────── */

static GtkWidget *build_menubar(void)
{
    GtkWidget *bar   = gtk_menu_bar_new();

    /* File menu */
    GtkWidget *mfile = gtk_menu_new();
    GtkWidget *ifile = gtk_menu_item_new_with_label("File");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(ifile), mfile);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), ifile);

    GtkWidget *parse = gtk_menu_item_new_with_label("Parse GNSS Folder…");
    GtkWidget *quit  = gtk_menu_item_new_with_label("Quit");
    g_signal_connect(parse, "activate", G_CALLBACK(cb_parse), NULL);
    g_signal_connect(quit,  "activate", G_CALLBACK(cb_quit),  NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(mfile), parse);
    gtk_menu_shell_append(GTK_MENU_SHELL(mfile), gtk_separator_menu_item_new());
    gtk_menu_shell_append(GTK_MENU_SHELL(mfile), quit);

    /* Map menu */
    GtkWidget *mmap = gtk_menu_new();
    GtkWidget *imap = gtk_menu_item_new_with_label("Map");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(imap), mmap);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), imap);

    GtkWidget *ground = gtk_menu_item_new_with_label("Set Ground Truth Coordinate…");
    GtkWidget *reset  = gtk_menu_item_new_with_label("Reset View (pan/zoom)");
    g_signal_connect(ground, "activate", G_CALLBACK(cb_ground),    NULL);
    g_signal_connect(reset,  "activate", G_CALLBACK(cb_reset_view), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(mmap), ground);
    gtk_menu_shell_append(GTK_MENU_SHELL(mmap), reset);

    /* Help menu */
    GtkWidget *mhelp = gtk_menu_new();
    GtkWidget *ihelp = gtk_menu_item_new_with_label("Help");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(ihelp), mhelp);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), ihelp);

    GtkWidget *about = gtk_menu_item_new_with_label("About…");
    g_signal_connect_swapped(about, "activate",
        G_CALLBACK(gtk_message_dialog_new), NULL);
    /* Simpler about inline */
    g_signal_connect(about, "activate", G_CALLBACK(
        ({
            void _ab(GtkMenuItem *x, gpointer d) {
                GtkWidget *dlg = gtk_message_dialog_new(
                    GTK_WINDOW(main_window),
                    GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                    "CTW-11 GNSS Coordinate Mapper\n\n"
                    "Made by Christopher Williams\n\n"
                    "Scale  :  1 screen inch = 1 mile\n"
                    "Grid   :  White (minor 1-mi, major 5-mi)\n"
                    "Background: 75%% translucent black\n\n"
                    "Left-click dot   → scrollable detail\n"
                    "Right-click dot  → export menu\n"
                    "Middle-drag      → pan\n"
                    "Scroll wheel     → zoom");
                gtk_dialog_run(GTK_DIALOG(dlg));
                gtk_widget_destroy(dlg);
            }
            _ab;
        })
    ), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(mhelp), about);

    return bar;
}

/* ─── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    /* Detect true screen DPI */
    GdkScreen *screen = gdk_screen_get_default();
    if (screen) {
        double dpi = gdk_screen_get_resolution(screen);
        if (dpi > 0) SCREEN_DPI = dpi;
    }

    /* Create base output dir */
    make_dir_p(output_base);

    /* ── Build window ── */
    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), APP_TITLE);
    gtk_window_maximize(GTK_WINDOW(main_window));
    g_signal_connect(main_window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(main_window), vbox);

    gtk_box_pack_start(GTK_BOX(vbox), build_menubar(), FALSE, FALSE, 0);

    drawing_area = gtk_drawing_area_new();
    gtk_widget_set_hexpand(drawing_area, TRUE);
    gtk_widget_set_vexpand(drawing_area, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), drawing_area, TRUE, TRUE, 0);

    gtk_widget_add_events(drawing_area,
        GDK_BUTTON_PRESS_MASK   | GDK_BUTTON_RELEASE_MASK |
        GDK_POINTER_MOTION_MASK | GDK_SCROLL_MASK);

    g_signal_connect(drawing_area, "draw",
                     G_CALLBACK(on_draw),          NULL);
    g_signal_connect(drawing_area, "button-press-event",
                     G_CALLBACK(on_button_press),  NULL);
    g_signal_connect(drawing_area, "button-release-event",
                     G_CALLBACK(on_button_release), NULL);
    g_signal_connect(drawing_area, "motion-notify-event",
                     G_CALLBACK(on_motion),        NULL);
    g_signal_connect(drawing_area, "scroll-event",
                     G_CALLBACK(on_scroll),        NULL);

    gtk_widget_show_all(main_window);

    /* ── Startup dialogs ── */
    show_ground_truth_dialog();   /* set ground truth */
    show_parse_dialog();          /* load data folder */

    gtk_main();

    /* cleanup */
    for (int i = 0; i < coord_count; i++)
        free(coords[i].recs);
    free(coords);
    return 0;
}
