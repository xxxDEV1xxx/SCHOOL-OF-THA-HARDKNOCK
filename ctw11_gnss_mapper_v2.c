/*
 * ============================================================
 *  CTW-11 GNSS COORDINATE MAPPER  v2.0
 *  Made by Christopher Williams
 * ============================================================
 *  IMPROVEMENTS OVER v1.0
 *   1. NMEA checksum validation (bad frames logged, skipped)
 *   2. Per-file parse context (GSV/last-pos no longer bleeds
 *      across files)
 *   3. Zoom centres on mouse cursor position
 *   4. Live status bar: mouse lat/lon · zoom · coord count
 *   5. Keyboard shortcuts: Ctrl+O  Ctrl+Q  R  G
 *   6. Adaptive scale bar (auto-rounds to nice mile value)
 *   7. Fix-quality colour coding on dots
 *        red    = no fix (quality 0)
 *        orange = standard GPS (quality 1)
 *        yellow = DGPS (quality 2)
 *        cyan   = PPS / RTK float (quality 3/5)
 *        green  = RTK fixed (quality 4)
 *   8. Dot label rendering at zoom ≥ 3×
 *   9. Visual stack badge when ≥ 2 dots overlap within dot radius
 *  10. Fixed broken about-dialog (was using non-portable GCC
 *      nested-function extension)
 *
 *  Build:
 *    gcc -O2 -Wall -std=gnu11 -o ctw11_gnss_mapper ctw11_gnss_mapper.c \
 *        $(pkg-config --cflags --libs gtk+-3.0) -lm
 *
 *  Controls
 *    Left-click dot        scrollable detail popup
 *    Right-click dot       export menu
 *    Middle-button drag    pan
 *    Scroll wheel          zoom (toward cursor)
 *    Ctrl+O                parse folder dialog
 *    Ctrl+Q                quit
 *    R                     reset view
 *    G                     set ground truth
 * ============================================================
 */

#include <gtk/gtk.h>
#include <cairo.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

/* ─── tunables ───────────────────────────────────────────────────────────── */
#define MAX_COORDS        8192
#define MAX_LINE          2048
#define MAX_REC_PER_COORD 2048
#define MAX_FIELDS        64
#define DOT_RADIUS        9.0
#define HIT_RADIUS        14.0
#define LABEL_ZOOM        3.0    /* show lat/lon labels above this zoom */
#define MILES_PER_DEG_LAT 69.0946

#define APP_TITLE \
    "CTW-11 GNSS Coordinate Mapper v2.0  —  Made by Christopher Williams"

/* ─── types ──────────────────────────────────────────────────────────────── */

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
    char sv_prn[256];
    char sv_elev[256];
    char sv_azim[256];
    char sv_snr[256];
    char rinex_epoch[64];
    char rinex_obs[1024];
    char source_file[512];
    int  location_type; /* 0=unknown 1=GPS 2=Network/Cell 3=DGPS 4=RTK 5=RINEX */
} NMEARecord;

/* location_type constants */
#define LOC_UNKNOWN  0
#define LOC_GPS      1
#define LOC_NETWORK  2
#define LOC_DGPS     3
#define LOC_RTK      4
#define LOC_RINEX    5

/* Per-file parse context — eliminates cross-file bleed */
typedef struct {
    char   gsv_prn[512];
    char   gsv_elev[512];
    char   gsv_azim[512];
    char   gsv_snr[512];
    double last_lat;
    double last_lon;
    int    checksum_failures;
    int    lines_parsed;
} ParseCtx;

typedef struct {
    double lat;
    double lon;
    char   key[64];
    char   folder[1024];
    NMEARecord *recs;
    int    rec_count;
    int    rec_cap;
    int    best_fix;    /* 0=none,1=GPS,2=DGPS,3=PPS,4=RTK,5=float */
    int    dominant_loc; /* LOC_GPS or LOC_NETWORK — majority vote */
    int    gps_count;    /* records with satellite fix */
    int    net_count;    /* records from network/cell */
} GPSCoord;

/* ─── globals ────────────────────────────────────────────────────────────── */

static GPSCoord *coords      = NULL;
static int       coord_count = 0;
static int       coord_cap   = 0;

static double SCREEN_DPI  = 96.0;
static double ground_lat  = 33.8530;
static double ground_lon  = -117.2280;
static double pan_x       = 0.0;
static double pan_y       = 0.0;
static double zoom_level  = 1.0;

/* toolbar state */
static double map_ratio       = 1.0;   /* miles per inch denominator: 1=1mi, 0.5=half-mi, 2=2mi */
static double win_alpha       = 1.0;   /* whole-window transparency 0.0-1.0 */
static GtkWidget *ratio_entry  = NULL;
static GtkWidget *alpha_scale  = NULL;

/* drag state */
static gboolean dragging  = FALSE;
static double   drag_sx, drag_sy, drag_px, drag_py;

/* widgets */
static GtkWidget *main_window  = NULL;
static GtkWidget *drawing_area = NULL;
static GtkWidget *popup_window = NULL;
static GtkWidget *status_label  = NULL;
static GtkWidget *toolbar_bar   = NULL;

static char output_base[1024] = "./gnss_output";

/* ─── utilities ──────────────────────────────────────────────────────────── */

static void make_dir_p(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

static void trim_crlf(char *s)
{
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

static int csv_split(char *buf, char **fields, int maxf)
{
    int n = 0;
    char *p = buf;
    while (n < maxf) {
        fields[n++] = p;
        p = strchr(p, ',');
        if (!p) break;
        *p++ = '\0';
    }
    return n;
}

/* ─── NMEA checksum validation ───────────────────────────────────────────── */

static int nmea_checksum_ok(const char *sentence)
{
    if (!sentence || sentence[0] != '$') return 1; /* no $ → pass through */
    const char *ast = strchr(sentence, '*');
    if (!ast) return 1; /* no checksum field → accept */
    uint8_t calc = 0;
    for (const char *p = sentence + 1; p < ast; p++) calc ^= (uint8_t)*p;
    unsigned int given = 0;
    if (sscanf(ast + 1, "%2X", &given) != 1) return 1;
    return calc == (uint8_t)given;
}

/* ─── NMEA field decoders ─────────────────────────────────────────────────── */

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

/* ─── ECEF → WGS-84 geodetic (Bowring iteration) ─────────────────────────── */

static void ecef_to_lla(double x, double y, double z,
                         double *lat_deg, double *lon_deg, double *alt_m)
{
    const double a  = 6378137.0;
    const double e2 = 6.6943799901414e-3;
    const double b  = 6356752.314245;
    double p  = sqrt(x*x + y*y);
    double lat = atan2(z, p * (1.0 - e2));
    for (int i = 0; i < 5; i++) {
        double slat = sin(lat);
        double N    = a / sqrt(1.0 - e2 * slat * slat);
        lat = atan2(z + e2 * N * slat, p);
    }
    *lat_deg = lat * 180.0 / M_PI;
    *lon_deg = atan2(y, x) * 180.0 / M_PI;
    double slat = sin(lat);
    double N    = a / sqrt(1.0 - e2 * slat * slat);
    *alt_m = (fabs(lat) > 0.7) ? z / slat - N * (1.0 - e2) : p / cos(lat) - N;
    (void)b;
}

/* ─── coordinate store ────────────────────────────────────────────────────── */

static GPSCoord *get_or_create_coord(double lat, double lon)
{
    char key[64];
    snprintf(key, sizeof(key), "%.6f_%.6f", lat, lon);
    for (int i = 0; i < coord_count; i++)
        if (strcmp(coords[i].key, key) == 0) return &coords[i];

    if (coord_count >= coord_cap) {
        coord_cap = coord_cap ? coord_cap * 2 : 256;
        coords = realloc(coords, (size_t)coord_cap * sizeof(GPSCoord));
        if (!coords) { fputs("OOM\n", stderr); exit(1); }
    }
    GPSCoord *c = &coords[coord_count++];
    memset(c, 0, sizeof(*c));
    c->lat = lat; c->lon = lon;
    strncpy(c->key, key, sizeof(c->key)-1);
    snprintf(c->folder, sizeof(c->folder), "%s/%s", output_base, key);
    make_dir_p(c->folder);
    return c;
}

static void push_record(GPSCoord *c, const NMEARecord *r)
{
    if (!c) return;
    if (c->rec_count >= c->rec_cap) {
        c->rec_cap = c->rec_cap ? c->rec_cap * 2 : 64;
        c->recs = realloc(c->recs, (size_t)c->rec_cap * sizeof(NMEARecord));
        if (!c->recs) { fputs("OOM recs\n", stderr); exit(1); }
    }
    c->recs[c->rec_count++] = *r;

    /* track best fix quality */
    int fq = atoi(r->fix_quality);
    if (fq > c->best_fix) c->best_fix = fq;

    /* classify location source */
    if (r->location_type == LOC_UNKNOWN) {
        /* infer from fix quality and sentence type */
        if (fq == 2 || fq == 3) r->location_type = LOC_DGPS;
        else if (fq == 4)       r->location_type = LOC_RTK;
        else if (fq >= 1)       r->location_type = LOC_GPS;
        else if (strcmp(r->sentence_type,"GNSSLOG")==0) r->location_type = LOC_NETWORK;
        else if (strcmp(r->sentence_type,"RINEX")==0)   r->location_type = LOC_RINEX;
        else                    r->location_type = LOC_GPS; /* default NMEA = satellite */
    }
    /* check source filename for network/cell keywords */
    {
        const char *sf = r->source_file;
        if (strstr(sf,"cell")||strstr(sf,"network")||strstr(sf,"lte")||
            strstr(sf,"gsm")||strstr(sf,"wifi")||strstr(sf,"agps")||
            strstr(sf,"nmea_network")||strstr(sf,"assisted"))
            r->location_type = LOC_NETWORK;
    }
    if (r->location_type == LOC_NETWORK) c->net_count++;
    else                                  c->gps_count++;
    /* dominant = whichever has more records */
    c->dominant_loc = (c->net_count > c->gps_count) ? LOC_NETWORK : LOC_GPS;
}

/* ─── NMEA line parser ─────────────────────────────────────────────────────── */

static void accum(char *buf, size_t sz, const char *val)
{
    if (val && val[0]) {
        strncat(buf, val, sz - strlen(buf) - 2);
        strncat(buf, " ", 2);
    }
}

static void parse_nmea_line(const char *line, const char *src, ParseCtx *ctx)
{
    ctx->lines_parsed++;

    /* checksum */
    if (!nmea_checksum_ok(line)) {
        ctx->checksum_failures++;
        return;  /* discard corrupted frame */
    }

    char buf[MAX_LINE];
    strncpy(buf, line, sizeof(buf)-1);
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

    /* ── GGA ── */
    if (strstr(sent, "GGA") && nf >= 6) {
        strncpy(rec.sentence_type, "GGA", 4);
        if (nf > 1)  strncpy(rec.timestamp,  fields[1], sizeof(rec.timestamp)-1);
        if (nf > 6)  strncpy(rec.fix_quality,fields[6], sizeof(rec.fix_quality)-1);
        if (nf > 7)  strncpy(rec.satellites, fields[7], sizeof(rec.satellites)-1);
        if (nf > 8)  strncpy(rec.hdop,       fields[8], sizeof(rec.hdop)-1);
        if (nf > 9)  strncpy(rec.altitude,   fields[9], sizeof(rec.altitude)-1);
        if (nf > 10) strncpy(rec.alt_unit,   fields[10],sizeof(rec.alt_unit)-1);

        if (nf > 4 && fields[2][0]) {
            double lat = nmea_to_dd(fields[2], nf>3 ? fields[3] : "N");
            double lon = nmea_to_dd(fields[4], nf>5 ? fields[5] : "E");
            if (lat != 0.0 || lon != 0.0) {
                ctx->last_lat = lat; ctx->last_lon = lon;
                strncpy(rec.sv_prn,  ctx->gsv_prn,  sizeof(rec.sv_prn)-1);
                strncpy(rec.sv_elev, ctx->gsv_elev, sizeof(rec.sv_elev)-1);
                strncpy(rec.sv_azim, ctx->gsv_azim, sizeof(rec.sv_azim)-1);
                strncpy(rec.sv_snr,  ctx->gsv_snr,  sizeof(rec.sv_snr)-1);
                push_record(get_or_create_coord(lat, lon), &rec);
            }
        }
    }
    /* ── RMC ── */
    else if (strstr(sent, "RMC") && nf >= 9) {
        strncpy(rec.sentence_type, "RMC", 4);
        if (nf > 1) strncpy(rec.timestamp,  fields[1], sizeof(rec.timestamp)-1);
        if (nf > 7) strncpy(rec.speed_kts,  fields[7], sizeof(rec.speed_kts)-1);
        if (nf > 8) strncpy(rec.course_deg, fields[8], sizeof(rec.course_deg)-1);
        if (nf > 9) strncpy(rec.date,       fields[9], sizeof(rec.date)-1);
        /* RMC fix status: fields[2] = A(active)/V(void) */
        strncpy(rec.fix_quality, (nf>2 && fields[2][0]=='A') ? "1" : "0", 2);

        if (nf > 5 && fields[3][0]) {
            double lat = nmea_to_dd(fields[3], fields[4]);
            double lon = nmea_to_dd(fields[5], fields[6]);
            if (lat != 0.0 || lon != 0.0) {
                ctx->last_lat = lat; ctx->last_lon = lon;
                push_record(get_or_create_coord(lat, lon), &rec);
            }
        }
    }
    /* ── GLL ── */
    else if (strstr(sent, "GLL") && nf >= 5) {
        strncpy(rec.sentence_type, "GLL", 4);
        if (nf > 5) strncpy(rec.timestamp, fields[5], sizeof(rec.timestamp)-1);
        if (fields[1][0]) {
            double lat = nmea_to_dd(fields[1], fields[2]);
            double lon = nmea_to_dd(fields[3], fields[4]);
            if (lat != 0.0 || lon != 0.0) {
                ctx->last_lat = lat; ctx->last_lon = lon;
                push_record(get_or_create_coord(lat, lon), &rec);
            }
        }
    }
    /* ── GSV — accumulate satellite constellation ── */
    else if (strstr(sent, "GSV")) {
        strncpy(rec.sentence_type, "GSV", 4);
        for (int i = 4; i + 3 < nf; i += 4) {
            accum(ctx->gsv_prn,  sizeof(ctx->gsv_prn),  fields[i]);
            accum(ctx->gsv_elev, sizeof(ctx->gsv_elev), fields[i+1]);
            accum(ctx->gsv_azim, sizeof(ctx->gsv_azim), fields[i+2]);
            accum(ctx->gsv_snr,  sizeof(ctx->gsv_snr),  fields[i+3]);
        }
        if (ctx->last_lat || ctx->last_lon) {
            strncpy(rec.sv_prn,  ctx->gsv_prn,  sizeof(rec.sv_prn)-1);
            strncpy(rec.sv_snr,  ctx->gsv_snr,  sizeof(rec.sv_snr)-1);
            push_record(get_or_create_coord(ctx->last_lat, ctx->last_lon), &rec);
        }
    }
    /* ── GSA ── */
    else if (strstr(sent, "GSA")) {
        strncpy(rec.sentence_type, "GSA", 4);
        if (ctx->last_lat || ctx->last_lon)
            push_record(get_or_create_coord(ctx->last_lat, ctx->last_lon), &rec);
    }
    /* ── VTG ── */
    else if (strstr(sent, "VTG") && nf >= 8) {
        strncpy(rec.sentence_type, "VTG", 4);
        if (nf > 1) strncpy(rec.course_deg, fields[1], sizeof(rec.course_deg)-1);
        if (nf > 7) strncpy(rec.speed_kts,  fields[7], sizeof(rec.speed_kts)-1);
        if (ctx->last_lat || ctx->last_lon)
            push_record(get_or_create_coord(ctx->last_lat, ctx->last_lon), &rec);
    }
}

static void parse_nmea_file(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    ParseCtx ctx;
    memset(&ctx, 0, sizeof(ctx));

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);
        if (strlen(line) < 6) continue;
        if (line[0] == '$') parse_nmea_line(line, filepath, &ctx);
    }
    fclose(f);

    if (ctx.checksum_failures > 0)
        fprintf(stderr, "[CTW-11] %s: %d/%d checksum failures\n",
                filepath, ctx.checksum_failures, ctx.lines_parsed);
}

/* ─── RINEX observer ─────────────────────────────────────────────────────── */

static void parse_rinex_file(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    char   line[MAX_LINE];
    int    in_header  = 1;
    double approx_lat = 0, approx_lon = 0, approx_alt = 0;
    char   epoch[64]  = "";
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

        if (line[0] == '>') {
            /* flush previous epoch */
            if ((approx_lat || approx_lon) && epoch[0] && obs_buf[0]) {
                NMEARecord rec;
                memset(&rec, 0, sizeof(rec));
                strncpy(rec.sentence_type, "RINEX",   6);
                strncpy(rec.rinex_epoch,   epoch,     sizeof(rec.rinex_epoch)-1);
                strncpy(rec.rinex_obs,     obs_buf,   sizeof(rec.rinex_obs)-1);
                strncpy(rec.source_file,   filepath,  sizeof(rec.source_file)-1);
                snprintf(rec.altitude, sizeof(rec.altitude), "%.2f", approx_alt);
                strncpy(rec.alt_unit, "m", 2);
                strncpy(rec.fix_quality, "1", 2);
                rec.location_type = LOC_RINEX;
                push_record(get_or_create_coord(approx_lat, approx_lon), &rec);
            }
            strncpy(epoch, line + 2, sizeof(epoch)-1);
            obs_buf[0] = '\0';
        } else {
            strncat(obs_buf, line, sizeof(obs_buf) - strlen(obs_buf) - 3);
            strncat(obs_buf, " | ", 4);
        }
    }
    /* flush last */
    if ((approx_lat || approx_lon) && epoch[0] && obs_buf[0]) {
        NMEARecord rec;
        memset(&rec, 0, sizeof(rec));
        strncpy(rec.sentence_type, "RINEX",  6);
        strncpy(rec.rinex_epoch,   epoch,    sizeof(rec.rinex_epoch)-1);
        strncpy(rec.rinex_obs,     obs_buf,  sizeof(rec.rinex_obs)-1);
        strncpy(rec.source_file,   filepath, sizeof(rec.source_file)-1);
        strncpy(rec.fix_quality,   "1",      2);
        push_record(get_or_create_coord(approx_lat, approx_lon), &rec);
    }
    fclose(f);
}

/* ─── gnss_log.txt parser ─────────────────────────────────────────────────── */

static void parse_gnss_log(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    ParseCtx ctx;
    memset(&ctx, 0, sizeof(ctx));

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);
        if (!line[0]) continue;

        char *nmea = strstr(line, "$G");
        if (!nmea) nmea = strstr(line, "$P");
        if (nmea) { parse_nmea_line(nmea, filepath, &ctx); continue; }

        double lat, lon;
        char ts[32] = "";
        if (sscanf(line, "%31[^,],%lf,%lf", ts, &lat, &lon) == 3 &&
            fabs(lat) <= 90.0 && fabs(lon) <= 180.0) {
            NMEARecord rec;
            memset(&rec, 0, sizeof(rec));
            strncpy(rec.sentence_type, "GNSSLOG", 8);
            strncpy(rec.timestamp,     ts,        sizeof(rec.timestamp)-1);
            strncpy(rec.raw_line,      line,      sizeof(rec.raw_line)-1);
            strncpy(rec.source_file,   filepath,  sizeof(rec.source_file)-1);
            strncpy(rec.fix_quality,   "1",       2);
            push_record(get_or_create_coord(lat, lon), &rec);
        }
    }
    fclose(f);
}


/* ─── Android GNSS Logger parser ─────────────────────────────────────────────
 *
 *  File format (Google GNSS Logger app):
 *   Header lines begin with '#'
 *   Record types (first CSV field):
 *     Fix    - position fix  ← the one we care about for coordinates
 *     Raw    - pseudorange measurements
 *     UncalAccel / UncalGyro / UncalMag - IMU
 *     Pressure / OrientationDeg / GameRotationVector - sensors
 *     Nav    - navigation message
 *
 *  Fix row columns (from header):
 *   Fix,Provider,LatitudeDegrees,LongitudeDegrees,AltitudeMeters,
 *   SpeedMps,AccuracyMeters,BearingDegrees,UnixTimeMillis,
 *   SpeedAccuracyMps,BearingAccuracyDegrees,elapsedRealtimeNanos,
 *   VerticalAccuracyMeters,MockLocation,NumberOfUsedSignals,
 *   VerticalSpeedAccuracyMps,SolutionType
 *
 *  Provider values: "gps" = satellite  "network" = cell/wifi
 * ────────────────────────────────────────────────────────────────────────── */

/* split buf by comma into fields[], returns count */
static int android_split(char *buf, char **fields, int maxf)
{
    int n = 0;
    char *p = buf;
    while (n < maxf - 1) {
        fields[n++] = p;
        p = strchr(p, ',');
        if (!p) break;
        *p++ = '\0';
    }
    if (p && n < maxf) fields[n++] = p;   /* last field (may be empty) */
    return n;
}

/* column index cache — filled once per file from header */
typedef struct {
    int provider;   /* "Fix" header: col index of Provider         */
    int lat;        /*                col index of LatitudeDegrees  */
    int lon;        /*                col index of LongitudeDegrees */
    int alt;        /*                col index of AltitudeMeters   */
    int speed;      /*                col index of SpeedMps         */
    int accuracy;   /*                col index of AccuracyMeters   */
    int bearing;    /*                col index of BearingDegrees   */
    int unixtime;   /*                col index of UnixTimeMillis   */
    int numsigs;    /*                col index of NumberOfUsedSignals */
    int mockloc;    /*                col index of MockLocation     */
    int solution;   /*                col index of SolutionType     */
    int valid;      /* 1 once the Fix header line has been parsed   */
} AndroidFixCols;

static int find_col(char **hdr, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (strcasecmp(hdr[i], name) == 0) return i;
    return -1;
}

static void parse_android_gnss_log(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    AndroidFixCols fc;
    memset(&fc, 0, sizeof(fc));
    fc.lat = fc.lon = fc.alt = fc.provider = -1;
    fc.speed = fc.accuracy = fc.bearing = fc.unixtime = -1;
    fc.numsigs = fc.mockloc = fc.solution = -1;

    char line[MAX_LINE];
    int  coords_found = 0;

    while (fgets(line, sizeof(line), f)) {
        trim_crlf(line);
        if (!line[0]) continue;

        /* ── header comment lines ── */
        if (line[0] == '#') {
            /* look for Fix header:
               "# Fix,Provider,LatitudeDegrees,..." */
            char *p = line + 1;
            while (*p == ' ') p++;   /* skip spaces after # */
            if (strncmp(p, "Fix,", 4) == 0) {
                char hbuf[MAX_LINE];
                strncpy(hbuf, p, sizeof(hbuf)-1);
                char *hfields[MAX_FIELDS];
                int  hn = android_split(hbuf, hfields, MAX_FIELDS);
                /* strip leading/trailing spaces from each field */
                for (int i = 0; i < hn; i++) {
                    while (*hfields[i] == ' ') hfields[i]++;
                    char *end = hfields[i] + strlen(hfields[i]) - 1;
                    while (end > hfields[i] && *end == ' ') *end-- = '\0';
                }
                fc.provider  = find_col(hfields, hn, "Provider");
                fc.lat       = find_col(hfields, hn, "LatitudeDegrees");
                fc.lon       = find_col(hfields, hn, "LongitudeDegrees");
                fc.alt       = find_col(hfields, hn, "AltitudeMeters");
                fc.speed     = find_col(hfields, hn, "SpeedMps");
                fc.accuracy  = find_col(hfields, hn, "AccuracyMeters");
                fc.bearing   = find_col(hfields, hn, "BearingDegrees");
                fc.unixtime  = find_col(hfields, hn, "UnixTimeMillis");
                fc.numsigs   = find_col(hfields, hn, "NumberOfUsedSignals");
                fc.mockloc   = find_col(hfields, hn, "MockLocation");
                fc.solution  = find_col(hfields, hn, "SolutionType");
                if (fc.lat >= 0 && fc.lon >= 0) {
                    fc.valid = 1;
                    fprintf(stderr, "[CTW-11] Android GNSS Logger Fix header found: "
                            "lat col=%d lon col=%d provider col=%d\n",
                            fc.lat, fc.lon, fc.provider);
                }
            }
            continue;
        }

        /* ── data lines ── */
        char buf[MAX_LINE];
        strncpy(buf, line, sizeof(buf)-1);
        char *fields[MAX_FIELDS];
        int   nf = android_split(buf, fields, MAX_FIELDS);
        if (nf < 2) continue;

        /* strip whitespace from record type */
        char *rtype = fields[0];
        while (*rtype == ' ') rtype++;

        /* ── Fix record ── */
        if (strcmp(rtype, "Fix") == 0) {
            if (!fc.valid) {
                /* No header found yet — try positional fallback:
                   Fix,provider,lat,lon,alt,speed,accuracy,bearing,unixtime */
                if (nf >= 4) {
                    fc.provider = 1; fc.lat = 2; fc.lon = 3;
                    fc.alt = (nf>4)?4:-1; fc.speed = (nf>5)?5:-1;
                    fc.accuracy=(nf>6)?6:-1; fc.bearing=(nf>7)?7:-1;
                    fc.unixtime=(nf>8)?8:-1; fc.valid=1;
                    fprintf(stderr,"[CTW-11] Fix header not found — using positional fallback\n");
                } else continue;
            }
            if (fc.lat < 0 || fc.lon < 0 || fc.lat >= nf || fc.lon >= nf) continue;

            double lat = atof(fields[fc.lat]);
            double lon = atof(fields[fc.lon]);
            if (fabs(lat) < 0.0001 && fabs(lon) < 0.0001) continue; /* skip 0,0 */
            if (fabs(lat) > 90.0 || fabs(lon) > 180.0)   continue;

            NMEARecord rec;
            memset(&rec, 0, sizeof(rec));
            strncpy(rec.sentence_type, "ANDROID_FIX", 12);
            strncpy(rec.raw_line,    line,      sizeof(rec.raw_line)-1);
            strncpy(rec.source_file, filepath,  sizeof(rec.source_file)-1);

            /* altitude */
            if (fc.alt >= 0 && fc.alt < nf) {
                strncpy(rec.altitude, fields[fc.alt], sizeof(rec.altitude)-1);
                strncpy(rec.alt_unit, "m", 2);
            }
            /* speed → knots */
            if (fc.speed >= 0 && fc.speed < nf && fields[fc.speed][0]) {
                double mps = atof(fields[fc.speed]);
                snprintf(rec.speed_kts, sizeof(rec.speed_kts), "%.4f", mps * 1.94384);
            }
            /* bearing */
            if (fc.bearing >= 0 && fc.bearing < nf)
                strncpy(rec.course_deg, fields[fc.bearing], sizeof(rec.course_deg)-1);
            /* HDOP proxy: accuracy in metres */
            if (fc.accuracy >= 0 && fc.accuracy < nf)
                strncpy(rec.hdop, fields[fc.accuracy], sizeof(rec.hdop)-1);
            /* satellites used */
            if (fc.numsigs >= 0 && fc.numsigs < nf)
                strncpy(rec.satellites, fields[fc.numsigs], sizeof(rec.satellites)-1);
            /* Unix timestamp → pseudo-timestamp string */
            if (fc.unixtime >= 0 && fc.unixtime < nf) {
                long long ut = atoll(fields[fc.unixtime]);
                time_t ts = (time_t)(ut / 1000LL);
                struct tm *gmt = gmtime(&ts);
                if (gmt)
                    strftime(rec.timestamp, sizeof(rec.timestamp),
                             "%Y%m%d %H%M%S", gmt);
            }

            /* provider → location type */
            const char *prov = (fc.provider >= 0 && fc.provider < nf)
                               ? fields[fc.provider] : "gps";
            if (strcasecmp(prov,"gps")==0 || strcasecmp(prov,"gnss")==0) {
                rec.location_type = LOC_GPS;
                strncpy(rec.fix_quality, "1", 2);
            } else {
                /* network / fused / passive */
                rec.location_type = LOC_NETWORK;
                strncpy(rec.fix_quality, "0", 2);
            }

            /* mock location flag */
            if (fc.mockloc >= 0 && fc.mockloc < nf &&
                (fields[fc.mockloc][0]=='1'||strcasecmp(fields[fc.mockloc],"true")==0))
                rec.location_type = LOC_NETWORK;  /* treat mock as network */

            GPSCoord *coord = get_or_create_coord(lat, lon);
            push_record(coord, &rec);
            coords_found++;
            continue;
        }

        /* ── Mandatory record types — all attached to last known coord ──
         *  Raw, Agc, UncalAccel, UncalGyro, UncalMag, Pressure,
         *  OrientationDeg, GameRotationVector, Status             */
        int is_sensor = (
            strcmp(rtype,"Raw")==0            ||
            strcmp(rtype,"Agc")==0            ||
            strcmp(rtype,"UncalAccel")==0     ||
            strcmp(rtype,"UncalGyro")==0      ||
            strcmp(rtype,"UncalMag")==0       ||
            strcmp(rtype,"Pressure")==0       ||
            strcmp(rtype,"OrientationDeg")==0 ||
            strcmp(rtype,"GameRotationVector")==0 ||
            strcmp(rtype,"Status")==0
        );
        if (is_sensor && coords_found > 0) {
            /* store raw pseudorange line in the most recent coordinate */
            GPSCoord *last = &coords[coord_count - 1];
            NMEARecord rec;
            memset(&rec, 0, sizeof(rec));
            strncpy(rec.sentence_type, "ANDROID_RAW", 12);
            strncpy(rec.raw_line,    line,     sizeof(rec.raw_line)-1);
            strncpy(rec.source_file, filepath, sizeof(rec.source_file)-1);
            /* extract Svid and constellation into sv_prn */
            /* Raw cols: Raw,utcTimeMillis,TimeNanos,...,Svid,...,ConstellationType */
            char rbuf[MAX_LINE];
            strncpy(rbuf, line, sizeof(rbuf)-1);
            char *rf[MAX_FIELDS];
            int rnf = android_split(rbuf, rf, MAX_FIELDS);
            /* ConstellationType col ~29, Svid col ~27 in standard format */
            /* for Raw: extract Svid/constellation */
            if (strcmp(rtype,"Raw")==0 && rnf > 28) {
                char sv[64];
                snprintf(sv, sizeof(sv), "Svid=%s Const=%s",
                         rnf>27?rf[27]:"?", rnf>28?rf[28]:"?");
                strncpy(rec.sv_prn, sv, sizeof(rec.sv_prn)-1);
            }
            push_record(last, &rec);
        }

        /* ── Fix,GPS and Fix,FLP variants ──
         * Some logger versions prefix provider into the record type itself */
        if ((strcmp(rtype,"Fix,GPS")==0 || strcmp(rtype,"Fix,FLP")==0) && nf >= 3) {
            double lat = atof(fields[1]);
            double lon = atof(fields[2]);
            if (fabs(lat) <= 90.0 && fabs(lon) <= 180.0 &&
                (fabs(lat) > 0.0001 || fabs(lon) > 0.0001)) {
                NMEARecord rec;
                memset(&rec, 0, sizeof(rec));
                strncpy(rec.sentence_type,
                        strcmp(rtype,"Fix,GPS")==0 ? "ANDROID_GPS" : "ANDROID_FLP",
                        13);
                strncpy(rec.raw_line,    line,     sizeof(rec.raw_line)-1);
                strncpy(rec.source_file, filepath, sizeof(rec.source_file)-1);
                if (nf > 3) strncpy(rec.altitude,   fields[3], sizeof(rec.altitude)-1);
                if (nf > 4) strncpy(rec.speed_kts,  fields[4], sizeof(rec.speed_kts)-1);
                if (nf > 5) strncpy(rec.hdop,        fields[5], sizeof(rec.hdop)-1);
                rec.location_type = (strcmp(rtype,"Fix,GPS")==0) ? LOC_GPS : LOC_NETWORK;
                strncpy(rec.fix_quality, "1", 2);
                GPSCoord *coord = get_or_create_coord(lat, lon);
                push_record(coord, &rec);
                coords_found++;
            }
        }
    }

    fclose(f);
    fprintf(stderr, "[CTW-11] Android GNSS log: %d Fix records -> %d coords  (%s)\n",
            coords_found, coord_count, filepath);
}

/* detect Android GNSS Logger file by sniffing first non-empty line */
static int is_android_gnss_log(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;
    char line[512];

    /* Score-based detection: Android GNSS Logger files have a long
     * header block (often 60-150 lines) before any data rows.
     * We scan up to 500 lines and accumulate evidence points.
     * A score >= 2 means confident match.                         */
    int score  = 0;
    int tries  = 0;
    int has_fix_header  = 0;
    int has_raw_header  = 0;
    int has_fix_data    = 0;
    int has_sensor_data = 0;
    int has_version     = 0;

    while (tries < 500 && fgets(line, sizeof(line), f)) {
        tries++;

        /* Strong single-line indicators — immediate accept */
        if (strstr(line, "GNSS Logger"))          { score += 5; break; }
        if (strstr(line, "Version: v") &&
            strstr(line, "Platform:"))             { has_version = 1; score += 3; }
        if (strstr(line, "HardwareClockDiscontinuityCount")) { score += 3; }
        if (strstr(line, "KlobucharAlpha"))        { score += 3; }
        if (strstr(line, "SatelliteInterSignalBias")) { score += 3; }

        /* Fix header line */
        if ((strstr(line, "Fix,Provider") ||
             strstr(line, "# Fix,Provider")) &&
            strstr(line, "LatitudeDegrees"))  { has_fix_header = 1; score += 3; }

        /* Raw header */
        if (strstr(line, "Raw,utcTimeMillis") &&
            strstr(line, "TimeNanos"))         { has_raw_header = 1; score += 2; }

        /* Sensor headers */
        if (strstr(line, "UncalAccel,") ||
            strstr(line, "UncalGyro,")  ||
            strstr(line, "UncalMag,"))         { has_sensor_data = 1; score += 1; }

        /* Actual Fix data row */
        if (strncmp(line, "Fix,", 4) == 0)    { has_fix_data = 1; score += 2; }

        /* Constellation / pseudorange field names in header */
        if (strstr(line, "ConstellationType") &&
            strstr(line, "CarrierFrequencyHz")) { score += 2; }
        if (strstr(line, "PseudorangeRateMetersPerSecond")) { score += 2; }
        if (strstr(line, "AccumulatedDeltaRangeMeters"))    { score += 2; }

        /* Early exit if already confident */
        if (score >= 4) break;
    }

    fclose(f);

    /* Also accept if we have complementary weaker signals */
    if (has_fix_header && has_sensor_data) score += 2;
    if (has_raw_header && has_sensor_data) score += 2;
    if (has_version    && has_fix_data)    score += 2;

    fprintf(stderr, "[CTW-11] sniffer: %s  score=%d lines_scanned=%d\n",
            filepath, score, tries);

    return score >= 2;
}

/* ─── folder scanner ─────────────────────────────────────────────────────── */

static int ext_is(const char *name, const char *ext)
{ const char *d = strrchr(name, '.'); return d && strcasecmp(d, ext) == 0; }

static int is_nmea(const char *n)
{ return ext_is(n,".nmea")||ext_is(n,".nma")||ext_is(n,".log")||ext_is(n,".txt"); }

static int is_rinex(const char *n)
{
    if (ext_is(n,".rnx")||ext_is(n,".obs")) return 1;
    const char *d = strrchr(n,'.');
    return d && strlen(d)==3 && tolower((unsigned char)d[2])=='o';
}

static void scan_folder(const char *folder)
{
    char path[2048];

    /* Try known filenames first */
    snprintf(path, sizeof(path), "%s/gnss_log.txt", folder);
    if (is_android_gnss_log(path)) parse_android_gnss_log(path);
    else                            parse_gnss_log(path);

    snprintf(path, sizeof(path), "%s/rnx_data.txt", folder);
    parse_rinex_file(path);

    DIR *dir = opendir(folder);
    if (!dir) { fprintf(stderr,"[CTW-11] Cannot open: %s\n", folder); return; }

    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.') continue;
        if (!strcmp(ent->d_name,"gnss_log.txt")) continue;
        if (!strcmp(ent->d_name,"rnx_data.txt"))  continue;

        snprintf(path, sizeof(path), "%s/%s", folder, ent->d_name);

        if (is_rinex(ent->d_name)) {
            parse_rinex_file(path);
        } else if (is_android_gnss_log(path)) {
            /* Android GNSS Logger — txt or log extension */
            parse_android_gnss_log(path);
        } else if (is_nmea(ent->d_name)) {
            parse_nmea_file(path);
        }
    }
    closedir(dir);
}

/* ─── persist per-coordinate data ────────────────────────────────────────── */

static void save_coord_data(GPSCoord *c)
{
    if (!c) return;
    char fpath[2048];

    snprintf(fpath, sizeof(fpath), "%s/raw_nmea.txt", c->folder);
    FILE *f = fopen(fpath, "w");
    if (f) {
        fprintf(f, "# RAW RECORDS  %.6f, %.6f\n\n", c->lat, c->lon);
        for (int i = 0; i < c->rec_count; i++)
            fprintf(f, "%s\n", c->recs[i].raw_line);
        fclose(f);
    }

    snprintf(fpath, sizeof(fpath), "%s/metadata.txt", c->folder);
    f = fopen(fpath, "w");
    if (f) {
        fprintf(f,
            "====================================================\n"
            "  CTW-11 GNSS Mapper v2.0 — Coordinate Metadata\n"
            "  Made by Christopher Williams\n"
            "====================================================\n"
            "  Lat:      %.8f\n"
            "  Lon:      %.8f\n"
            "  Best Fix: %d\n"
            "  Records:  %d\n"
            "====================================================\n\n",
            c->lat, c->lon, c->best_fix, c->rec_count);

        for (int i = 0; i < c->rec_count; i++) {
            NMEARecord *r = &c->recs[i];
            fprintf(f, "--- Record %d [%s] ---\n", i+1, r->sentence_type);
            if (r->timestamp[0])   fprintf(f, "  Time:      %s\n", r->timestamp);
            if (r->date[0])        fprintf(f, "  Date:      %s\n", r->date);
            if (r->fix_quality[0]) fprintf(f, "  Fix:       %s\n", r->fix_quality);
            if (r->satellites[0])  fprintf(f, "  Sats:      %s\n", r->satellites);
            if (r->hdop[0])        fprintf(f, "  HDOP:      %s\n", r->hdop);
            if (r->altitude[0])    fprintf(f, "  Alt:       %s %s\n", r->altitude, r->alt_unit);
            if (r->speed_kts[0])   fprintf(f, "  Speed:     %s kts\n", r->speed_kts);
            if (r->course_deg[0])  fprintf(f, "  Course:    %s\n", r->course_deg);
            if (r->sv_prn[0])      fprintf(f, "  SV PRN:    %s\n", r->sv_prn);
            if (r->sv_snr[0])      fprintf(f, "  SV SNR:    %s\n", r->sv_snr);
            if (r->sv_elev[0])     fprintf(f, "  SV Elev:   %s\n", r->sv_elev);
            if (r->sv_azim[0])     fprintf(f, "  SV Azim:   %s\n", r->sv_azim);
            if (r->rinex_epoch[0]) fprintf(f, "  RNX Epoch: %s\n", r->rinex_epoch);
            if (r->rinex_obs[0])   fprintf(f, "  RNX Obs:   %s\n", r->rinex_obs);
            fprintf(f, "  Source:    %s\n\n", r->source_file);
        }
        fclose(f);
    }

    snprintf(fpath, sizeof(fpath), "%s/satellite_info.txt", c->folder);
    f = fopen(fpath, "w");
    if (f) {
        fprintf(f, "# SATELLITE DATA  %.6f, %.6f\n\n", c->lat, c->lon);
        for (int i = 0; i < c->rec_count; i++) {
            NMEARecord *r = &c->recs[i];
            if (strcmp(r->sentence_type,"GSV") == 0)
                fprintf(f,"PRN: %s\nSNR: %s\nElev: %s\nAzim: %s\n\n",
                        r->sv_prn, r->sv_snr, r->sv_elev, r->sv_azim);
        }
        fclose(f);
    }
}

/* ─── export single structured file ─────────────────────────────────────── */

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

    const char *fix_names[] = {
        "No Fix","GPS","DGPS","PPS","RTK Fixed","RTK Float","Dead Reckoning"
    };
    int fi = (c->best_fix >= 0 && c->best_fix <= 6) ? c->best_fix : 0;

    fprintf(f,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║   CTW-11 GNSS MAPPER v2.0 — COORDINATE EXPORT            ║\n"
        "║   Made by Christopher Williams                            ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║   Exported  : %-43s ║\n"
        "║   Latitude  : %-43.8f ║\n"
        "║   Longitude : %-43.8f ║\n"
        "║   Best Fix  : %-43s ║\n"
        "║   Records   : %-43d ║\n"
        "║   Output    : %-43s ║\n"
        "╚══════════════════════════════════════════════════════════╝\n\n",
        ts, c->lat, c->lon, fix_names[fi], c->rec_count, c->folder);

    for (int i = 0; i < c->rec_count; i++) {
        NMEARecord *r = &c->recs[i];
        fprintf(f, "┌─ Record %d ── [%s] ─────────────────────────────────┐\n",
                i+1, r->sentence_type);
        fprintf(f, "│  Raw      : %s\n", r->raw_line);
        fprintf(f, "│  Source   : %s\n", r->source_file);
        if (r->timestamp[0])   fprintf(f,"│  Time     : %s\n", r->timestamp);
        if (r->date[0])        fprintf(f,"│  Date     : %s\n", r->date);
        if (r->fix_quality[0]) fprintf(f,"│  Fix      : %s\n", r->fix_quality);
        if (r->satellites[0])  fprintf(f,"│  Sats     : %s\n", r->satellites);
        if (r->hdop[0])        fprintf(f,"│  HDOP     : %s\n", r->hdop);
        if (r->altitude[0])    fprintf(f,"│  Alt      : %s %s\n", r->altitude, r->alt_unit);
        if (r->speed_kts[0])   fprintf(f,"│  Speed    : %s kts\n", r->speed_kts);
        if (r->course_deg[0])  fprintf(f,"│  Course   : %s°\n", r->course_deg);
        if (r->sv_prn[0])      fprintf(f,"│  SV PRN   : %s\n", r->sv_prn);
        if (r->sv_snr[0])      fprintf(f,"│  SV SNR   : %s\n", r->sv_snr);
        if (r->sv_elev[0])     fprintf(f,"│  SV Elev  : %s\n", r->sv_elev);
        if (r->sv_azim[0])     fprintf(f,"│  SV Azim  : %s\n", r->sv_azim);
        if (r->rinex_epoch[0]) fprintf(f,"│  RNX Epch : %s\n", r->rinex_epoch);
        if (r->rinex_obs[0])   fprintf(f,"│  RNX Obs  : %s\n", r->rinex_obs);
        fprintf(f,"└────────────────────────────────────────────────────────┘\n\n");
    }
    fclose(f);

    GtkWidget *dlg = gtk_message_dialog_new(GTK_WINDOW(main_window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "✅ Exported to:\n\n%s", fpath);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

/* ─── coordinate → screen pixel ──────────────────────────────────────────── */

/* pixels per mile — true physical inch = 1 mile when zoom=1, ratio=1
 * map_ratio: miles represented by 1 physical inch
 *   ratio=1   → 1 inch = 1 mile  (default)
 *   ratio=2   → 1 inch = 2 miles (zoomed out)
 *   ratio=0.5 → 1 inch = 0.5 miles (zoomed in)
 * ppm = (SCREEN_DPI / ratio) * zoom_level                             */
static double get_ppm(void)
{
    double ratio = (map_ratio > 0.0001) ? map_ratio : 1.0;
    return (SCREEN_DPI / ratio) * zoom_level;
}

static void coord_to_px(double lat, double lon, int w, int h,
                         double *px, double *py)
{
    double ref = ground_lat * M_PI / 180.0;
    double ppm = get_ppm();
    *px = w/2.0 + pan_x + (lon-ground_lon)*cos(ref)*MILES_PER_DEG_LAT*ppm;
    *py = h/2.0 + pan_y - (lat-ground_lat)          *MILES_PER_DEG_LAT*ppm;
}

/* inverse: screen pixel → geographic coordinate */
static void px_to_coord(double px, double py, int w, int h,
                         double *lat, double *lon)
{
    double ref = ground_lat * M_PI / 180.0;
    double ppm = get_ppm();
    double dy  = (h/2.0 + pan_y - py) / ppm;
    double dx  = (px - w/2.0 - pan_x) / ppm;
    *lat = ground_lat + dy / MILES_PER_DEG_LAT;
    *lon = ground_lon + dx / (MILES_PER_DEG_LAT * cos(ref));
}

/* ─── fix-quality dot colour ─────────────────────────────────────────────── */

static void set_dot_colour(cairo_t *cr, int fix, double alpha)
{
    switch (fix) {
        case 0:  cairo_set_source_rgba(cr, 1.0, 0.10, 0.10, alpha); break;
        case 1:  cairo_set_source_rgba(cr, 1.0, 0.40, 0.00, alpha); break;
        case 2:  cairo_set_source_rgba(cr, 1.0, 0.85, 0.00, alpha); break;
        case 3:  cairo_set_source_rgba(cr, 0.0, 0.85, 1.00, alpha); break;
        case 4:  cairo_set_source_rgba(cr, 0.0, 1.00, 0.20, alpha); break;
        default: cairo_set_source_rgba(cr, 0.6, 0.60, 1.00, alpha); break;
    }
}

/* Draw a dot shaped by location type:
   GPS/DGPS/RTK : neon-orange filled circle  (satellite fix)
   Network/Cell : blue filled diamond        (assisted/cell)
   RINEX        : cyan filled square         (post-process)  */
static void draw_location_dot(cairo_t *cr, double px, double py,
                               int loc_type, int fix_qual, int stack)
{
    double r = DOT_RADIUS;

    /* --- outer glow --- */
    if (loc_type == LOC_NETWORK) {
        cairo_set_source_rgba(cr, 0.10, 0.50, 1.00, 0.22);
    } else if (loc_type == LOC_RINEX) {
        cairo_set_source_rgba(cr, 0.00, 0.90, 0.90, 0.22);
    } else {
        set_dot_colour(cr, fix_qual, 0.22);
    }
    cairo_arc(cr, px, py, r+4, 0, 2*M_PI); cairo_fill(cr);

    /* --- shape fill --- */
    if (loc_type == LOC_NETWORK) {
        /* blue diamond */
        cairo_set_source_rgba(cr, 0.10, 0.55, 1.00, 0.95);
        cairo_move_to(cr, px,   py-r);
        cairo_line_to(cr, px+r, py);
        cairo_line_to(cr, px,   py+r);
        cairo_line_to(cr, px-r, py);
        cairo_close_path(cr); cairo_fill(cr);
        /* white border */
        cairo_set_source_rgba(cr, 1,1,1,1);
        cairo_set_line_width(cr, 1.8);
        cairo_move_to(cr, px,   py-r);
        cairo_line_to(cr, px+r, py);
        cairo_line_to(cr, px,   py+r);
        cairo_line_to(cr, px-r, py);
        cairo_close_path(cr); cairo_stroke(cr);
        /* inner label N */
        cairo_set_source_rgba(cr, 1,1,1,1);
        cairo_select_font_face(cr,"monospace",
            CAIRO_FONT_SLANT_NORMAL,CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 7.0);
        cairo_move_to(cr, px-3.5, py+3); cairo_show_text(cr,"N");
    } else if (loc_type == LOC_RINEX) {
        /* cyan square */
        cairo_set_source_rgba(cr, 0.00, 0.90, 0.90, 0.95);
        cairo_rectangle(cr, px-r, py-r, r*2, r*2); cairo_fill(cr);
        cairo_set_source_rgba(cr, 1,1,1,1);
        cairo_set_line_width(cr, 1.8);
        cairo_rectangle(cr, px-r, py-r, r*2, r*2); cairo_stroke(cr);
        cairo_set_source_rgba(cr, 0,0,0,1);
        cairo_arc(cr, px, py, 2.8, 0, 2*M_PI); cairo_fill(cr);
    } else {
        /* GPS/DGPS/RTK — neon orange circle */
        set_dot_colour(cr, fix_qual, 0.95);
        cairo_arc(cr, px, py, r, 0, 2*M_PI); cairo_fill(cr);
        cairo_set_source_rgba(cr, 1,1,1,1);
        cairo_set_line_width(cr, 1.8);
        cairo_arc(cr, px, py, r, 0, 2*M_PI); cairo_stroke(cr);
        cairo_set_source_rgba(cr, 0,0,0,1);
        cairo_arc(cr, px, py, 2.8, 0, 2*M_PI); cairo_fill(cr);
    }

    /* --- stack badge --- */
    if (stack > 0) {
        char badge[8]; snprintf(badge,sizeof(badge),"+%d",stack);
        cairo_set_source_rgba(cr, 1,1,0,1);
        cairo_select_font_face(cr,"monospace",
            CAIRO_FONT_SLANT_NORMAL,CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 8.0);
        cairo_move_to(cr, px+r+1, py-r);
        cairo_show_text(cr, badge);
    }
}

/* ─── adaptive scale bar ─────────────────────────────────────────────────── */

static double nice_miles(double raw)
{
    if (raw <= 0) return 1.0;
    double mag = pow(10.0, floor(log10(raw)));
    double f   = raw / mag;
    double n   = (f < 1.5) ? 1.0 : (f < 3.5) ? 2.0 : (f < 7.5) ? 5.0 : 10.0;
    return n * mag;
}

/* ─── drawing ─────────────────────────────────────────────────────────────── */

static gboolean on_draw(GtkWidget *widget, cairo_t *cr, gpointer ud)
{
    int W = gtk_widget_get_allocated_width(widget);
    int H = gtk_widget_get_allocated_height(widget);

    /* background 75% black */
    cairo_set_source_rgba(cr, 0, 0, 0, 0.75);
    cairo_paint(cr);

    /* apply whole-window alpha to background */
    double cell  = get_ppm();
    double ox    = W/2.0 + pan_x;
    double oy    = H/2.0 + pan_y;

    /* minor grid (1 mile) */
    cairo_set_source_rgba(cr, 1, 1, 1, 0.28);
    cairo_set_line_width(cr, 0.5);
    double sx = fmod(ox, cell); if (sx < 0) sx += cell;
    for (double x = sx; x <= W; x += cell) {
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, H); cairo_stroke(cr);
    }
    double sy = fmod(oy, cell); if (sy < 0) sy += cell;
    for (double y = sy; y <= H; y += cell) {
        cairo_move_to(cr, 0, y); cairo_line_to(cr, W, y); cairo_stroke(cr);
    }

    /* major grid (5 miles) */
    double cell5 = cell * 5.0;
    cairo_set_source_rgba(cr, 1, 1, 1, 0.65);
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

    /* ground truth crosshair */
    double gx, gy;
    coord_to_px(ground_lat, ground_lon, W, H, &gx, &gy);

    cairo_set_source_rgba(cr, 0, 1, 0.25, 0.20);
    cairo_arc(cr, gx, gy, 18.0, 0, 2*M_PI); cairo_fill(cr);
    cairo_set_source_rgba(cr, 0, 1, 0.25, 1.0);
    cairo_arc(cr, gx, gy, 7.0, 0, 2*M_PI); cairo_fill(cr);
    cairo_set_source_rgba(cr, 1, 1, 1, 1.0);
    cairo_set_line_width(cr, 1.5);
    cairo_arc(cr, gx, gy, 7.0, 0, 2*M_PI); cairo_stroke(cr);
    cairo_set_source_rgba(cr, 0, 1, 0.25, 0.85);
    cairo_set_line_width(cr, 1.0);
    cairo_move_to(cr, gx-20, gy); cairo_line_to(cr, gx+20, gy); cairo_stroke(cr);
    cairo_move_to(cr, gx, gy-20); cairo_line_to(cr, gx, gy+20); cairo_stroke(cr);
    cairo_set_font_size(cr, 10.5);
    cairo_move_to(cr, gx+14, gy-6);  cairo_show_text(cr, "GROUND TRUTH");
    char gll[64];
    snprintf(gll, sizeof(gll), "%.6f, %.6f", ground_lat, ground_lon);
    cairo_move_to(cr, gx+14, gy+8);  cairo_show_text(cr, gll);

    /* data dots — with stack badge */
    for (int i = 0; i < coord_count; i++) {
        double px, py;
        coord_to_px(coords[i].lat, coords[i].lon, W, H, &px, &py);
        if (px < -30 || px > W+30 || py < -30 || py > H+30) continue;

        /* count neighbours for stack badge */
        int stack = 0;
        for (int j = 0; j < coord_count; j++) {
            if (i == j) continue;
            double qx, qy;
            coord_to_px(coords[j].lat, coords[j].lon, W, H, &qx, &qy);
            if (hypot(px-qx, py-qy) < DOT_RADIUS * 1.5) stack++;
        }
        draw_location_dot(cr, px, py,
                          coords[i].dominant_loc,
                          coords[i].best_fix,
                          stack);

        /* coordinate label at high zoom */
        if (zoom_level >= LABEL_ZOOM) {
            cairo_set_source_rgba(cr, 1, 1, 1, 0.85);
            cairo_set_font_size(cr, 9.0);
            char lbl[64];
            snprintf(lbl, sizeof(lbl), "%.5f,%.5f", coords[i].lat, coords[i].lon);
            cairo_move_to(cr, px + DOT_RADIUS + 4, py + 4);
            cairo_show_text(cr, lbl);
        }
    }

    /* adaptive scale bar */
    double miles_per_px  = 1.0 / get_ppm();
    double raw_bar_miles = nice_miles(150.0 * miles_per_px);
    double bar_px        = raw_bar_miles / miles_per_px;
    char   bar_lbl[32];
    if (raw_bar_miles < 0.1)
        snprintf(bar_lbl, sizeof(bar_lbl), "%.3f mi", raw_bar_miles);
    else if (raw_bar_miles < 1.0)
        snprintf(bar_lbl, sizeof(bar_lbl), "%.2f mi", raw_bar_miles);
    else
        snprintf(bar_lbl, sizeof(bar_lbl), "%.4g mi", raw_bar_miles);

    double bx = 20.0, by = H - 22.0;
    cairo_set_source_rgba(cr, 1, 1, 1, 0.9);
    cairo_set_line_width(cr, 2.0);
    cairo_move_to(cr, bx, by);       cairo_line_to(cr, bx+bar_px, by); cairo_stroke(cr);
    cairo_move_to(cr, bx, by-7);     cairo_line_to(cr, bx, by+7);      cairo_stroke(cr);
    cairo_move_to(cr, bx+bar_px, by-7); cairo_line_to(cr, bx+bar_px, by+7); cairo_stroke(cr);
    cairo_set_font_size(cr, 10.0);
    cairo_move_to(cr, bx + bar_px/2 - 20, by - 8);
    cairo_show_text(cr, bar_lbl);

    /* coord count + zoom */
    cairo_set_source_rgba(cr, 1, 0.40, 0, 0.85);
    cairo_set_font_size(cr, 10.0);
    char info[80];
    snprintf(info, sizeof(info), "Coords: %d   Zoom: %.2f×", coord_count, zoom_level);
    cairo_move_to(cr, 20, H - 38);
    cairo_show_text(cr, info);

    /* fix legend (bottom-right) */
    struct { int fix; const char *label; } legend[] = {
        {0,"No Fix"},{1,"GPS"},{2,"DGPS"},{3,"PPS"},{4,"RTK Fixed"},{-1,NULL}
    };
    double lx = W - 130, ly = H - 105;
    cairo_set_font_size(cr, 9.5);
    for (int i = 0; legend[i].label; i++) {
        set_dot_colour(cr, legend[i].fix, 0.9);
        cairo_arc(cr, lx, ly + i*16, 5.0, 0, 2*M_PI); cairo_fill(cr);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.8);
        cairo_set_line_width(cr, 1.0);
        cairo_arc(cr, lx, ly + i*16, 5.0, 0, 2*M_PI); cairo_stroke(cr);
        cairo_set_source_rgba(cr, 1, 1, 1, 0.85);
        cairo_move_to(cr, lx + 10, ly + i*16 + 4);
        cairo_show_text(cr, legend[i].label);
    }

    /* watermark */
    cairo_set_source_rgba(cr, 1, 0.40, 0, 0.35);
    cairo_set_font_size(cr, 9.0);
    cairo_move_to(cr, W - 385, H - 6);
    cairo_show_text(cr, "CTW-11 GNSS COORDINATE MAPPER v2.0  —  Made by Christopher Williams");

    return FALSE;
}

/* ─── popup detail window ────────────────────────────────────────────────── */

static void on_export_btn(GtkButton *btn, gpointer data) { export_coord((GPSCoord *)data); }

static void show_detail_popup(GPSCoord *c)
{
    if (!c) return;
    if (popup_window) { gtk_widget_destroy(popup_window); popup_window = NULL; }

    popup_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[128];
    snprintf(title, sizeof(title), "📍 %.6f, %.6f  [%d records]",
             c->lat, c->lon, c->rec_count);
    gtk_window_set_title(GTK_WINDOW(popup_window), title);
    gtk_window_set_default_size(GTK_WINDOW(popup_window), 640, 540);
    gtk_window_set_transient_for(GTK_WINDOW(popup_window),
                                 GTK_WINDOW(main_window));
    gtk_window_set_position(GTK_WINDOW(popup_window),
                            GTK_WIN_POS_CENTER_ON_PARENT);
    g_signal_connect(popup_window, "destroy",
                     G_CALLBACK(gtk_widget_destroyed), &popup_window);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);
    gtk_container_add(GTK_CONTAINER(popup_window), vbox);

    const char *fix_names[] = {
        "No Fix","GPS","DGPS","PPS","RTK Fixed","RTK Float","Dead Reckoning"
    };
    int fi = (c->best_fix >= 0 && c->best_fix <= 6) ? c->best_fix : 0;
    char hdr[256];
    snprintf(hdr, sizeof(hdr),
             "Lat: %.8f    Lon: %.8f    Best Fix: %s    Records: %d",
             c->lat, c->lon, fix_names[fi], c->rec_count);
    GtkWidget *lbl = gtk_label_new(hdr);
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), lbl, FALSE, FALSE, 0);

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
        "  CTW-11 GNSS Coordinate Detail  v2.0\n"
        "  Made by Christopher Williams\n"
        "══════════════════════════════════════════════════════════\n"
        "  Latitude  : %.8f\n"
        "  Longitude : %.8f\n"
        "  Best Fix  : %s\n"
        "  Records   : %d\n"
        "  Folder    : %s\n"
        "══════════════════════════════════════════════════════════\n\n",
        c->lat, c->lon, fix_names[fi], c->rec_count, c->folder);

    for (int i = 0; i < c->rec_count; i++) {
        NMEARecord *r = &c->recs[i];
        g_string_append_printf(txt,
            "┌── Record %-4d [%-8s] ────────────────────────────────\n",
            i+1, r->sentence_type);
        g_string_append_printf(txt, "│  Raw      : %s\n", r->raw_line);
        g_string_append_printf(txt, "│  Source   : %s\n", r->source_file);
        if (r->timestamp[0])   g_string_append_printf(txt,"│  Time     : %s\n", r->timestamp);
        if (r->date[0])        g_string_append_printf(txt,"│  Date     : %s\n", r->date);
        if (r->fix_quality[0]) g_string_append_printf(txt,"│  Fix Qual : %s\n", r->fix_quality);
        if (r->satellites[0])  g_string_append_printf(txt,"│  Sats     : %s\n", r->satellites);
        if (r->hdop[0])        g_string_append_printf(txt,"│  HDOP     : %s\n", r->hdop);
        if (r->altitude[0])    g_string_append_printf(txt,"│  Altitude : %s %s\n", r->altitude, r->alt_unit);
        if (r->speed_kts[0])   g_string_append_printf(txt,"│  Speed    : %s kts\n", r->speed_kts);
        if (r->course_deg[0])  g_string_append_printf(txt,"│  Course   : %s°\n", r->course_deg);
        if (r->sv_prn[0])      g_string_append_printf(txt,"│  SV PRN   : %s\n", r->sv_prn);
        if (r->sv_snr[0])      g_string_append_printf(txt,"│  SV SNR   : %s\n", r->sv_snr);
        if (r->sv_elev[0])     g_string_append_printf(txt,"│  SV Elev  : %s\n", r->sv_elev);
        if (r->sv_azim[0])     g_string_append_printf(txt,"│  SV Azim  : %s\n", r->sv_azim);
        if (r->rinex_epoch[0]) g_string_append_printf(txt,"│  RNX Epoch: %s\n", r->rinex_epoch);
        if (r->rinex_obs[0])   g_string_append_printf(txt,"│  RNX Obs  : %s\n", r->rinex_obs);
        g_string_append(txt,
            "└────────────────────────────────────────────────────────\n\n");
    }

    gtk_text_buffer_set_text(buf, txt->str, -1);
    g_string_free(txt, TRUE);

    GtkWidget *btn = gtk_button_new_with_label(
        "⬇  Export This Coordinate — Structured Single File");
    g_signal_connect(btn, "clicked", G_CALLBACK(on_export_btn), c);
    gtk_box_pack_start(GTK_BOX(vbox), btn, FALSE, FALSE, 0);

    gtk_widget_show_all(popup_window);
}

/* ─── hit test ───────────────────────────────────────────────────────────── */

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

/* ─── mouse events ───────────────────────────────────────────────────────── */

static gboolean on_button_press(GtkWidget *widget, GdkEventButton *ev, gpointer ud)
{
    int W = gtk_widget_get_allocated_width(widget);
    int H = gtk_widget_get_allocated_height(widget);

    if (ev->button == 1) {
        GPSCoord *c = hit_test(ev->x, ev->y, W, H);
        if (c) show_detail_popup(c);
    }
    else if (ev->button == 2) {
        dragging = TRUE;
        drag_sx = ev->x; drag_sy = ev->y;
        drag_px = pan_x; drag_py = pan_y;
    }
    else if (ev->button == 3) {
        GPSCoord *c = hit_test(ev->x, ev->y, W, H);
        if (c) {
            GtkWidget *menu = gtk_menu_new();
            char lbl[128];
            snprintf(lbl, sizeof(lbl), "Export  %.6f, %.6f", c->lat, c->lon);
            GtkWidget *exp = gtk_menu_item_new_with_label(lbl);
            g_signal_connect(exp, "activate", G_CALLBACK(on_export_btn), c);
            gtk_menu_shell_append(GTK_MENU_SHELL(menu), exp);
            gtk_menu_shell_append(GTK_MENU_SHELL(menu),
                                  gtk_separator_menu_item_new());
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

/* update status bar with live mouse lat/lon */
static gboolean on_motion(GtkWidget *widget, GdkEventMotion *ev, gpointer ud)
{
    int W = gtk_widget_get_allocated_width(widget);
    int H = gtk_widget_get_allocated_height(widget);

    if (dragging) {
        pan_x = drag_px + (ev->x - drag_sx);
        pan_y = drag_py + (ev->y - drag_sy);
        gtk_widget_queue_draw(widget);
    }

    /* live lat/lon in status bar */
    if (status_label) {
        double lat, lon;
        px_to_coord(ev->x, ev->y, W, H, &lat, &lon);
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "  Cursor: %.6f, %.6f    Zoom: %.3f×    Coords loaded: %d",
                 lat, lon, zoom_level, coord_count);
        gtk_label_set_text(GTK_LABEL(status_label), msg);
    }
    return TRUE;
}

/* zoom toward cursor */
static gboolean on_scroll(GtkWidget *widget, GdkEventScroll *ev, gpointer ud)
{
    int W = gtk_widget_get_allocated_width(widget);
    int H = gtk_widget_get_allocated_height(widget);

    double factor = (ev->direction == GDK_SCROLL_UP) ? 1.18 : 1.0/1.18;

    /* world-space position under cursor before zoom */
    double ppm0 = get_ppm();
    double wx = (ev->x - W/2.0 - pan_x) / ppm0;
    double wy = (ev->y - H/2.0 - pan_y) / ppm0;

    zoom_level *= factor;
    if (zoom_level < 0.004) zoom_level = 0.004;
    if (zoom_level > 600.0) zoom_level = 600.0;

    /* pan to keep cursor over same world point */
    double ppm1 = get_ppm();
    pan_x = ev->x - W/2.0 - wx * ppm1;
    pan_y = ev->y - H/2.0 - wy * ppm1;

    gtk_widget_queue_draw(widget);
    toolbar_update_zoom();
    return TRUE;
}

/* ─── dialogs ─────────────────────────────────────────────────────────────── */

static void show_ground_truth_dialog(void)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Set Ground Truth GPS Coordinate",
        GTK_WINDOW(main_window), GTK_DIALOG_MODAL,
        "_Set", GTK_RESPONSE_OK, "_Cancel", GTK_RESPONSE_CANCEL, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 420, 210);

    GtkWidget *ca   = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 16);
    gtk_container_add(GTK_CONTAINER(ca), grid);

    GtkWidget *l1 = gtk_label_new("Latitude  (decimal degrees):");
    GtkWidget *l2 = gtk_label_new("Longitude (decimal degrees):");
    GtkWidget *e1 = gtk_entry_new();
    GtkWidget *e2 = gtk_entry_new();
    gtk_widget_set_hexpand(e1, TRUE);
    gtk_widget_set_hexpand(e2, TRUE);

    char buf[32];
    snprintf(buf, sizeof(buf), "%.6f", ground_lat);
    gtk_entry_set_text(GTK_ENTRY(e1), buf);
    snprintf(buf, sizeof(buf), "%.6f", ground_lon);
    gtk_entry_set_text(GTK_ENTRY(e2), buf);

    gtk_grid_attach(GTK_GRID(grid), l1, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), e1, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), l2, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), e2, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid),
        gtk_label_new("Green dot = map centre reference point."),
        0, 2, 2, 1);

    gtk_widget_show_all(dlg);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        double lat = atof(gtk_entry_get_text(GTK_ENTRY(e1)));
        double lon = atof(gtk_entry_get_text(GTK_ENTRY(e2)));
        if (fabs(lat) <= 90.0 && fabs(lon) <= 180.0) {
            ground_lat = lat; ground_lon = lon;
        }
    }
    gtk_widget_destroy(dlg);
    gtk_widget_queue_draw(drawing_area);
}

static void show_parse_dialog(void)
{
    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "Parse GNSS Data Folder",
        GTK_WINDOW(main_window), GTK_DIALOG_MODAL,
        "_Parse", GTK_RESPONSE_OK, "_Cancel", GTK_RESPONSE_CANCEL, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 580, 175);

    GtkWidget *ca = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *vb = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vb), 14);
    gtk_container_add(GTK_CONTAINER(ca), vb);

    gtk_box_pack_start(GTK_BOX(vb),
        gtk_label_new(
            "Enter FULL PATH to folder with GNSS data.\n"
            "Parsed: Android GNSS Logger (*.txt/*.log) · gnss_log.txt · rnx_data.txt · *.nmea · *.rnx · *.obs"),
        FALSE, FALSE, 0);

    GtkWidget *ent = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(ent), "/full/path/to/gnss/data");
    gtk_entry_set_width_chars(GTK_ENTRY(ent), 62);
    gtk_box_pack_start(GTK_BOX(vb), ent, FALSE, FALSE, 0);
    gtk_widget_show_all(dlg);

    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_OK) {
        const char *path = gtk_entry_get_text(GTK_ENTRY(ent));
        if (path && path[0]) {
            int prev = coord_count;
            gtk_widget_destroy(dlg); dlg = NULL;

            scan_folder(path);
            for (int i = prev; i < coord_count; i++)
                save_coord_data(&coords[i]);

            gtk_widget_queue_draw(drawing_area);

            GtkWidget *info = gtk_message_dialog_new(GTK_WINDOW(main_window),
                GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                "✅ Parse complete\n\n"
                "New coordinates : %d\n"
                "Total on map    : %d\n"
                "Output folder   : %s",
                coord_count - prev, coord_count, output_base);
            gtk_dialog_run(GTK_DIALOG(info));
            gtk_widget_destroy(info);
            return;
        }
    }
    if (dlg) gtk_widget_destroy(dlg);
}

static void show_about_dialog(void)
{
    GtkWidget *dlg = gtk_message_dialog_new(
        GTK_WINDOW(main_window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
        "CTW-11 GNSS Coordinate Mapper  v2.0\n\n"
        "Made by Christopher Williams\n\n"
        "Scale      : 1 screen inch = 1 mile\n"
        "Grid       : White (minor 1-mi · major 5-mi)\n"
        "Background : 75%% translucent black\n"
        "Dot colour : fix-quality coded\n\n"
        "Left-click dot    → detail popup\n"
        "Right-click dot   → export menu\n"
        "Middle-drag       → pan\n"
        "Scroll wheel      → zoom (toward cursor)\n"
        "Ctrl+O            → parse folder\n"
        "Ctrl+Q            → quit\n"
        "R                 → reset view\n"
        "G                 → set ground truth");
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

/* ─── keyboard shortcuts ─────────────────────────────────────────────────── */

static gboolean on_key_press(GtkWidget *widget, GdkEventKey *ev, gpointer ud)
{
    gboolean ctrl = (ev->state & GDK_CONTROL_MASK) != 0;

    if (ctrl && (ev->keyval == GDK_KEY_o || ev->keyval == GDK_KEY_O)) {
        show_parse_dialog(); return TRUE;
    }
    if (ctrl && (ev->keyval == GDK_KEY_q || ev->keyval == GDK_KEY_Q)) {
        gtk_main_quit(); return TRUE;
    }
    if (ev->keyval == GDK_KEY_r || ev->keyval == GDK_KEY_R) {
        pan_x = pan_y = 0.0; zoom_level = 1.0;
        gtk_widget_queue_draw(drawing_area); return TRUE;
    }
    if (ev->keyval == GDK_KEY_g || ev->keyval == GDK_KEY_G) {
        show_ground_truth_dialog(); return TRUE;
    }
    /* arrow-key pan */
    double step = 40.0;
    if      (ev->keyval == GDK_KEY_Left)  { pan_x += step; gtk_widget_queue_draw(drawing_area); return TRUE; }
    else if (ev->keyval == GDK_KEY_Right) { pan_x -= step; gtk_widget_queue_draw(drawing_area); return TRUE; }
    else if (ev->keyval == GDK_KEY_Up)    { pan_y += step; gtk_widget_queue_draw(drawing_area); return TRUE; }
    else if (ev->keyval == GDK_KEY_Down)  { pan_y -= step; gtk_widget_queue_draw(drawing_area); return TRUE; }
    return FALSE;
}

/* ─── menu bar ───────────────────────────────────────────────────────────── */

/* ─── toolbar callbacks ──────────────────────────────────────────────────── */

static void on_ratio_changed(GtkEntry *e, gpointer d)
{
    const char *txt = gtk_entry_get_text(e);
    double v = atof(txt);
    if (v > 0.0) {
        map_ratio = v;
        gtk_widget_queue_draw(drawing_area);
    }
}

static void on_ratio_activate(GtkEntry *e, gpointer d) { on_ratio_changed(e, d); }

static void on_alpha_changed(GtkRange *r, gpointer d)
{
    win_alpha = gtk_range_get_value(r);
    /* GTK window opacity */
    gtk_window_set_opacity(GTK_WINDOW(main_window), win_alpha);
}

static GtkWidget *build_toolbar(void)
{
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_name(bar, "ctw11-toolbar");

    /* ── ratio: miles per inch ── */
    GtkWidget *lbl_r = gtk_label_new("  Scale (miles/inch):");
    gtk_box_pack_start(GTK_BOX(bar), lbl_r, FALSE, FALSE, 2);

    ratio_entry = gtk_entry_new();
    gtk_entry_set_width_chars(GTK_ENTRY(ratio_entry), 8);
    gtk_entry_set_text(GTK_ENTRY(ratio_entry), "1.0");
    gtk_widget_set_tooltip_text(ratio_entry,
        "Miles represented by 1 physical screen inch.\n"
        "1.0 = true 1:1  |  2.0 = 1 inch shows 2 miles  |  0.5 = 1 inch shows half a mile");
    g_signal_connect(ratio_entry, "changed",  G_CALLBACK(on_ratio_changed),  NULL);
    g_signal_connect(ratio_entry, "activate", G_CALLBACK(on_ratio_activate), NULL);
    gtk_box_pack_start(GTK_BOX(bar), ratio_entry, FALSE, FALSE, 0);

    GtkWidget *lbl_u = gtk_label_new("mi/in");
    gtk_box_pack_start(GTK_BOX(bar), lbl_u, FALSE, FALSE, 0);

    /* separator */
    gtk_box_pack_start(GTK_BOX(bar),
        gtk_separator_new(GTK_ORIENTATION_VERTICAL), FALSE, FALSE, 4);

    /* ── window transparency ── */
    GtkWidget *lbl_a = gtk_label_new("Window opacity:");
    gtk_box_pack_start(GTK_BOX(bar), lbl_a, FALSE, FALSE, 2);

    alpha_scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL,
                                           0.10, 1.00, 0.01);
    gtk_range_set_value(GTK_RANGE(alpha_scale), 1.0);
    gtk_scale_set_draw_value(GTK_SCALE(alpha_scale), TRUE);
    gtk_scale_set_value_pos(GTK_SCALE(alpha_scale), GTK_POS_RIGHT);
    gtk_widget_set_size_request(alpha_scale, 180, -1);
    gtk_widget_set_tooltip_text(alpha_scale,
        "Fade the entire window (1.0 = fully opaque, 0.1 = nearly invisible)");
    g_signal_connect(alpha_scale, "value-changed", G_CALLBACK(on_alpha_changed), NULL);
    gtk_box_pack_start(GTK_BOX(bar), alpha_scale, FALSE, FALSE, 0);

    /* separator */
    gtk_box_pack_start(GTK_BOX(bar),
        gtk_separator_new(GTK_ORIENTATION_VERTICAL), FALSE, FALSE, 4);

    /* ── quick DPI readout ── */
    char dpi_buf[48];
    snprintf(dpi_buf, sizeof(dpi_buf), "Screen DPI: %.0f", SCREEN_DPI);
    GtkWidget *lbl_dpi = gtk_label_new(dpi_buf);
    gtk_widget_set_tooltip_text(lbl_dpi,
        "Physical screen DPI detected at startup.\n"
        "This is used to ensure 1 inch = 1 mile accuracy.");
    gtk_box_pack_start(GTK_BOX(bar), lbl_dpi, FALSE, FALSE, 4);

    /* separator */
    gtk_box_pack_start(GTK_BOX(bar),
        gtk_separator_new(GTK_ORIENTATION_VERTICAL), FALSE, FALSE, 4);

    /* ── zoom readout (live) ── */
    GtkWidget *lbl_z = gtk_label_new("Zoom: 1.00×");
    g_object_set_data(G_OBJECT(bar), "zoom-label", lbl_z);
    gtk_box_pack_start(GTK_BOX(bar), lbl_z, FALSE, FALSE, 4);

    toolbar_bar = bar;
    return bar;
}

/* call after every zoom change to refresh the readout */
static void toolbar_update_zoom(void)
{
    if (!toolbar_bar) return;
    GtkWidget *lbl = GTK_WIDGET(g_object_get_data(G_OBJECT(toolbar_bar), "zoom-label"));
    if (!lbl) return;
    char buf[32];
    snprintf(buf, sizeof(buf), "Zoom: %.3f×", zoom_level);
    gtk_label_set_text(GTK_LABEL(lbl), buf);
}

static void cb_parse (GtkMenuItem *i, gpointer d) { show_parse_dialog(); }
static void cb_ground(GtkMenuItem *i, gpointer d) { show_ground_truth_dialog(); }
static void cb_quit  (GtkMenuItem *i, gpointer d) { gtk_main_quit(); }
static void cb_about (GtkMenuItem *i, gpointer d) { show_about_dialog(); }
static void cb_reset (GtkMenuItem *i, gpointer d)
{ pan_x=pan_y=0.0; zoom_level=1.0; gtk_widget_queue_draw(drawing_area); }

static GtkWidget *build_menubar(void)
{
    GtkWidget *bar = gtk_menu_bar_new();

    /* File */
    GtkWidget *mf = gtk_menu_new(), *if_ = gtk_menu_item_new_with_label("File");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(if_), mf);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), if_);
    GtkWidget *parse = gtk_menu_item_new_with_label("Parse GNSS Folder…  Ctrl+O");
    GtkWidget *quit  = gtk_menu_item_new_with_label("Quit  Ctrl+Q");
    g_signal_connect(parse, "activate", G_CALLBACK(cb_parse), NULL);
    g_signal_connect(quit,  "activate", G_CALLBACK(cb_quit),  NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(mf), parse);
    gtk_menu_shell_append(GTK_MENU_SHELL(mf), gtk_separator_menu_item_new());
    gtk_menu_shell_append(GTK_MENU_SHELL(mf), quit);

    /* Map */
    GtkWidget *mm = gtk_menu_new(), *im = gtk_menu_item_new_with_label("Map");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(im), mm);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), im);
    GtkWidget *ground = gtk_menu_item_new_with_label("Set Ground Truth…  G");
    GtkWidget *reset  = gtk_menu_item_new_with_label("Reset View  R");
    g_signal_connect(ground, "activate", G_CALLBACK(cb_ground), NULL);
    g_signal_connect(reset,  "activate", G_CALLBACK(cb_reset),  NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(mm), ground);
    gtk_menu_shell_append(GTK_MENU_SHELL(mm), reset);

    /* Help */
    GtkWidget *mh = gtk_menu_new(), *ih = gtk_menu_item_new_with_label("Help");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(ih), mh);
    gtk_menu_shell_append(GTK_MENU_SHELL(bar), ih);
    GtkWidget *about = gtk_menu_item_new_with_label("About…");
    g_signal_connect(about, "activate", G_CALLBACK(cb_about), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(mh), about);

    return bar;
}

/* ─── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    GdkScreen *scr = gdk_screen_get_default();
    if (scr) { double dpi = gdk_screen_get_resolution(scr); if (dpi > 0) SCREEN_DPI = dpi; }

    make_dir_p(output_base);

    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), APP_TITLE);
    gtk_window_maximize(GTK_WINDOW(main_window));
    g_signal_connect(main_window, "destroy",       G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(main_window, "key-press-event", G_CALLBACK(on_key_press), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(main_window), vbox);

    gtk_box_pack_start(GTK_BOX(vbox), build_menubar(), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), build_toolbar(),  FALSE, FALSE, 0);

    drawing_area = gtk_drawing_area_new();
    gtk_widget_set_hexpand(drawing_area, TRUE);
    gtk_widget_set_vexpand(drawing_area, TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), drawing_area, TRUE, TRUE, 0);

    /* status bar */
    status_label = gtk_label_new("  Move mouse over map to see coordinates.");
    gtk_label_set_xalign(GTK_LABEL(status_label), 0.0);
    GtkWidget *status_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_box_pack_start(GTK_BOX(status_bar), status_label, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), status_bar, FALSE, FALSE, 2);

    gtk_widget_add_events(drawing_area,
        GDK_BUTTON_PRESS_MASK | GDK_BUTTON_RELEASE_MASK |
        GDK_POINTER_MOTION_MASK | GDK_SCROLL_MASK);

    g_signal_connect(drawing_area, "draw",                 G_CALLBACK(on_draw),          NULL);
    g_signal_connect(drawing_area, "button-press-event",   G_CALLBACK(on_button_press),  NULL);
    g_signal_connect(drawing_area, "button-release-event", G_CALLBACK(on_button_release),NULL);
    g_signal_connect(drawing_area, "motion-notify-event",  G_CALLBACK(on_motion),        NULL);
    g_signal_connect(drawing_area, "scroll-event",         G_CALLBACK(on_scroll),        NULL);

    gtk_widget_show_all(main_window);

    show_ground_truth_dialog();
    show_parse_dialog();

    gtk_main();

    for (int i = 0; i < coord_count; i++) free(coords[i].recs);
    free(coords);
    return 0;
}
