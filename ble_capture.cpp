/*
 * Phase 5 — BLE Passive RF Monitor (ble_capture.cpp)
 * CTW SDR Forensic Platform
 * 
 * Passive IQ capture on BLE advertising channels (37/38/39) via HackRF.
 * Demodulates GFSK, extracts advertising PDUs, emits structured JSON
 * records to stdout for consumption by the Python analysis layer.
 *
 * NO decryption. NO connection attempts. NO active transmission.
 * Purely passive reception and demodulation.
 *
 * Build:
 *   g++ -O2 -std=c++17 -o ble_capture ble_capture.cpp \
 *       -lhackrf -lfftw3 -lm -lpthread
 *
 * (c) 2026 Christopher T. Williams — CTW SDR Forensic Platform
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <csignal>
#include <ctime>
#include <vector>
#include <deque>
#include <map>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <libhackrf/hackrf.h>

/* ─── BLE Physical Layer Constants ─── */

// BLE advertising channel center frequencies (Hz)
static const uint64_t BLE_ADV_FREQ[3] = {
    2402000000ULL,  // Channel 37
    2426000000ULL,  // Channel 38
    2480000000ULL   // Channel 39
};

// BLE advertising channel indices
static const int BLE_ADV_CH[3] = { 37, 38, 39 };

// BLE access address for advertising channel (fixed per spec)
static const uint32_t BLE_ADV_ACCESS_ADDR = 0x8E89BED6;

// GFSK parameters: BLE uses 1 Msym/s, BT=0.5
static const double BLE_SYMBOL_RATE   = 1000000.0;
static const double BLE_FREQ_DEV      = 250000.0;   // ±250 kHz nominal
static const double SAMPLE_RATE       = 4000000.0;   // 4 Msps capture rate
static const double SAMPLES_PER_SYM   = SAMPLE_RATE / BLE_SYMBOL_RATE; // 4

// Capture parameters
static const uint32_t LNA_GAIN_DB     = 32;
static const uint32_t VGA_GAIN_DB     = 40;
static const uint32_t AMP_ENABLE      = 1;

// Dwell time per channel (ms) — hop across 3 adv channels
static const int DWELL_MS             = 80;

// Preamble: BLE advertising uses 0xAA (10101010) preamble byte
static const uint8_t BLE_PREAMBLE     = 0xAA;

// Maximum PDU length (BLE 4.x advertising PDU max = 39 bytes incl header)
// BLE 5.x extended can be larger but we cap at standard for detection
static const int MAX_PDU_LEN          = 258;

/* ─── PDU Types (BLE Core Spec Vol 6, Part B, §2.3) ─── */
static const char* PDU_TYPE_NAMES[] = {
    "ADV_IND",          // 0 - Connectable undirected
    "ADV_DIRECT_IND",   // 1 - Connectable directed
    "ADV_NONCONN_IND",  // 2 - Non-connectable undirected
    "SCAN_REQ",         // 3 - Scan request
    "SCAN_RSP",         // 4 - Scan response
    "CONNECT_IND",      // 5 - Connect request
    "ADV_SCAN_IND",     // 6 - Scannable undirected
    "ADV_EXT_IND",      // 7 - Extended advertising (BLE 5)
    "RESERVED_8",
    "RESERVED_9",
    "RESERVED_A",
    "RESERVED_B",
    "RESERVED_C",
    "RESERVED_D",
    "RESERVED_E",
    "RESERVED_F"
};

/* ─── Global State ─── */
static hackrf_device*     g_device      = nullptr;
static std::atomic<bool>  g_running{true};
static std::atomic<int>   g_current_ch{0};
static std::mutex         g_output_mtx;
static uint64_t           g_pkt_seq     = 0;
static std::atomic<int64_t> g_noise_floor_sum{0};
static std::atomic<int64_t> g_noise_floor_cnt{0};
static std::atomic<double>  g_peak_power{-200.0};

// IQ ring buffer for demodulation thread
static const size_t IQ_RING_SIZE = 1024 * 1024;  // 1M samples
static int8_t       g_iq_ring[IQ_RING_SIZE * 2];  // I/Q interleaved
static std::atomic<size_t> g_iq_write{0};
static std::atomic<size_t> g_iq_read{0};
static int          g_capture_channel = 37;

/* ─── Signal Handler ─── */
static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

/* ─── Utility: BLE CRC-24 (polynomial 0x00065B) ─── */
static uint32_t ble_crc24(const uint8_t* data, size_t len, uint32_t init) {
    uint32_t state = init;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = data[i];
        for (int bit = 0; bit < 8; bit++) {
            uint32_t fb = ((state >> 23) ^ (byte >> bit)) & 1;
            state = (state << 1) & 0xFFFFFF;
            if (fb) state ^= 0x00065B;
        }
    }
    return state & 0xFFFFFF;
}

/* ─── Utility: Reverse bits in a byte (BLE sends LSB first) ─── */
static inline uint8_t reverse_bits(uint8_t b) {
    b = ((b & 0xF0) >> 4) | ((b & 0x0F) << 4);
    b = ((b & 0xCC) >> 2) | ((b & 0x33) << 2);
    b = ((b & 0xAA) >> 1) | ((b & 0x55) << 1);
    return b;
}

/* ─── Utility: BLE channel whitening (de-whiten) ─── */
static void ble_dewhiten(uint8_t* data, size_t len, int channel) {
    // LFSR init = channel number (bit-reversed, position 0 = MSB of channel)
    uint8_t lfsr = reverse_bits(channel) | 0x02;  // set bit 1 per spec
    // Actually BLE whitening LFSR init = 1 + channel (7-bit)
    lfsr = (1 << 6) | (channel & 0x3F);
    
    for (size_t i = 0; i < len; i++) {
        uint8_t out = 0;
        for (int bit = 0; bit < 8; bit++) {
            uint8_t lfsr_bit = lfsr & 1;
            out |= (((data[i] >> bit) ^ lfsr_bit) & 1) << bit;
            uint8_t fb = ((lfsr >> 6) ^ (lfsr >> 3)) & 1;
            lfsr = (lfsr >> 1) | (fb << 6);
        }
        data[i] = out;
    }
}

/* ─── Utility: ISO timestamp string ─── */
static std::string iso_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto us  = std::chrono::duration_cast<std::chrono::microseconds>(
                   now.time_since_epoch()) .count();
    time_t sec = us / 1000000;
    int    usf = us % 1000000;
    struct tm tm;
    gmtime_r(&sec, &tm);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, usf);
    return std::string(buf);
}

/* ─── Utility: bytes to hex string ─── */
static std::string bytes_hex(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char hx[4];
        snprintf(hx, sizeof(hx), "%02x", data[i]);
        out += hx;
    }
    return out;
}

/* ─── Utility: format BD_ADDR ─── */
static std::string format_bdaddr(const uint8_t* addr) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
    return std::string(buf);
}

/* ─── JSON escape ─── */
static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

/* ─── Compute power in dB from IQ samples ─── */
static double compute_power_db(const int8_t* iq, size_t num_samples) {
    double sum = 0.0;
    for (size_t i = 0; i < num_samples; i++) {
        double I = iq[i * 2]     / 128.0;
        double Q = iq[i * 2 + 1] / 128.0;
        sum += I * I + Q * Q;
    }
    if (num_samples == 0) return -200.0;
    double mean_power = sum / num_samples;
    if (mean_power < 1e-20) return -200.0;
    return 10.0 * log10(mean_power);
}

/* ─── GFSK Demodulation: FM discriminator approach ─── */
// Returns bit decisions in `bits` array. Returns count of bits extracted.
static size_t demod_gfsk(const int8_t* iq, size_t num_samples,
                         uint8_t* bits, size_t max_bits)
{
    if (num_samples < 4) return 0;
    
    // FM discriminator: arg(s[n] * conj(s[n-1]))
    std::vector<double> freq(num_samples - 1);
    for (size_t i = 1; i < num_samples; i++) {
        double I0 = iq[(i-1) * 2]     / 128.0;
        double Q0 = iq[(i-1) * 2 + 1] / 128.0;
        double I1 = iq[i * 2]         / 128.0;
        double Q1 = iq[i * 2 + 1]     / 128.0;
        // conj multiply: (I1 + jQ1)(I0 - jQ0) = (I1*I0+Q1*Q0) + j(Q1*I0-I1*Q0)
        double re = I1 * I0 + Q1 * Q0;
        double im = Q1 * I0 - I1 * Q0;
        freq[i-1] = atan2(im, re);
    }
    
    // Symbol sampling at SAMPLES_PER_SYM intervals
    // Simple: sample at midpoint of each symbol period
    size_t bit_count = 0;
    double half_sym = SAMPLES_PER_SYM / 2.0;
    
    for (double pos = half_sym; pos < freq.size() && bit_count < max_bits;
         pos += SAMPLES_PER_SYM)
    {
        size_t idx = (size_t)pos;
        if (idx >= freq.size()) break;
        // Positive frequency = 1, negative = 0 (BLE convention)
        bits[bit_count++] = (freq[idx] > 0) ? 1 : 0;
    }
    
    return bit_count;
}

/* ─── Search demodulated bits for BLE access address ─── */
// Returns bit offset of first match, or -1
static int find_access_address(const uint8_t* bits, size_t num_bits,
                               uint32_t target_aa)
{
    if (num_bits < 40) return -1;  // need at least preamble + AA
    
    // Convert target AA to bit sequence (LSB first per BLE)
    uint8_t aa_bits[32];
    for (int i = 0; i < 32; i++) {
        aa_bits[i] = (target_aa >> i) & 1;
    }
    
    // Search for 8-bit preamble (01010101 or 10101010) followed by AA
    for (size_t i = 0; i + 40 <= num_bits; i++) {
        // Check preamble (alternating)
        bool preamble_ok = true;
        for (int p = 0; p < 8 && preamble_ok; p++) {
            if (bits[i + p] != (p & 1)) {
                // Try inverted preamble
                if (bits[i + p] != ((p + 1) & 1)) {
                    preamble_ok = false;
                }
            }
        }
        if (!preamble_ok) continue;
        
        // Check access address bits starting at offset +8
        bool aa_ok = true;
        for (int a = 0; a < 32 && aa_ok; a++) {
            if (bits[i + 8 + a] != aa_bits[a]) aa_ok = false;
        }
        if (aa_ok) return (int)i;
    }
    return -1;
}

/* ─── Extract PDU bytes from bit stream (after AA) ─── */
static size_t extract_pdu_bytes(const uint8_t* bits, size_t start_bit,
                                size_t num_bits, uint8_t* pdu, size_t max_pdu)
{
    size_t byte_count = 0;
    for (size_t bi = start_bit; bi + 8 <= num_bits && byte_count < max_pdu; bi += 8) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            byte |= (bits[bi + b] & 1) << b;  // LSB first
        }
        pdu[byte_count++] = byte;
    }
    return byte_count;
}

/* ─── Emit JSON packet record to stdout ─── */
static void emit_packet_json(
    int channel, const std::string& timestamp, double rssi_db,
    int pdu_type, bool tx_add_random, bool rx_add_random,
    const uint8_t* adv_addr, int pdu_len,
    const uint8_t* raw_pdu, size_t raw_len,
    bool crc_valid, uint32_t crc_rx, uint32_t crc_calc,
    double freq_offset_hz)
{
    std::lock_guard<std::mutex> lock(g_output_mtx);
    
    const char* pdu_name = (pdu_type >= 0 && pdu_type <= 15) ?
                           PDU_TYPE_NAMES[pdu_type] : "UNKNOWN";
    
    printf("{\"seq\":%lu,"
           "\"ts\":\"%s\","
           "\"ch\":%d,"
           "\"freq_mhz\":%.1f,"
           "\"rssi_db\":%.1f,"
           "\"pdu_type\":%d,"
           "\"pdu_name\":\"%s\","
           "\"tx_addr_random\":%s,"
           "\"rx_addr_random\":%s,"
           "\"adv_addr\":\"%s\","
           "\"pdu_len\":%d,"
           "\"raw_hex\":\"%s\","
           "\"crc_valid\":%s,"
           "\"crc_rx\":\"0x%06X\","
           "\"crc_calc\":\"0x%06X\","
           "\"freq_offset_hz\":%.1f,"
           "\"noise_floor_db\":%.1f,"
           "\"peak_power_db\":%.1f"
           "}\n",
           g_pkt_seq++,
           json_escape(timestamp).c_str(),
           channel,
           BLE_ADV_FREQ[channel - 37] / 1e6,
           rssi_db,
           pdu_type,
           pdu_name,
           tx_add_random ? "true" : "false",
           rx_add_random ? "true" : "false",
           format_bdaddr(adv_addr).c_str(),
           pdu_len,
           bytes_hex(raw_pdu, std::min(raw_len, (size_t)64)).c_str(),
           crc_valid ? "true" : "false",
           crc_rx, crc_calc,
           freq_offset_hz,
           (g_noise_floor_cnt > 0) ?
               10.0 * log10((double)g_noise_floor_sum / g_noise_floor_cnt / 128.0 / 128.0) :
               -200.0,
           g_peak_power.load()
    );
    fflush(stdout);
}

/* ─── Emit channel energy record (for jamming detection) ─── */
static void emit_energy_json(int channel, const std::string& timestamp,
                             double power_db, double bandwidth_energy_db,
                             size_t valid_pkts, size_t corrupt_pkts)
{
    std::lock_guard<std::mutex> lock(g_output_mtx);
    printf("{\"type\":\"energy\","
           "\"ts\":\"%s\","
           "\"ch\":%d,"
           "\"power_db\":%.2f,"
           "\"bw_energy_db\":%.2f,"
           "\"valid_pkts\":%zu,"
           "\"corrupt_pkts\":%zu"
           "}\n",
           json_escape(timestamp).c_str(),
           channel,
           power_db,
           bandwidth_energy_db,
           valid_pkts,
           corrupt_pkts);
    fflush(stdout);
}

/* ─── HackRF RX callback ─── */
static int hackrf_rx_callback(hackrf_transfer* transfer) {
    if (!g_running) return -1;
    
    size_t len = transfer->valid_length;
    size_t wr  = g_iq_write.load(std::memory_order_relaxed);
    
    for (size_t i = 0; i < len; i++) {
        size_t idx = (wr + i) % (IQ_RING_SIZE * 2);
        g_iq_ring[idx] = (int8_t)(transfer->buffer[i] - 128);  // unsigned->signed
    }
    g_iq_write.store((wr + len) % (IQ_RING_SIZE * 2),
                     std::memory_order_release);
    
    return 0;
}

/* ─── Processing thread: demod + packet extraction ─── */
static void processing_thread() {
    // Work buffer for IQ data
    const size_t CHUNK_SAMPLES = 8192;  // Process in chunks
    int8_t iq_buf[CHUNK_SAMPLES * 2];
    uint8_t bits[CHUNK_SAMPLES * 2];
    uint8_t pdu_buf[MAX_PDU_LEN + 4];  // +3 CRC +1 spare
    
    size_t valid_pkts   = 0;
    size_t corrupt_pkts = 0;
    auto   last_energy  = std::chrono::steady_clock::now();
    
    while (g_running) {
        size_t wr = g_iq_write.load(std::memory_order_acquire);
        size_t rd = g_iq_read.load(std::memory_order_relaxed);
        
        // Calculate available samples
        size_t avail;
        if (wr >= rd) avail = wr - rd;
        else avail = (IQ_RING_SIZE * 2) - rd + wr;
        
        if (avail < CHUNK_SAMPLES * 2) {
            std::this_thread::sleep_for(std::chrono::microseconds(500));
            continue;
        }
        
        // Copy chunk from ring buffer
        for (size_t i = 0; i < CHUNK_SAMPLES * 2; i++) {
            iq_buf[i] = g_iq_ring[(rd + i) % (IQ_RING_SIZE * 2)];
        }
        g_iq_read.store((rd + CHUNK_SAMPLES * 2) % (IQ_RING_SIZE * 2),
                        std::memory_order_release);
        
        int current_ch = g_capture_channel;
        
        // Compute chunk power for energy monitoring
        double chunk_power = compute_power_db(iq_buf, CHUNK_SAMPLES);
        
        // Update peak power tracking
        double cur_peak = g_peak_power.load();
        if (chunk_power > cur_peak) {
            g_peak_power.store(chunk_power);
        }
        
        // Demodulate GFSK
        size_t num_bits = demod_gfsk(iq_buf, CHUNK_SAMPLES, bits,
                                     sizeof(bits));
        if (num_bits < 80) continue;  // Need at least preamble+AA+header
        
        // Search for BLE advertising access address
        int offset = 0;
        while (offset >= 0 && (size_t)offset < num_bits - 40) {
            int aa_pos = find_access_address(bits + offset,
                                            num_bits - offset,
                                            BLE_ADV_ACCESS_ADDR);
            if (aa_pos < 0) break;
            
            int pdu_start_bit = offset + aa_pos + 40;  // after preamble+AA
            
            // Extract PDU bytes (header + payload + CRC)
            size_t pdu_bytes = extract_pdu_bytes(bits, pdu_start_bit,
                                                 num_bits, pdu_buf,
                                                 MAX_PDU_LEN + 3);
            
            if (pdu_bytes < 2) {
                offset += aa_pos + 40;
                continue;
            }
            
            // De-whiten
            uint8_t dewhitened[MAX_PDU_LEN + 4];
            memcpy(dewhitened, pdu_buf, pdu_bytes);
            ble_dewhiten(dewhitened, pdu_bytes, current_ch);
            
            // Parse PDU header (2 bytes)
            uint8_t header0  = dewhitened[0];
            uint8_t header1  = dewhitened[1];
            int pdu_type     = header0 & 0x0F;
            bool tx_random   = (header0 >> 6) & 1;
            bool rx_random   = (header0 >> 7) & 1;
            int payload_len  = header1 & 0x3F;
            
            // Sanity check
            if (payload_len < 6 || payload_len > 37 ||
                (size_t)(payload_len + 2 + 3) > pdu_bytes)
            {
                corrupt_pkts++;
                offset += aa_pos + 40;
                continue;
            }
            
            // Extract advertiser address (first 6 bytes of payload)
            uint8_t adv_addr[6];
            memcpy(adv_addr, &dewhitened[2], 6);
            
            // CRC check (CRC-24 over header + payload, init = 0x555555)
            uint32_t crc_calc = ble_crc24(dewhitened, payload_len + 2,
                                          0x555555);
            uint32_t crc_rx   = dewhitened[payload_len + 2]
                              | (dewhitened[payload_len + 3] << 8)
                              | (dewhitened[payload_len + 4] << 16);
            bool crc_ok = (crc_calc == crc_rx);
            
            if (!crc_ok) corrupt_pkts++;
            else valid_pkts++;
            
            // Estimate frequency offset from demod signal
            // (average frequency during preamble gives carrier offset)
            double freq_offset = 0.0;
            // Simplified: not computed in this path, set to 0
            
            std::string ts = iso_timestamp();
            
            emit_packet_json(current_ch, ts, chunk_power,
                           pdu_type, tx_random, rx_random,
                           adv_addr, payload_len,
                           dewhitened, pdu_bytes,
                           crc_ok, crc_rx, crc_calc,
                           freq_offset);
            
            offset += aa_pos + 40 + (payload_len + 5) * 8;
        }
        
        // Periodic energy report (every ~500ms)
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_energy).count() >= 500)
        {
            emit_energy_json(current_ch, iso_timestamp(),
                           chunk_power, chunk_power,
                           valid_pkts, corrupt_pkts);
            valid_pkts   = 0;
            corrupt_pkts = 0;
            last_energy  = now;
        }
    }
}

/* ─── Channel hopping thread ─── */
static void hop_thread() {
    int ch_idx = 0;
    while (g_running) {
        uint64_t freq = BLE_ADV_FREQ[ch_idx];
        int result = hackrf_set_freq(g_device, freq);
        if (result != HACKRF_SUCCESS) {
            fprintf(stderr, "[!] hackrf_set_freq(%llu) failed: %s\n",
                    (unsigned long long)freq,
                    hackrf_error_name((hackrf_error)result));
        }
        g_capture_channel = BLE_ADV_CH[ch_idx];
        
        std::this_thread::sleep_for(std::chrono::milliseconds(DWELL_MS));
        ch_idx = (ch_idx + 1) % 3;
    }
}

/* ─── Main ─── */
int main(int argc, char** argv) {
    
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse optional args
    int serial_idx = -1;
    bool wideband_mode = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i+1 < argc) {
            serial_idx = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--wideband") == 0) {
            wideband_mode = true;  // Future: capture full 2.4 GHz band
        }
        else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr,
                "Usage: %s [--device N] [--wideband]\n"
                "  Phase 5 BLE Passive RF Monitor\n"
                "  Output: NDJSON packet records to stdout\n"
                "  --device N    HackRF device index (default: 0)\n"
                "  --wideband    Capture full 2400-2483 MHz (future)\n",
                argv[0]);
            return 0;
        }
    }
    
    fprintf(stderr, "═══════════════════════════════════════════════\n");
    fprintf(stderr, "  Phase 5 — BLE Passive RF Monitor v0.1\n");
    fprintf(stderr, "  CTW SDR Forensic Platform\n");
    fprintf(stderr, "  Mode: Passive Receive Only\n");
    fprintf(stderr, "  Channels: 37 (2402), 38 (2426), 39 (2480) MHz\n");
    fprintf(stderr, "  Sample Rate: %.0f Msps\n", SAMPLE_RATE / 1e6);
    fprintf(stderr, "  Dwell: %d ms per channel\n", DWELL_MS);
    fprintf(stderr, "═══════════════════════════════════════════════\n");
    
    // Init HackRF
    int result = hackrf_init();
    if (result != HACKRF_SUCCESS) {
        fprintf(stderr, "[FATAL] hackrf_init() failed: %s\n",
                hackrf_error_name((hackrf_error)result));
        return 1;
    }
    
    // Open device
    if (serial_idx >= 0) {
        hackrf_device_list_t* list = hackrf_device_list();
        if (!list || serial_idx >= list->devicecount) {
            fprintf(stderr, "[FATAL] Device index %d not found\n", serial_idx);
            hackrf_device_list_free(list);
            hackrf_exit();
            return 1;
        }
        result = hackrf_device_list_open(list, serial_idx, &g_device);
        hackrf_device_list_free(list);
    } else {
        result = hackrf_open(&g_device);
    }
    
    if (result != HACKRF_SUCCESS || !g_device) {
        fprintf(stderr, "[FATAL] hackrf_open() failed: %s\n",
                hackrf_error_name((hackrf_error)result));
        hackrf_exit();
        return 1;
    }
    
    // Configure
    hackrf_set_sample_rate(g_device, SAMPLE_RATE);
    hackrf_set_baseband_filter_bandwidth(g_device, 1750000);  // 1.75 MHz BW
    hackrf_set_lna_gain(g_device, LNA_GAIN_DB);
    hackrf_set_vga_gain(g_device, VGA_GAIN_DB);
    hackrf_set_amp_enable(g_device, AMP_ENABLE);
    hackrf_set_freq(g_device, BLE_ADV_FREQ[0]);
    g_capture_channel = BLE_ADV_CH[0];
    
    fprintf(stderr, "[+] HackRF configured, starting capture...\n");
    
    // Start RX
    result = hackrf_start_rx(g_device, hackrf_rx_callback, nullptr);
    if (result != HACKRF_SUCCESS) {
        fprintf(stderr, "[FATAL] hackrf_start_rx() failed: %s\n",
                hackrf_error_name((hackrf_error)result));
        hackrf_close(g_device);
        hackrf_exit();
        return 1;
    }
    
    // Launch processing and hopping threads
    std::thread proc_t(processing_thread);
    std::thread hop_t(hop_thread);
    
    fprintf(stderr, "[+] Capture running. Ctrl+C to stop.\n");
    
    // Main loop — just wait
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    fprintf(stderr, "\n[*] Shutting down...\n");
    
    // Cleanup
    hackrf_stop_rx(g_device);
    proc_t.join();
    hop_t.join();
    hackrf_close(g_device);
    hackrf_exit();
    
    fprintf(stderr, "[+] Captured %lu packets total.\n", g_pkt_seq);
    fprintf(stderr, "[+] Phase 5 capture complete.\n");
    
    return 0;
}
