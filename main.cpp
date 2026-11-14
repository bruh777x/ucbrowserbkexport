#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <commctrl.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <filesystem>
#include <ctime>
#include <iomanip>
#include <cstdint>

#include "sqlite3.h"
#undef DecryptFile

namespace fs = std::filesystem;

enum ExportFormat : uint32_t {
    FMT_NONE   = 0,
    FMT_HTML   = 1 << 0,
    FMT_JSON   = 1 << 1,
    FMT_CSV    = 1 << 2,
    FMT_TXT    = 1 << 3,
    FMT_SQLITE = 1 << 4,
    FMT_ALL    = FMT_HTML | FMT_JSON | FMT_CSV | FMT_TXT | FMT_SQLITE
};

// Known keys
static const std::vector<std::vector<uint8_t>> KNOWN_KEYS = {
    {'e','1','9','2','3','7','a','3','a','9','3','3','f','7','e','b'},
    {'a','a','1','7','1','0','2','1','f','9','4','3','8','c','b','2'},
    {0x97, 0xa7, 0x40, 0x50, 0x7b, 0x29, 0x78, 0x69, 0x79, 0x41, 0x3b, 0x34, 0x5e, 0x64, 0x65, 0x2a}
};

struct BookmarkItem {
    int64_t id = 0;
    int64_t parent_id = 0;
    std::string folder;
    std::string title;
    std::string url;
    int64_t created_time = 0;
    int64_t modified_time = 0;
    std::string created_iso;
    std::string modified_iso;
    int64_t order_index = 0;
};

struct UCFolderItem {
    int64_t id = 0;
    int64_t parent_id = 0;
    std::string title;
    int64_t created_time = 0;
    int64_t modified_time = 0;
    std::vector<int64_t> children;
    std::vector<BookmarkItem> bookmarks;
};

struct DecryptResult {
    std::string key;
    size_t encrypted_size = 0;
    size_t decrypted_size = 0;
    int total_bookmarks = 0;
    int total_folders = 0;
    std::map<int64_t, std::string> non_empty_folders;
    std::vector<std::pair<std::string, std::string>> saved_files;
};

// UTF-8 / UTF-16 helpers
std::wstring ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
    std::wstring res(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), &res[0], sz);
    return res;
}

std::string ToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    std::string res(sz, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), &res[0], sz, nullptr, nullptr);
    return res;
}

std::vector<uint8_t> ParseKeyString(const std::string& s) {
    if (s.size() % 2 == 0) {
        std::vector<uint8_t> bytes;
        bool validHex = true;
        for (size_t i = 0; i < s.size(); i += 2) {
            char c1 = s[i], c2 = s[i + 1];
            auto hexVal = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int v1 = hexVal(c1), v2 = hexVal(c2);
            if (v1 < 0 || v2 < 0) { validHex = false; break; }
            bytes.push_back((uint8_t)((v1 << 4) | v2));
        }
        if (validHex && !bytes.empty()) return bytes;
    }
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::string FormatKeyString(const std::vector<uint8_t>& key) {
    bool printable = true;
    for (uint8_t b : key) {
        if (b < 32 || b > 126) { printable = false; break; }
    }
    if (printable) return std::string(key.begin(), key.end());
    std::ostringstream oss;
    for (uint8_t b : key) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

// M9 Decryption Engine
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> DecryptM9Lenient(const std::vector<uint8_t>& in_data, const std::vector<uint8_t>& key) {
    size_t in_len = in_data.size();
    uint8_t use_key[16] = {0};
    memcpy(use_key, key.data(), std::min<size_t>(16, key.size()));

    uint8_t local_key1[8], local_key2[8];
    memcpy(local_key1, use_key, 8);
    memcpy(local_key2, use_key + 8, 8);

    uint8_t b4 = in_data[4], b5 = in_data[5], b6 = in_data[6], b7 = in_data[7];
    uint8_t c4 = (b4 + 0x57) & 0xFF;
    uint8_t c5 = (b5 + 0x1D) & 0xFF;
    uint8_t c6 = (b6 + 0xAB) & 0xFF;
    uint8_t c7 = (b7 + 0x94) & 0xFF;

    std::vector<uint8_t> out(in_len - 10);
    for (size_t r2 = 8; r2 < in_len - 2; ++r2) {
        if ((r2 & 7) == 0) {
            local_key1[0] = (local_key1[0] + local_key2[0] + b4) & 0xFF;
            local_key1[1] = (local_key1[1] + local_key2[1] + b5) & 0xFF;
            local_key1[2] = (local_key1[2] + local_key2[2] + b6) & 0xFF;
            local_key1[3] = (local_key1[3] + local_key2[3] + b7) & 0xFF;
            local_key1[4] = (local_key1[4] + local_key2[4] + c4) & 0xFF;
            local_key1[5] = (local_key1[5] + local_key2[5] + c5) & 0xFF;
            local_key1[6] = (local_key1[6] + local_key2[6] + c6) & 0xFF;
            local_key1[7] = (local_key1[7] + local_key2[7] + c7) & 0xFF;
        }
        out[r2 - 8] = in_data[r2] ^ local_key1[r2 & 7];
    }
    return {out, key};
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> DecryptM9(const std::vector<uint8_t>& in_data, const std::vector<uint8_t>& custom_key = {}) {
    if (in_data.size() <= 9)
        throw std::runtime_error("Input data is too small to be a valid M9 file (minimum 10 bytes).");
    if (in_data[0] != 'm' || in_data[1] != '9' || in_data[2] != '0')
        throw std::runtime_error("Invalid M9 magic header: expected 'm90' (this file may not be an encrypted UC Browser database).");

    size_t in_len = in_data.size();
    std::vector<std::vector<uint8_t>> keys_to_try = custom_key.empty() ? KNOWN_KEYS : std::vector<std::vector<uint8_t>>{custom_key};

    for (const auto& candidate : keys_to_try) {
        uint8_t use_key[16] = {0};
        memcpy(use_key, candidate.data(), std::min<size_t>(16, candidate.size()));

        uint8_t local_key1[8], local_key2[8];
        memcpy(local_key1, use_key, 8);
        memcpy(local_key2, use_key + 8, 8);

        uint8_t b4 = in_data[4], b5 = in_data[5], b6 = in_data[6], b7 = in_data[7];
        uint8_t c4 = (b4 + 0x57) & 0xFF;
        uint8_t c5 = (b5 + 0x1D) & 0xFF;
        uint8_t c6 = (b6 + 0xAB) & 0xFF;
        uint8_t c7 = (b7 + 0x94) & 0xFF;

        std::vector<uint8_t> out(in_len - 10);
        uint8_t running_checksum = 0;

        for (size_t r2 = 8; r2 < in_len - 2; ++r2) {
            if ((r2 & 7) == 0) {
                local_key1[0] = (local_key1[0] + local_key2[0] + b4) & 0xFF;
                local_key1[1] = (local_key1[1] + local_key2[1] + b5) & 0xFF;
                local_key1[2] = (local_key1[2] + local_key2[2] + b6) & 0xFF;
                local_key1[3] = (local_key1[3] + local_key2[3] + b7) & 0xFF;
                local_key1[4] = (local_key1[4] + local_key2[4] + c4) & 0xFF;
                local_key1[5] = (local_key1[5] + local_key2[5] + c5) & 0xFF;
                local_key1[6] = (local_key1[6] + local_key2[6] + c6) & 0xFF;
                local_key1[7] = (local_key1[7] + local_key2[7] + c7) & 0xFF;
            }
            uint8_t p_byte = in_data[r2] ^ local_key1[r2 & 7];
            out[r2 - 8] = p_byte;
            running_checksum ^= p_byte;
        }

        uint8_t chk1 = in_data[in_len - 2];
        uint8_t chk2 = in_data[in_len - 1];
        uint8_t exp1 = (local_key1[0] ^ running_checksum) & 0xFF;
        uint8_t exp2 = (local_key1[1] ^ running_checksum) & 0xFF;

        if (chk1 == exp1 && chk2 == exp2) return {out, candidate};
    }

    if (!custom_key.empty())
        throw std::runtime_error("Checksum verification failed for the provided key.");

    for (const auto& candidate : keys_to_try) {
        auto [lenient_out, k] = DecryptM9Lenient(in_data, candidate);
        if (lenient_out.size() >= 15 && memcmp(lenient_out.data(), "SQLite format 3", 15) == 0)
            return {lenient_out, k};
    }

    throw std::runtime_error("Failed to decrypt: None of the known M9 decryption keys matched.");
}

// String formatting helpers
std::string HtmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#x27;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
                break;
        }
    }
    return out;
}

std::string CsvEscape(const std::string& s) {
    if (s.find_first_of(",\"\r\n") == std::string::npos) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

std::string UnixToIso(int64_t sec) {
    if (sec <= 0) return "";
    time_t t = (time_t)sec;
    struct tm gmt;
    if (gmtime_s(&gmt, &t) != 0) return "";
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S+00:00", &gmt);
    return buf;
}

// SQLite Parser & Exporter
class UCBookmarkParser {
public:
    std::map<int64_t, UCFolderItem> folders;
    std::vector<BookmarkItem> bookmarks;

    explicit UCBookmarkParser(const fs::path& db_path) {
        sqlite3* db = nullptr;
        std::string utf8_path = ToUtf8(db_path.wstring());
        if (sqlite3_open(utf8_path.c_str(), &db) != SQLITE_OK) {
            std::string err = db ? sqlite3_errmsg(db) : "Unknown error";
            if (db) sqlite3_close(db);
            throw std::runtime_error("SQLite open failed: " + err);
        }

        sqlite3_exec(db, "PRAGMA journal_mode = DELETE;", nullptr, nullptr, nullptr);

        sqlite3_stmt* stmt = nullptr;
        bool has_table = false;
        if (sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='bookmark'", -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                has_table = sqlite3_column_int64(stmt, 0) > 0;
            }
            sqlite3_finalize(stmt);
        }

        if (!has_table) {
            sqlite3_close(db);
            return;
        }

        if (sqlite3_prepare_v2(db, "SELECT luid, parent_id, title, create_time, last_modify_time FROM bookmark WHERE folder = 1", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int64_t luid = sqlite3_column_int64(stmt, 0);
                int64_t pid  = sqlite3_column_int64(stmt, 1);
                const char* raw_t = (const char*)sqlite3_column_text(stmt, 2);
                int64_t ctime = sqlite3_column_int64(stmt, 3);
                int64_t mtime = sqlite3_column_int64(stmt, 4);

                std::string clean = raw_t ? raw_t : "";
                while (!clean.empty() && (clean.front() == '`' || clean.front() == ' ')) clean.erase(clean.begin());
                while (!clean.empty() && (clean.back() == '`' || clean.back() == ' ')) clean.pop_back();
                if (clean.empty()) clean = "Folder_" + std::to_string(luid);

                folders[luid] = UCFolderItem{luid, pid, clean, ctime, mtime, {}, {}};
            }
            sqlite3_finalize(stmt);
        }

        for (auto& [fid, f] : folders) {
            if (folders.count(f.parent_id) && f.parent_id != fid) {
                folders[f.parent_id].children.push_back(fid);
            }
        }

        if (sqlite3_prepare_v2(db, "SELECT luid, parent_id, title, url, create_time, last_modify_time, order_index FROM bookmark WHERE folder = 0 ORDER BY order_index, luid", -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int64_t luid = sqlite3_column_int64(stmt, 0);
                int64_t pid  = sqlite3_column_int64(stmt, 1);
                const char* raw_t = (const char*)sqlite3_column_text(stmt, 2);
                const char* raw_u = (const char*)sqlite3_column_text(stmt, 3);
                int64_t ctime = sqlite3_column_int64(stmt, 4);
                int64_t mtime = sqlite3_column_int64(stmt, 5);
                int64_t oidx  = sqlite3_column_int64(stmt, 6);

                std::string title = raw_t ? raw_t : "";
                std::string url   = raw_u ? raw_u : "";
                if (title.empty()) title = url;

                int64_t c_sec = (ctime > 0 && ctime < 2000000000000000LL) ? (ctime / 1000000LL) : 0;
                int64_t m_sec = (mtime > 0 && mtime < 2000000000000000LL) ? (mtime / 1000000LL) : 0;

                std::string folder_title = folders.count(pid) ? folders[pid].title : "Root";

                BookmarkItem item{
                    luid, pid, folder_title, title, url,
                    c_sec, m_sec, UnixToIso(c_sec), UnixToIso(m_sec), oidx
                };
                bookmarks.push_back(item);
                if (folders.count(pid)) {
                    folders[pid].bookmarks.push_back(item);
                }
            }
            sqlite3_finalize(stmt);
        }

        sqlite3_close(db);
    }

    void ExportHtml(const fs::path& out_path) {
        std::ofstream f(out_path, std::ios::binary);
        f << "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n"
          << "<!-- This is an automatically generated file.\n"
          << "     It will be read and overwritten.\n"
          << "     DO NOT EDIT! -->\n"
          << "<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n"
          << "<TITLE>Bookmarks</TITLE>\n"
          << "<H1>Bookmarks</H1>\n"
          << "<DL><p>\n";

        for (const auto& bm : bookmarks) {
            if (!folders.count(bm.parent_id)) {
                std::string add = bm.created_time > 0 ? " ADD_DATE=\"" + std::to_string(bm.created_time) + "\"" : "";
                f << "    <DT><A HREF=\"" << HtmlEscape(bm.url) << "\"" << add << ">" << HtmlEscape(bm.title) << "</A>\n";
            }
        }

        auto render_folder = [&](auto& self, int64_t fid, const std::string& indent) -> void {
            const auto& fld = folders[fid];
            std::string add = (fld.created_time > 0 && fld.created_time < 2000000000000000LL)
                ? " ADD_DATE=\"" + std::to_string(fld.created_time / 1000000LL) + "\"" : "";
            f << indent << "<DT><H3" << add << ">" << HtmlEscape(fld.title) << "</H3>\n";
            f << indent << "<DL><p>\n";
            for (int64_t cid : fld.children) self(self, cid, indent + "    ");
            for (const auto& bm : fld.bookmarks) {
                std::string b_add = bm.created_time > 0 ? " ADD_DATE=\"" + std::to_string(bm.created_time) + "\"" : "";
                f << indent << "    <DT><A HREF=\"" << HtmlEscape(bm.url) << "\"" << b_add << ">" << HtmlEscape(bm.title) << "</A>\n";
            }
            f << indent << "</DL><p>\n";
        };

        for (const auto& [fid, fld] : folders) {
            if (!folders.count(fld.parent_id) || fld.parent_id == 0) {
                if (fld.bookmarks.empty() && fld.children.empty()) continue;
                render_folder(render_folder, fid, "    ");
            }
        }
        f << "</DL><p>\n";
    }

    void ExportJson(const fs::path& out_path) {
        std::ofstream f(out_path, std::ios::binary);
        f << "{\n"
          << "  \"total_bookmarks\": " << bookmarks.size() << ",\n"
          << "  \"total_folders\": " << folders.size() << ",\n"
          << "  \"folders\": [\n";
        size_t fi = 0;
        for (const auto& [fid, fld] : folders) {
            f << "    {\n"
              << "      \"id\": " << fld.id << ",\n"
              << "      \"parent_id\": " << fld.parent_id << ",\n"
              << "      \"title\": \"" << JsonEscape(fld.title) << "\",\n"
              << "      \"bookmarks_count\": " << fld.bookmarks.size() << "\n"
              << "    }" << (++fi < folders.size() ? "," : "") << "\n";
        }
        f << "  ],\n  \"bookmarks\": [\n";
        for (size_t i = 0; i < bookmarks.size(); ++i) {
            const auto& b = bookmarks[i];
            f << "    {\n"
              << "      \"id\": " << b.id << ",\n"
              << "      \"parent_id\": " << b.parent_id << ",\n"
              << "      \"folder\": \"" << JsonEscape(b.folder) << "\",\n"
              << "      \"title\": \"" << JsonEscape(b.title) << "\",\n"
              << "      \"url\": \"" << JsonEscape(b.url) << "\",\n"
              << "      \"created_time\": " << b.created_time << ",\n"
              << "      \"modified_time\": " << b.modified_time << ",\n"
              << "      \"created_iso\": \"" << JsonEscape(b.created_iso) << "\",\n"
              << "      \"modified_iso\": \"" << JsonEscape(b.modified_iso) << "\",\n"
              << "      \"order_index\": " << b.order_index << "\n"
              << "    }" << (i + 1 < bookmarks.size() ? "," : "") << "\n";
        }
        f << "  ]\n}\n";
    }

    void ExportCsv(const fs::path& out_path) {
        std::ofstream f(out_path, std::ios::binary);
        f << "\xEF\xBB\xBFid,folder,title,url,created_iso,modified_iso\r\n";
        for (const auto& b : bookmarks) {
            f << b.id << ","
              << CsvEscape(b.folder) << ","
              << CsvEscape(b.title) << ","
              << CsvEscape(b.url) << ","
              << CsvEscape(b.created_iso) << ","
              << CsvEscape(b.modified_iso) << "\r\n";
        }
    }

    void ExportTxt(const fs::path& out_path) {
        std::ofstream f(out_path, std::ios::binary);
        for (const auto& b : bookmarks) {
            f << b.url << "\t" << b.title << "\n";
        }
    }
};

DecryptResult DecryptFile(const fs::path& src_path, fs::path out_dir = "", const std::vector<uint8_t>& custom_key = {}, bool is_single = true, uint32_t formats = FMT_ALL) {
    if (!fs::exists(src_path))
        throw std::runtime_error("Input file not found: " + ToUtf8(src_path.wstring()));

    if (out_dir.empty()) out_dir = fs::absolute(src_path).parent_path();
    fs::create_directories(out_dir);

    std::string base_name = ToUtf8(src_path.stem().wstring());

    std::ifstream in(src_path, std::ios::binary);
    std::vector<uint8_t> enc_data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    auto [dec_bytes, matched_key] = DecryptM9(enc_data, custom_key);
    std::string key_str = FormatKeyString(matched_key);

    bool keep_sqlite = (formats & FMT_SQLITE) != 0;
    fs::path sqlite_path = keep_sqlite
        ? (out_dir / (base_name + "_decrypted.sqlite"))
        : (fs::temp_directory_path() / ("uc_tmp_" + std::to_string(GetTickCount64()) + ".sqlite"));

    {
        std::ofstream out_db(sqlite_path, std::ios::binary);
        out_db.write((const char*)dec_bytes.data(), dec_bytes.size());
    }

    DecryptResult res;
    res.key = key_str;
    res.encrypted_size = enc_data.size();
    res.decrypted_size = dec_bytes.size();

    try {
        UCBookmarkParser parser(sqlite_path);
        res.total_bookmarks = (int)parser.bookmarks.size();
        res.total_folders = (int)parser.folders.size();
        for (const auto& [fid, fld] : parser.folders) {
            if (!fld.bookmarks.empty()) res.non_empty_folders[fid] = fld.title;
        }

        std::string lower_base = base_name;
        std::transform(lower_base.begin(), lower_base.end(), lower_base.begin(), ::tolower);
        bool also_std = is_single || lower_base == "ucbook" || lower_base == "bookmarks";

        if (formats & FMT_HTML) {
            fs::path p = out_dir / (base_name + "_bookmarks.html");
            parser.ExportHtml(p);
            res.saved_files.push_back({"HTML", ToUtf8(p.wstring())});
            if (also_std) parser.ExportHtml(out_dir / "bookmarks.html");
        }
        if (formats & FMT_JSON) {
            fs::path p = out_dir / (base_name + "_bookmarks.json");
            parser.ExportJson(p);
            res.saved_files.push_back({"JSON", ToUtf8(p.wstring())});
            if (also_std) parser.ExportJson(out_dir / "bookmarks.json");
        }
        if (formats & FMT_CSV) {
            fs::path p = out_dir / (base_name + "_bookmarks.csv");
            parser.ExportCsv(p);
            res.saved_files.push_back({"CSV", ToUtf8(p.wstring())});
            if (also_std) parser.ExportCsv(out_dir / "bookmarks.csv");
        }
        if (formats & FMT_TXT) {
            fs::path p = out_dir / (base_name + "_bookmarks.txt");
            parser.ExportTxt(p);
            res.saved_files.push_back({"TXT", ToUtf8(p.wstring())});
            if (also_std) parser.ExportTxt(out_dir / "bookmarks.txt");
        }
        if (keep_sqlite) {
            res.saved_files.push_back({"SQLite", ToUtf8(sqlite_path.wstring())});
        }
    } catch (...) {
        if (!keep_sqlite && fs::exists(sqlite_path)) fs::remove(sqlite_path);
        throw;
    }

    if (!keep_sqlite && fs::exists(sqlite_path)) fs::remove(sqlite_path);
    return res;
}

// ============================================================================
// Native Resizable Win32 GUI Implementation
// ============================================================================
#define IDC_PATH_EDIT    101
#define IDC_BROWSE_FILE  102
#define IDC_BROWSE_DIR   103
#define IDC_CHK_HTML     104
#define IDC_CHK_CSV      105
#define IDC_CHK_JSON     106
#define IDC_CHK_TXT      107
#define IDC_CHK_SQLITE   108
#define IDC_LOG_EDIT     109
#define IDC_DECRYPT_BTN  110

static HWND g_hTitle, g_hSub, g_hGrpFile, g_hPathEdit, g_hBtnFile, g_hBtnDir;
static HWND g_hGrpFmt, g_hChkHtml, g_hChkCsv, g_hChkJson, g_hChkTxt, g_hChkSqlite;
static HWND g_hGrpLog, g_hLogEdit, g_hBtnDecrypt;
static HFONT g_hFontNormal, g_hFontTitle, g_hFontBold, g_hFontMono;

void AppendGuiLog(const std::wstring& line) {
    std::wstring text = line + L"\r\n";
    int len = GetWindowTextLengthW(g_hLogEdit);
    SendMessageW(g_hLogEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_hLogEdit, EM_REPLACESEL, 0, (LPARAM)text.c_str());
}

void LayoutControls(int cw, int ch) {
    if (!g_hPathEdit) return;
    int margin = 18;
    int grpW = cw - (margin * 2);
    if (grpW < 400) grpW = 400;

    MoveWindow(g_hTitle, margin, 14, grpW, 28, TRUE);
    MoveWindow(g_hSub, margin, 44, grpW, 20, TRUE);

    // File / Folder Group
    MoveWindow(g_hGrpFile, margin, 72, grpW, 64, TRUE);
    int btnFileW = 115;
    int btnDirW  = 128;
    int gap      = 8;
    int innerMargin = 12;
    int btnDirX  = margin + grpW - innerMargin - btnDirW;
    int btnFileX = btnDirX - gap - btnFileW;
    int editX    = margin + innerMargin;
    int editW    = btnFileX - gap - editX;

    MoveWindow(g_hPathEdit, editX, 96, editW, 26, TRUE);
    MoveWindow(g_hBtnFile, btnFileX, 95, btnFileW, 28, TRUE);
    MoveWindow(g_hBtnDir, btnDirX, 95, btnDirW, 28, TRUE);

    // Export Formats Group
    MoveWindow(g_hGrpFmt, margin, 144, grpW, 56, TRUE);
    MoveWindow(g_hChkHtml,   editX,       166, 145, 22, TRUE);
    MoveWindow(g_hChkCsv,    editX + 150, 166, 110, 22, TRUE);
    MoveWindow(g_hChkJson,   editX + 265, 166, 75,  22, TRUE);
    MoveWindow(g_hChkTxt,    editX + 345, 166, 110, 22, TRUE);
    MoveWindow(g_hChkSqlite, editX + 460, 166, 175, 22, TRUE);

    // Action Button at Bottom Right
    int btnDecW = 225, btnDecH = 36;
    int btnDecY = ch - 14 - btnDecH;
    int btnDecX = margin + grpW - btnDecW;
    MoveWindow(g_hBtnDecrypt, btnDecX, btnDecY, btnDecW, btnDecH, TRUE);

    // Log Output Group fills remaining vertical space
    int logGrpY = 208;
    int logGrpH = btnDecY - 12 - logGrpY;
    if (logGrpH < 100) logGrpH = 100;
    MoveWindow(g_hGrpLog, margin, logGrpY, grpW, logGrpH, TRUE);
    MoveWindow(g_hLogEdit, editX, logGrpY + 24, grpW - (innerMargin * 2), logGrpH - 36, TRUE);

    RedrawWindow(GetParent(g_hPathEdit), nullptr, nullptr, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

void RunGuiDecrypt(HWND hwnd) {
    wchar_t pathBuf[MAX_PATH * 2] = {0};
    GetWindowTextW(g_hPathEdit, pathBuf, MAX_PATH * 2);
    fs::path target(pathBuf);

    if (target.empty() || !fs::exists(target)) {
        MessageBoxW(hwnd, L"Please select a valid source file or folder (or drag and drop a .db file onto the window).", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    uint32_t fmt = FMT_NONE;
    if (SendMessageW(g_hChkHtml, BM_GETCHECK, 0, 0) == BST_CHECKED)   fmt |= FMT_HTML;
    if (SendMessageW(g_hChkCsv, BM_GETCHECK, 0, 0) == BST_CHECKED)    fmt |= FMT_CSV;
    if (SendMessageW(g_hChkJson, BM_GETCHECK, 0, 0) == BST_CHECKED)   fmt |= FMT_JSON;
    if (SendMessageW(g_hChkTxt, BM_GETCHECK, 0, 0) == BST_CHECKED)    fmt |= FMT_TXT;
    if (SendMessageW(g_hChkSqlite, BM_GETCHECK, 0, 0) == BST_CHECKED) fmt |= FMT_SQLITE;

    if (fmt == FMT_NONE) {
        MessageBoxW(hwnd, L"Please check at least one export format.", L"No Format Selected", MB_OK | MB_ICONWARNING);
        return;
    }

    SetWindowTextW(g_hLogEdit, L"");
    std::vector<fs::path> db_files;

    if (fs::is_directory(target)) {
        for (const auto& entry : fs::directory_iterator(target)) {
            if (entry.is_regular_file() && entry.path().extension() == L".db")
                db_files.push_back(entry.path());
        }
        std::sort(db_files.begin(), db_files.end());
        if (db_files.empty()) {
            MessageBoxW(hwnd, L"No .db files found in the selected folder.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        AppendGuiLog(L"Found " + std::to_wstring(db_files.size()) + L" database file(s) in folder:\r\n" + target.wstring() + L"\r\n");
    } else {
        db_files.push_back(target);
    }

    int success_count = 0;
    int total_bms = 0;
    std::wstring error_messages;

    for (const auto& fpath : db_files) {
        AppendGuiLog(L"[*] Processing: " + fpath.filename().wstring() + L" (" + std::to_wstring(fs::file_size(fpath)) + L" bytes)...");
        try {
            auto res = DecryptFile(fpath, "", {}, db_files.size() == 1, fmt);
            AppendGuiLog(L"    [+] SUCCESS! Key: " + ToWide(res.key));
            AppendGuiLog(L"    [+] Bookmarks: " + std::to_wstring(res.total_bookmarks) + L" | Folders: " + std::to_wstring(res.total_folders));
            for (const auto& [fid, fname] : res.non_empty_folders) {
                AppendGuiLog(L"        - Folder: " + ToWide(fname));
            }
            for (const auto& [f_name, f_path] : res.saved_files) {
                AppendGuiLog(L"    [+] Saved " + ToWide(f_name) + L": " + fs::path(ToWide(f_path)).filename().wstring());
            }
            AppendGuiLog(L"");
            success_count++;
            total_bms += res.total_bookmarks;
        } catch (const std::exception& ex) {
            std::wstring err = fpath.filename().wstring() + L": " + ToWide(ex.what());
            AppendGuiLog(L"    [-] ERROR on " + err + L"\r\n");
            error_messages += L"• " + err + L"\n";
        }
    }

    AppendGuiLog(L"All operations finished: " + std::to_wstring(success_count) + L"/" + std::to_wstring(db_files.size()) + L" databases decrypted successfully!");
    AppendGuiLog(L"Total bookmarks exported across all files: " + std::to_wstring(total_bms));

    if (!error_messages.empty()) {
        std::wstring msg = L"Failed to decrypt " + std::to_wstring(db_files.size() - success_count) + L" file(s):\n\n" + error_messages;
        MessageBoxW(hwnd, msg.c_str(), L"Decryption Error", MB_OK | MB_ICONERROR);
    } else {
        std::wstring summary = L"Processed " + std::to_wstring(success_count) + L"/" + std::to_wstring(db_files.size()) +
                               L" database(s).\nTotal bookmarks exported: " + std::to_wstring(total_bms);
        MessageBoxW(hwnd, summary.c_str(), L"Done", MB_OK | MB_ICONINFORMATION);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hFontTitle  = CreateFontW(-22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
            g_hFontNormal = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
            g_hFontBold   = CreateFontW(-15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
            g_hFontMono   = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

            g_hTitle = CreateWindowW(L"STATIC", L"UC Browser Bookmark Export", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hTitle, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);

            g_hSub = CreateWindowW(L"STATIC", L"Export your UC Browser Mobile bookmarks (.db) to importable formats.", WS_CHILD | WS_VISIBLE | SS_NOPREFIX, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hSub, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            // File Selection Group
            g_hGrpFile = CreateWindowW(L"BUTTON", L"Select File or Folder (or Drag && Drop)", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hGrpFile, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            g_hPathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_PATH_EDIT, nullptr, nullptr);
            SendMessageW(g_hPathEdit, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            g_hBtnFile = CreateWindowW(L"BUTTON", L"Browse File...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_BROWSE_FILE, nullptr, nullptr);
            SendMessageW(g_hBtnFile, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            g_hBtnDir = CreateWindowW(L"BUTTON", L"Browse Folder...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_BROWSE_DIR, nullptr, nullptr);
            SendMessageW(g_hBtnDir, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            // Export Formats Group
            g_hGrpFmt = CreateWindowW(L"BUTTON", L"Export Formats", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hGrpFmt, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            g_hChkHtml   = CreateWindowW(L"BUTTON", L"HTML (Browsers)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHK_HTML, nullptr, nullptr);
            g_hChkCsv    = CreateWindowW(L"BUTTON", L"CSV (Excel)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHK_CSV, nullptr, nullptr);
            g_hChkJson   = CreateWindowW(L"BUTTON", L"JSON", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHK_JSON, nullptr, nullptr);
            g_hChkTxt    = CreateWindowW(L"BUTTON", L"Text (URLs)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHK_TXT, nullptr, nullptr);
            g_hChkSqlite = CreateWindowW(L"BUTTON", L"Raw SQLite (.sqlite)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHK_SQLITE, nullptr, nullptr);

            for (HWND hChk : {g_hChkHtml, g_hChkCsv, g_hChkJson, g_hChkTxt, g_hChkSqlite}) {
                SendMessageW(hChk, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                SendMessageW(hChk, BM_SETCHECK, BST_CHECKED, 0);
            }

            // Output & Stats Group
            g_hGrpLog = CreateWindowW(L"BUTTON", L"Decryption Output && Stats", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            SendMessageW(g_hGrpLog, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

            g_hLogEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOG_EDIT, nullptr, nullptr);
            SendMessageW(g_hLogEdit, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);

            // Action Button
            g_hBtnDecrypt = CreateWindowW(L"BUTTON", L"Export Selected Formats", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_DECRYPT_BTN, nullptr, nullptr);
            SendMessageW(g_hBtnDecrypt, WM_SETFONT, (WPARAM)g_hFontBold, TRUE);

            DragAcceptFiles(hwnd, TRUE);
            if (fs::exists("ucbook.db")) {
                SetWindowTextW(g_hPathEdit, fs::absolute("ucbook.db").wstring().c_str());
            }

            RECT rc;
            GetClientRect(hwnd, &rc);
            LayoutControls(rc.right - rc.left, rc.bottom - rc.top);
            return 0;
        }

        case WM_SIZE: {
            if (wParam != SIZE_MINIMIZED) {
                LayoutControls(LOWORD(lParam), HIWORD(lParam));
            }
            return 0;
        }

        case WM_GETMINMAXINFO: {
            MINMAXINFO* mmi = (MINMAXINFO*)lParam;
            mmi->ptMinTrackSize.x = 700;
            mmi->ptMinTrackSize.y = 520;
            return 0;
        }

        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            wchar_t filePath[MAX_PATH] = {0};
            if (DragQueryFileW(hDrop, 0, filePath, MAX_PATH)) {
                SetWindowTextW(g_hPathEdit, filePath);
            }
            DragFinish(hDrop);
            return 0;
        }

        case WM_CTLCOLORSTATIC: {
            HDC hdc = (HDC)wParam;
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BROWSE_FILE: {
                    wchar_t fileBuf[MAX_PATH] = {0};
                    OPENFILENAMEW ofn = {sizeof(ofn)};
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFilter = L"Database Files (*.db)\0*.db\0All Files (*.*)\0*.*\0";
                    ofn.lpstrFile = fileBuf;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                    if (GetOpenFileNameW(&ofn)) SetWindowTextW(g_hPathEdit, fileBuf);
                    break;
                }
                case IDC_BROWSE_DIR: {
                    BROWSEINFOW bi = {0};
                    bi.hwndOwner = hwnd;
                    bi.lpszTitle = L"Select Folder with UC Browser Databases";
                    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
                    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
                    if (pidl) {
                        wchar_t dirBuf[MAX_PATH] = {0};
                        if (SHGetPathFromIDListW(pidl, dirBuf)) SetWindowTextW(g_hPathEdit, dirBuf);
                        CoTaskMemFree(pidl);
                    }
                    break;
                }
                case IDC_DECRYPT_BTN:
                    RunGuiDecrypt(hwnd);
                    break;
            }
            return 0;
        }

        case WM_DESTROY:
            DeleteObject(g_hFontTitle);
            DeleteObject(g_hFontNormal);
            DeleteObject(g_hFontBold);
            DeleteObject(g_hFontMono);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int LaunchGui() {
    FreeConsole();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    InitCommonControls();

    WNDCLASSEXW wc = {sizeof(wc)};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"UCExporterWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    // WS_OVERLAPPEDWINDOW enables Resizing + Maximize Button
    HWND hwnd = CreateWindowExW(
        0, L"UCExporterWnd", L"UC Browser Bookmark Export",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 750, 620,
        nullptr, nullptr, wc.hInstance, nullptr
    );

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    CoUninitialize();
    return 0;
}

uint32_t ParseFormatsArg(const std::string& arg) {
    if (arg.empty() || arg == "all") return FMT_ALL;
    uint32_t fmt = FMT_NONE;
    std::stringstream ss(arg);
    std::string item;
    while (std::getline(ss, item, ',')) {
        std::transform(item.begin(), item.end(), item.begin(), ::tolower);
        if (item == "html") fmt |= FMT_HTML;
        else if (item == "json") fmt |= FMT_JSON;
        else if (item == "csv") fmt |= FMT_CSV;
        else if (item == "txt" || item == "text") fmt |= FMT_TXT;
        else if (item == "sqlite" || item == "db") fmt |= FMT_SQLITE;
    }
    return fmt == FMT_NONE ? FMT_ALL : fmt;
}

int main(int argc, char* argv[]) {
    // Check if launched from Explorer (double-click or drag-and-drop onto EXE) vs Terminal
    DWORD procList[2];
    bool launched_from_explorer = (GetConsoleProcessList(procList, 2) <= 1);

    // 1. No arguments (e.g. double-clicked EXE or ran `UCExporter.exe` with no args): ALWAYS open GUI
    if (argc == 1) {
        return LaunchGui();
    }

    std::vector<std::string> inputs;
    std::string out_dir, key_arg, fmt_arg;
    bool force_gui = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if ((a == "-o" || a == "--output-dir") && i + 1 < argc) out_dir = argv[++i];
        else if ((a == "-k" || a == "--key") && i + 1 < argc) key_arg = argv[++i];
        else if ((a == "-f" || a == "--formats") && i + 1 < argc) fmt_arg = argv[++i];
        else if (a == "--gui") force_gui = true;
        else if (a == "-h" || a == "--help") {
            std::cout << "Usage: UCExporter [inputs...] [-o OUTPUT_DIR] [-f html,json,csv,txt,sqlite] [-k KEY] [--gui]\n";
            return 0;
        } else {
            inputs.push_back(a);
        }
    }

    if (force_gui) {
        return LaunchGui();
    }

    // If user dragged a file onto UCExporter.exe in Explorer, hide the flashing console
    if (launched_from_explorer) {
        FreeConsole();
    }

    uint32_t formats = ParseFormatsArg(fmt_arg);
    std::vector<uint8_t> custom_key = key_arg.empty() ? std::vector<uint8_t>{} : ParseKeyString(key_arg);

    std::vector<fs::path> files;
    std::wstring error_accumulator;

    for (const auto& inp : inputs) {
        fs::path p(inp);
        if (fs::is_directory(p)) {
            for (const auto& entry : fs::directory_iterator(p)) {
                if (entry.is_regular_file() && entry.path().extension() == ".db")
                    files.push_back(entry.path());
            }
        } else if (fs::exists(p)) {
            files.push_back(p);
        } else {
            std::string err = "Input path '" + inp + "' not found.";
            std::cerr << "[-] Error: " << err << "\n";
            error_accumulator += L"• " + ToWide(err) + L"\n";
        }
    }

    if (files.empty()) {
        std::wstring msg = error_accumulator.empty()
            ? L"No valid database (.db) files found to decrypt."
            : error_accumulator;
        MessageBoxW(nullptr, msg.c_str(), L"UC Exporter - Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    int success_count = 0, total_bms = 0;
    for (const auto& fpath : files) {
        if (!launched_from_explorer) {
            std::cout << "\n==================================================\n";
            std::cout << "[*] Reading: " << fpath.string() << " (" << fs::file_size(fpath) << " bytes)\n";
        }
        try {
            auto res = DecryptFile(fpath, out_dir, custom_key, files.size() == 1, formats);
            if (!launched_from_explorer) {
                std::cout << "[+] Successfully decrypted M9 container using key: " << res.key << "\n";
                std::cout << "[+] Discovered " << res.total_folders << " folders, " << res.total_bookmarks << " bookmarks:\n";
                for (const auto& [fid, fname] : res.non_empty_folders)
                    std::cout << "    - Folder: '" << fname << "'\n";
                for (const auto& [f_type, f_path] : res.saved_files)
                    std::cout << "[+] Exported " << f_type << ": " << f_path << "\n";
            }
            success_count++;
            total_bms += res.total_bookmarks;
        } catch (const std::exception& ex) {
            std::string err = fpath.filename().string() + ": " + ex.what();
            if (!launched_from_explorer) {
                std::cerr << "[-] ERROR on " << err << "\n";
            }
            error_accumulator += L"• " + ToWide(err) + L"\n";
        }
    }

    if (!launched_from_explorer) {
        std::cout << "\n==================================================\n";
        std::cout << "[*] Finished: " << success_count << "/" << files.size() << " databases decrypted successfully.\n";
        std::cout << "[*] Total bookmarks exported: " << total_bms << "\n";
    }

    // Pop up native error box if any file failed
    if (!error_accumulator.empty()) {
        std::wstring errMsg = L"Errors occurred while processing:\n\n" + error_accumulator;
        MessageBoxW(nullptr, errMsg.c_str(), L"UC Exporter - Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // If a file/folder was dragged directly onto the .exe in Explorer, show completion popup
    if (launched_from_explorer) {
        std::wstring doneMsg = L"Directly exported " + std::to_wstring(success_count) + L"/" + std::to_wstring(files.size()) +
                               L" database(s)!\nTotal bookmarks exported: " + std::to_wstring(total_bms);
        MessageBoxW(nullptr, doneMsg.c_str(), L"UC Exporter - Export Complete", MB_OK | MB_ICONINFORMATION);
    }

    return 0;
}