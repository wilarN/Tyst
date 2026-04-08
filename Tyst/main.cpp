#include <windows.h>
#include <string>
#include <iostream>
#include <sodium.h>
#include <vector>
#include <wincrypt.h>
#include <map>
#include <cstring>
#include <CommCtrl.h>
#include "resource.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Comctl32.lib")

#pragma region vars

// Config / constants

const std::string PREFIX = "SHHH#:";

// Global state (app)

bool g_enabled = true;
bool internal_change = false;

bool sidebar_open = false;
int sidebar_width = 200;

bool copy_hover = false;

int sidebar_scroll = 0;
int sidebar_content_height = 0;


// Windows / handles

HWND main_hwnd = nullptr;
HWND overlay_hwnd = nullptr;
HWND active_edit = nullptr;
HWND tooltip_hwnd = nullptr;

DWORD overlay_spawn_time = 0;

// Clipboard state

std::string last_clipboard_text;

// Crypto / identity

unsigned char MY_PUBLIC_KEY[crypto_box_PUBLICKEYBYTES];
unsigned char MY_SECRET_KEY[crypto_box_SECRETKEYBYTES];

std::vector<unsigned char> current_target;
bool has_target = false;

// Peer state

struct PeerInfo {
    std::string pubkey;
    std::wstring nickname;
};

std::map<std::string, PeerInfo> known_peers;
std::map<std::string, HWND> peer_edits;
std::map<std::string, HWND> peer_labels;

std::wstring last_contact_fp;
std::wstring instance_id;
std::string active_peer_key;

// Overlay state

DWORD overlay_last_time = 0;
DWORD copy_feedback_time = 0;

POINT overlay_origin;

BYTE overlay_alpha = 255;
bool fading_out = false;
bool overlay_active = false;
bool overlay_is_decrypted = false;

struct TextSegment {
    std::wstring text;
    bool is_decrypted;
};

std::vector<TextSegment> overlay_segments;

enum class DecryptResultType {
    Message,
    NewPeer,
    Connected,
    Error
};

struct DecryptResult {
    DecryptResultType type;
    std::string text;
};

// UI / interaction

RECT toggle_rect = { 150, 55, 200, 75 };
RECT status_rect = { 40, 50, 140, 80 };
RECT copykey_rect = { 20, 110, 240, 140 };
RECT sidebar_toggle_rect = { 210, 10, 250, 40 };

std::string editing_key;

// GDI / resources

std::map<HWND, HFONT> edit_fonts;
WNDPROC original_edit_proc = nullptr;


#pragma endregion

#pragma region utility_functions
// Utility functions

std::wstring to_wstring(const std::string& str);
std::wstring fingerprint_from_key(const unsigned char* key);

std::string pubkey_to_string(const unsigned char* key) {
    return std::string((const char*)key, crypto_box_PUBLICKEYBYTES);
}

void clamp_sidebar_scroll() {
    int visible_height = 160; // wnd height
    int max_scroll = max(0, sidebar_content_height - visible_height + 10);

    if (sidebar_scroll < 0)
        sidebar_scroll = 0;

    if (sidebar_scroll > max_scroll)
        sidebar_scroll = max_scroll;
}

#pragma endregion

#pragma region clipboard_helpers
// clipboard helpers

// Read text from clipboard
std::wstring get_clipboard_text() {
    if (!OpenClipboard(nullptr)) return L"";

    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (!hData) {
        CloseClipboard();
        return L"";
    }

    wchar_t* pszText = static_cast<wchar_t*>(GlobalLock(hData));
    if (!pszText) {
        CloseClipboard();
        return L"";
    }

    std::wstring text(pszText);

    GlobalUnlock(hData);
    CloseClipboard();
    return text;
}


// Write text to clipboard
void set_clipboard_text(const std::wstring& text) {
    for (int i = 0; i < 5; i++) {
        if (OpenClipboard(nullptr)) {

            EmptyClipboard();

            size_t size = (text.size() + 1) * sizeof(wchar_t);

            HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, size);
            if (!hGlob) {
                CloseClipboard();
                return;
            }

            void* ptr = GlobalLock(hGlob);
            if (!ptr) {
                GlobalFree(hGlob);
                CloseClipboard();
                return;
            }

            memcpy(ptr, text.c_str(), size);
            GlobalUnlock(hGlob);

            SetClipboardData(CF_UNICODETEXT, hGlob);

            CloseClipboard();
            return;
        }

        Sleep(5); // retry
    }
}

#pragma endregion

#pragma region encoding_and_string_conversions
// Encoding o String conversiions

std::string wstring_to_utf8(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), -1,
        NULL, 0, NULL, NULL
    );
    if (size_needed <= 0) return "";

    std::string str(size_needed - 1, 0);

    WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), -1,
        &str[0], size_needed,
        NULL, NULL
    );


    return str;
}

std::string base32_encode(const unsigned char* data, size_t len) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    std::string output;
    output.reserve((len * 8 + 4) / 5);

    uint32_t buffer = 0;
    int bits_left = 0;

    for (size_t i = 0; i < len; i++) {
        buffer <<= 8;
        buffer |= data[i] & 0xFF;
        bits_left += 8;

        while (bits_left >= 5) {
            output += alphabet[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }

    if (bits_left > 0) {
        buffer <<= (5 - bits_left);
        output += alphabet[buffer & 0x1F];
    }

    return output;
}

std::wstring utf8_to_wstring(const std::string& str) {
    int size_needed = MultiByteToWideChar(
        CP_UTF8, 0,
        str.c_str(), -1,
        NULL, 0
    );

    std::wstring wstr(size_needed - 1, 0);

    if (size_needed <= 0) return L"";

    MultiByteToWideChar(
        CP_UTF8, 0,
        str.c_str(), -1,
        &wstr[0], size_needed
    );

    return wstr;
}

// Base64 helpers (libsodium etc)

// Encode binary --> base64
std::string base64_encode(const std::vector<unsigned char>& data) {
    size_t encoded_len = sodium_base64_ENCODED_LEN(
        data.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    std::vector<char> encoded(encoded_len);

    sodium_bin2base64(
        encoded.data(),
        encoded.size(),
        data.data(),
        data.size(),
        sodium_base64_VARIANT_ORIGINAL
    );

    return std::string(encoded.data());
}

std::wstring to_wstring(const std::string& str) {
    return utf8_to_wstring(str);
}


std::string base64_encode_ui(const std::vector<unsigned char>& data) {
    size_t len = sodium_base64_ENCODED_LEN(
        data.size(),
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
    );

    std::vector<char> out(len);

    sodium_bin2base64(
        out.data(),
        out.size(),
        data.data(),
        data.size(),
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
    );

    return std::string(out.data());
}

// Decode base64 --> binary
std::vector<unsigned char> base64_decode(const std::string& text) {
    std::vector<unsigned char> decoded(text.size());

    size_t decoded_len;

    if (sodium_base642bin(
        decoded.data(),
        decoded.size(),
        text.c_str(),
        text.size(),
        nullptr,
        &decoded_len,
        nullptr,
        sodium_base64_VARIANT_ORIGINAL
    ) != 0) {
        return {};
    }

    decoded.resize(decoded_len);
    return decoded;
}

#pragma endregion

#pragma region peer_management
// Peer management

void update_peer_controls(HWND parent) {
    for (auto& [_, hwnd] : peer_edits)
        DestroyWindow(hwnd);
    for (auto& [_, hwnd] : peer_labels)
        DestroyWindow(hwnd);

    peer_edits.clear();
    peer_labels.clear();

    int x_start = 260;
    int y = 30;

    for (auto& [key, peer] : known_peers) {

        std::wstring fp_text =
            L"(" + fingerprint_from_key((const unsigned char*)key.data()) + L")";

        HWND label = CreateWindowEx(
            0,
            L"STATIC",
            fp_text.c_str(),
            WS_CHILD | WS_VISIBLE,
            x_start + 125, y + 2,
            80, 20,
            parent,
            NULL,
            GetModuleHandle(NULL),
            NULL
        );

        peer_labels[key] = label;

        y += 30;
    }
}

void hide_peer_controls() {
    for (auto& [_, hwnd] : peer_edits)
        ShowWindow(hwnd, SW_HIDE);

    for (auto& [_, hwnd] : peer_labels)
        ShowWindow(hwnd, SW_HIDE);
}


void save_peers() {
    std::vector<unsigned char> raw;

    uint32_t magic = 0x54595354; // "TYST"
    uint32_t version = 1;
    uint32_t count = (uint32_t)known_peers.size();

    // header
    raw.insert(raw.end(), (BYTE*)&magic, (BYTE*)&magic + 4);
    raw.insert(raw.end(), (BYTE*)&version, (BYTE*)&version + 4);
    raw.insert(raw.end(), (BYTE*)&count, (BYTE*)&count + 4);

    for (auto& [key, peer] : known_peers) {

        // pubkey
        raw.insert(raw.end(), key.begin(), key.end());

        // nickname len
        uint16_t len = (uint16_t)peer.nickname.size();
        raw.insert(raw.end(), (BYTE*)&len, (BYTE*)&len + sizeof(len));

        // nickname
        const BYTE* ptr = (BYTE*)peer.nickname.data();
        raw.insert(raw.end(), ptr, ptr + len * sizeof(wchar_t));
    }

    DATA_BLOB input{};
    input.pbData = raw.data();
    input.cbData = (DWORD)raw.size();

    DATA_BLOB output{};

    if (!CryptProtectData(&input, NULL, NULL, NULL, NULL, 0, &output))
        return;

    FILE* f;
    if (fopen_s(&f, "peers.bin", "wb") != 0) {
        LocalFree(output.pbData);
        return;
    }

    fwrite(output.pbData, 1, output.cbData, f);
    fclose(f);

    LocalFree(output.pbData);
}

void load_peers() {
    FILE* f;
    if (fopen_s(&f, "peers.bin", "rb") != 0) return;

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    std::vector<unsigned char> buffer(size);
    fread(buffer.data(), 1, size, f);
    fclose(f);

    DATA_BLOB input{};
    input.pbData = buffer.data();
    input.cbData = (DWORD)buffer.size();

    DATA_BLOB output{};

    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output))
        return;

    size_t offset = 0;

    // read header
    uint32_t magic, version, count;

    memcpy(&magic, output.pbData + offset, 4); offset += 4;
    memcpy(&version, output.pbData + offset, 4); offset += 4;
    memcpy(&count, output.pbData + offset, 4); offset += 4;

    // validate
    if (magic != 0x54595354) {
        LocalFree(output.pbData);
        return;
    }

    // read peers.
    for (uint32_t i = 0; i < count; i++) {

        if (offset + crypto_box_PUBLICKEYBYTES > output.cbData) break;

        PeerInfo peer{};

        peer.pubkey = std::string(
            (char*)output.pbData + offset,
            crypto_box_PUBLICKEYBYTES
        );
        offset += crypto_box_PUBLICKEYBYTES;

        if (offset + sizeof(uint16_t) > output.cbData) break;

        uint16_t len;
        memcpy(&len, output.pbData + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        if (offset + len * sizeof(wchar_t) > output.cbData) break;

        peer.nickname.resize(len);

        if (len > 0) {
            memcpy(&peer.nickname[0], output.pbData + offset, len * sizeof(wchar_t));

            // remove (XXXXXX) if present.
            size_t pos = peer.nickname.find(L" (");
            if (pos != std::wstring::npos) {
                peer.nickname = peer.nickname.substr(0, pos);
            }
        }

        offset += len * sizeof(wchar_t);

        known_peers[peer.pubkey] = peer;
    }

    LocalFree(output.pbData);
}

#pragma endregion

#pragma region crypto
// crypto

bool load_identity() {
    FILE* f;
    if (fopen_s(&f, "identity.bin", "rb") != 0) return false;

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    if (size == 0) {
        fclose(f);
        return false;
    }

    std::vector<unsigned char> buffer(size);
    fread(buffer.data(), 1, size, f);
    fclose(f);

    DATA_BLOB input{};
    input.pbData = buffer.data();
    input.cbData = (DWORD)buffer.size();

    DATA_BLOB output{};

    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        return false;
    }

    if (output.cbData != crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES) {
        LocalFree(output.pbData);
        return false;
    }

    memcpy(MY_PUBLIC_KEY, output.pbData, crypto_box_PUBLICKEYBYTES);
    memcpy(MY_SECRET_KEY, output.pbData + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);

    LocalFree(output.pbData);
    return true;
}

void save_identity() {
    unsigned char raw[crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES];

    memcpy(raw, MY_PUBLIC_KEY, crypto_box_PUBLICKEYBYTES);
    memcpy(raw + crypto_box_PUBLICKEYBYTES, MY_SECRET_KEY, crypto_box_SECRETKEYBYTES);

    DATA_BLOB input{};
    input.pbData = raw;
    input.cbData = sizeof(raw);

    DATA_BLOB output{};

    if (!CryptProtectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        return;
    }

    FILE* f;
    if (fopen_s(&f, "identity.bin", "wb") != 0) {
        LocalFree(output.pbData);
        return;
    }

    fwrite(output.pbData, 1, output.cbData, f);
    fclose(f);

    LocalFree(output.pbData);
}

std::string get_current_target_key() {
    if (current_target.empty()) return "";
    return std::string(
        (char*)current_target.data(),
        crypto_box_PUBLICKEYBYTES
    );
}

std::wstring generate_id() {
    const wchar_t charset[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int length = 6;

    std::wstring result;
    result.reserve(length);

    for (int i = 0; i < length; i++) {
        unsigned int r = randombytes_uniform(36); // 26 letters + 10 digits
        result += charset[r];
    }

    return result;
}

std::wstring fingerprint_from_key(const unsigned char* key) {
    std::string encoded = base32_encode(key, crypto_box_PUBLICKEYBYTES);

    encoded = encoded.substr(0, 6);

    return std::wstring(encoded.begin(), encoded.end());
}


// Encrypt plaintext --> base64 packet
std::string encrypt_message(const std::string& text) {

    // No target --> send identity only
    if (!has_target) {
        std::vector<unsigned char> key(
            MY_PUBLIC_KEY,
            MY_PUBLIC_KEY + crypto_box_PUBLICKEYBYTES
        );

        return PREFIX + base64_encode(key);
    }

    const unsigned char* receiver_pub = current_target.data();

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> ciphertext(
        text.size() + crypto_box_MACBYTES
    );

    crypto_box_easy(
        ciphertext.data(),
        (const unsigned char*)text.c_str(),
        text.size(),
        nonce,
        receiver_pub,
        MY_SECRET_KEY
    );

    std::vector<unsigned char> combined;

    // sender pubkey
    combined.insert(combined.end(),
        MY_PUBLIC_KEY,
        MY_PUBLIC_KEY + crypto_box_PUBLICKEYBYTES
    );

    // nonce
    combined.insert(combined.end(),
        nonce,
        nonce + crypto_box_NONCEBYTES
    );

    // ciphertext
    combined.insert(combined.end(),
        ciphertext.begin(),
        ciphertext.end()
    );

    return PREFIX + base64_encode(combined);
}

std::wstring get_fingerprint() {
    std::string encoded = base32_encode(MY_PUBLIC_KEY, 6);

    encoded = encoded.substr(0, 6);

    return std::wstring(encoded.begin(), encoded.end());
}

DecryptResult decrypt_message(const std::string& text) {
    std::string encoded = text.substr(PREFIX.size());

    std::vector<unsigned char> data = base64_decode(encoded);
    if (data.empty()) return { DecryptResultType::Message, "[Invalid data]" };

    // new id message
    if (data.size() == crypto_box_PUBLICKEYBYTES) {

        // ignore own identity
        if (memcmp(data.data(), MY_PUBLIC_KEY, crypto_box_PUBLICKEYBYTES) == 0) {
            return { DecryptResultType::Message, "[Ignoring self]" };
        }

        std::string key_str(
            (char*)data.data(),
            crypto_box_PUBLICKEYBYTES
        );

        current_target.assign(data.begin(), data.end());
        has_target = true;

        // Update fingerprint
        std::wstring fp = fingerprint_from_key(data.data());
        last_contact_fp = fp;

        // Update ui + active peer
        auto it = known_peers.find(key_str);

        std::string fp_str = wstring_to_utf8(fp);

        if (known_peers.find(key_str) == known_peers.end()) {
            PeerInfo peer{};
            peer.pubkey = key_str;
            peer.nickname = L"";

            known_peers[key_str] = peer;
            save_peers();

            return { DecryptResultType::NewPeer, "[New peer connected]" };
        }

        return { DecryptResultType::Connected, "[Connected to " + fp_str + "]" };
    }

    // normal enc message
    size_t offset = 0;

    if (data.size() < crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        return  { DecryptResultType::Error, "[Invalid data]" };
    }

    unsigned char* sender_pub = data.data();
    offset += crypto_box_PUBLICKEYBYTES;

    unsigned char* nonce = data.data() + offset;
    offset += crypto_box_NONCEBYTES;

    unsigned char* ciphertext = data.data() + offset;
    size_t ciphertext_len = data.size() - offset;

    std::vector<unsigned char> decrypted(
        ciphertext_len - crypto_box_MACBYTES
    );

    if (crypto_box_open_easy(
        decrypted.data(),
        ciphertext,
        ciphertext_len,
        nonce,
        sender_pub,
        MY_SECRET_KEY
    ) != 0) {
        return { DecryptResultType::Error, "[Decryption failed]" };
    }

    // update active peer automatically
    current_target.assign(
        sender_pub,
        sender_pub + crypto_box_PUBLICKEYBYTES
    );

    has_target = true;


    std::string key((char*)sender_pub, crypto_box_PUBLICKEYBYTES);
    active_peer_key = key;

    std::string msg((char*)decrypted.data(), decrypted.size());

    std::wstring fp = fingerprint_from_key(sender_pub);
    std::string fp_str = wstring_to_utf8(fp);

    auto it = known_peers.find(key);

    std::string display;

    if (it != known_peers.end() && !it->second.nickname.empty()) {
        display = wstring_to_utf8(it->second.nickname);
    }
    else {
        display = fp_str;
    }

    return { DecryptResultType::Message, "[" + display + "] " + msg };
}

#pragma endregion

#pragma region message_processing

// Message processing

std::vector<std::string> extract_encrypted_blocks(const std::string& text) {
    std::vector<std::string> results;

    size_t pos = 0;

    while ((pos = text.find(PREFIX, pos)) != std::string::npos) {

        size_t end = text.find_first_of(" \n\r\t", pos);

        if (end == std::string::npos) {
            end = text.length();
        }

        results.push_back(text.substr(pos, end - pos));

        pos = end;
    }

    return results;
}

std::vector<TextSegment> build_segments(const std::string& text) {
    std::vector<TextSegment> segments;

    size_t pos = 0;

    while (pos < text.size()) {
        size_t found = text.find(PREFIX, pos);

        // normal text before encrypted
        if (found == std::string::npos) {
            segments.push_back({ to_wstring(text.substr(pos)), false });
            break;
        }

        if (found > pos) {
            segments.push_back({
                to_wstring(text.substr(pos, found - pos)),
                false
                });
        }

        size_t end = text.find_first_of(" \n\r\t", found);
        if (end == std::string::npos) end = text.length();

        std::string block = text.substr(found, end - found);
        auto result = decrypt_message(block);

        // ui 
        if (result.type == DecryptResultType::NewPeer ||
            result.type == DecryptResultType::Connected) {
            InvalidateRect(main_hwnd, NULL, TRUE);
        }

        segments.push_back({
            to_wstring(result.text),
            true
            });

        pos = end;
    }

    return segments;
}


std::string rebuild_text(const std::vector<TextSegment>& segments) {
    std::wstring result;

    for (const auto& seg : segments) {
        result += seg.text;
    }

    return wstring_to_utf8(result);
}

// Check if message starts with prefix
bool is_encrypted(const std::string& text) {
    return text.rfind(PREFIX, 0) == 0;
}

#pragma endregion


#pragma region overlay_logic
// Overlay logic

void show_overlay(bool is_decrypted) {

    overlay_spawn_time = GetTickCount();

    // prevent rapid re-trigger (200ms window)
    if (overlay_spawn_time - overlay_last_time < 200) return;

    overlay_last_time = overlay_spawn_time;
    // prevent spam / restart loop
    if (overlay_active) return;

    overlay_active = true;

    overlay_alpha = 255;
    fading_out = false;

    SetLayeredWindowAttributes(overlay_hwnd, 0, overlay_alpha, LWA_ALPHA);

    GetCursorPos(&overlay_origin);

    SetWindowPos(
        overlay_hwnd,
        HWND_TOPMOST,
        overlay_origin.x + 10,
        overlay_origin.y - 60,
        10, 10,
        SWP_NOACTIVATE | SWP_SHOWWINDOW
    );

    InvalidateRect(overlay_hwnd, NULL, TRUE);
    UpdateWindow(overlay_hwnd);

    SetTimer(overlay_hwnd, 1, 50, NULL);
}



void update_window_region(HWND hwnd, int width, int height) {
    HRGN old = CreateRectRgn(0, 0, 0, 0);

    GetWindowRgn(hwnd, old);
    DeleteObject(old);

    HRGN region = CreateRoundRectRgn(0, 0, width, height, 20, 20);
    SetWindowRgn(hwnd, region, TRUE);
}

#pragma endregion


#pragma region window_procs
// Win procs

LRESULT CALLBACK EditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {

    if (msg == WM_KEYDOWN) {

        if (wParam == VK_RETURN) {
            SendMessage(GetParent(hwnd), WM_COMMAND,
                MAKEWPARAM(0, EN_KILLFOCUS),
                (LPARAM)hwnd);
            return 0;
        }

        if (wParam == VK_ESCAPE) {
            DestroyWindow(hwnd);
            active_edit = nullptr;
            return 0;
        }
    }

    return CallWindowProc(original_edit_proc, hwnd, msg, wParam, lParam);
}

// Window rendering

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {

    case WM_PAINT: {
        // Create font
        HFONT font = CreateFontW(
            16, 0, 0, 0,
            FW_NORMAL,
            FALSE, FALSE, FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI Symbol"
        );

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        HFONT oldFont = (HFONT)SelectObject(hdc, font);


        SetGraphicsMode(hdc, GM_ADVANCED);

        // background
        HBRUSH brush = CreateSolidBrush(RGB(28, 28, 30));
        FillRect(hdc, &ps.rcPaint, brush);
        DeleteObject(brush);

        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, font);

        // title
        SetTextColor(hdc, RGB(255, 255, 255));
        std::wstring title = L"Tyst v0.1.2 [" + instance_id + L"]";
        TextOutW(hdc, 20, 20, title.c_str(), static_cast<int>(title.length()));

        // status dot
        HPEN pen = CreatePen(PS_NULL, 0, 0);
        HBRUSH dotBrush = CreateSolidBrush(
            g_enabled ? RGB(0, 200, 120) : RGB(120, 120, 120)
        );

        // Known peers toggle sidebar button
        SetTextColor(hdc, RGB(200, 200, 255));
        DrawTextW(
            hdc,
            sidebar_open ? L"◀" : L"▶",
            -1,
            &sidebar_toggle_rect,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE
        );


        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, dotBrush);

        Ellipse(hdc, 20, 60, 34, 74);

        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);

        DeleteObject(dotBrush);
        DeleteObject(pen);

        // status text
        SetTextColor(hdc, g_enabled ? RGB(0, 200, 120) : RGB(160, 160, 160));

        std::wstring status = g_enabled ? L"Enabled" : L"Disabled";
        TextOutW(hdc, 50, 58, status.c_str(), static_cast<int>(status.length()));

        SetTextColor(hdc, RGB(180, 180, 180));
        std::wstring contact_text;

        if (has_target) {
            contact_text = L"→ " + last_contact_fp;
        }
        else {
            contact_text = L"→ No peer key selected.";
        }


        TextOutW(hdc, 50, 75, contact_text.c_str(), static_cast<int>(contact_text.length()));

        // border
        int padding = 2;

        HBRUSH nullBrush = (HBRUSH)GetStockObject(NULL_BRUSH);
        SelectObject(hdc, nullBrush);

        // outer
        HPEN outerPen = CreatePen(PS_SOLID, 3, RGB(90, 60, 180));
        HPEN oldOuter = (HPEN)SelectObject(hdc, outerPen);

        RoundRect(hdc, padding, padding, 260 - padding, 160 - padding, 18, 18);

        SelectObject(hdc, oldOuter);
        DeleteObject(outerPen);

        // inner
        HPEN innerPen = CreatePen(PS_SOLID, 1, RGB(140, 80, 255));
        HPEN oldInner = (HPEN)SelectObject(hdc, innerPen);

        RoundRect(
            hdc,
            padding + 1,
            padding + 1,
            260 - padding - 1,
            160 - padding - 1,
            16,
            16
        );

        SelectObject(hdc, oldInner);
        DeleteObject(innerPen);



        // copy button

        // color
        COLORREF btnColor = copy_hover
            ? RGB(65, 65, 85)   // hover
            : RGB(45, 45, 55);  // normal

        HBRUSH btnBrush = CreateSolidBrush(btnColor);
        HPEN nullPen = CreatePen(PS_NULL, 0, 0);

        // fill
        HBRUSH oldBtnBrush = (HBRUSH)SelectObject(hdc, btnBrush);
        HPEN oldBtnPen = (HPEN)SelectObject(hdc, nullPen);

        RoundRect(
            hdc,
            copykey_rect.left,
            copykey_rect.top,
            copykey_rect.right,
            copykey_rect.bottom,
            10, 10
        );

        // restore before outline draw
        SelectObject(hdc, oldBtnBrush);
        SelectObject(hdc, oldBtnPen);

        DeleteObject(btnBrush);
        DeleteObject(nullPen);

        // outline
        HPEN outlinePen = CreatePen(PS_SOLID, 1, RGB(160, 80, 255)); // same as inner border
        HPEN oldOutline = (HPEN)SelectObject(hdc, outlinePen);

        HBRUSH hollow = (HBRUSH)GetStockObject(NULL_BRUSH);
        HBRUSH oldHollow = (HBRUSH)SelectObject(hdc, hollow);

        RoundRect(
            hdc,
            copykey_rect.left,
            copykey_rect.top,
            copykey_rect.right,
            copykey_rect.bottom,
            10, 10
        );

        // restore
        SelectObject(hdc, oldOutline);
        SelectObject(hdc, oldHollow);

        DeleteObject(outlinePen);

        // btn text
        SetTextColor(hdc, RGB(220, 220, 255));

        std::wstring btnText = L"Copy own public key";
        if (GetTickCount() - copy_feedback_time < 1000) {
            btnText = L"Copied!";
        }

        // center text manually
        RECT textRect = copykey_rect;

        DrawTextW(
            hdc,
            btnText.c_str(),
            -1,
            &textRect,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE
        );


        if (sidebar_open) {

            int x_start = 260 + 15; // padd
            int y = 20 - sidebar_scroll;

            for (auto& [key, peer] : known_peers) {

                std::wstring name = peer.nickname.empty()
                    ? L"Unnamed"
                    : peer.nickname;

                std::wstring fp = fingerprint_from_key(
                    (const unsigned char*)key.data()
                );

                std::wstring fp_text = L"[" + fp + L"]";

                // name (selected= highlighted)
                if (key == active_peer_key) {
                    SetTextColor(hdc, RGB(0, 200, 120)); // green
                }
                else {
                    SetTextColor(hdc, RGB(255, 255, 255)); // normal
                }

                TextOutW(
                    hdc,
                    x_start,
                    y,
                    name.c_str(),
                    (int)name.length()
                );

                // measure name width so ID sits next to it cleanly
                SIZE size;
                GetTextExtentPoint32W(hdc, name.c_str(), (int)name.length(), &size);

                // id
                SetTextColor(hdc, RGB(160, 100, 255));

                TextOutW(
                    hdc,
                    x_start + size.cx + 8,
                    y,
                    fp_text.c_str(),
                    (int)fp_text.length()
                );

                // underline
                HPEN pen = CreatePen(PS_SOLID, 1, RGB(50, 50, 60));
                HPEN old = (HPEN)SelectObject(hdc, pen);

                MoveToEx(hdc, x_start, y + 22, NULL);
                LineTo(hdc, x_start + sidebar_width - 30, y + 22);

                SelectObject(hdc, old);
                DeleteObject(pen);

                y += 30;
            }
        }

        
        // cleanup
		SelectObject(hdc, oldFont);
        DeleteObject(font);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;

        SetTextColor(hdc, RGB(255, 255, 255));
        SetBkColor(hdc, RGB(28, 28, 30)); // matches bg col

        static HBRUSH brush = NULL;
        if(!brush) brush = CreateSolidBrush(RGB(28, 28, 30));
        return (INT_PTR)brush;
    }

    case WM_VSCROLL:
    {
        int scrollAmount = 10;

        switch (LOWORD(wParam)) {
        case SB_LINEUP:
            sidebar_scroll -= scrollAmount;
            break;

        case SB_LINEDOWN:
            sidebar_scroll += scrollAmount;
            break;

        case SB_PAGEUP:
            sidebar_scroll -= 50;
            break;

        case SB_PAGEDOWN:
            sidebar_scroll += 50;
            break;
        }

        if (sidebar_scroll < 0)
            sidebar_scroll = 0;

        if (sidebar_scroll > sidebar_content_height)
            sidebar_scroll = sidebar_content_height;

        int visible_height = 160; // wnd height
        int max_scroll = max(0, sidebar_content_height - visible_height);

        if (sidebar_scroll > max_scroll)
            sidebar_scroll = max_scroll;

        if (sidebar_scroll < 0)
            sidebar_scroll = 0;

        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_MOUSEWHEEL:
    {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);

        sidebar_scroll -= (delta / 120) * 30;

        clamp_sidebar_scroll();

        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_MOUSEMOVE:
    {
        if (!sidebar_open) break;

        int x_start = 260 + 15;
        int y = 20 - sidebar_scroll;

        POINT pt = { LOWORD(lParam), HIWORD(lParam) };

        bool hovering_peer = false;

        for (auto& [key, peer] : known_peers) {

            RECT row = { x_start, y, x_start + sidebar_width - 30, y + 25 };

            if (PtInRect(&row, pt)) {
                hovering_peer = true;
                break;
            }

            y += 30;
        }

        TOOLINFO ti;
        ZeroMemory(&ti, sizeof(ti));
        ti.cbSize = sizeof(TOOLINFO);
        ti.hwnd = hwnd;
        ti.uId = 1;

        if (hovering_peer) {
            ti.lpszText = (LPWSTR)L"Left click: copy key\nRight click: rename";
        }
        else {
            ti.lpszText = (LPWSTR)L"";
        }

        SendMessage(tooltip_hwnd, TTM_UPDATETIPTEXT, 0, (LPARAM)&ti);

        break;
    }

    case WM_COMMAND:
    {
        for (auto& [key, edit] : peer_edits) {
            if ((HWND)lParam == edit && HIWORD(wParam) == EN_CHANGE) {

                wchar_t buffer[21]; // 21 + null
                GetWindowTextW(edit, buffer, 21);

                std::wstring new_name = buffer;

                // strip
                size_t pos = new_name.find(L" (");
                if (pos != std::wstring::npos) {
                    new_name = new_name.substr(0, pos);
                }

				if (new_name.length() > 20) {
					new_name = new_name.substr(0, 20);
				}

                // trim trailing space
                while (!new_name.empty() && new_name.back() == L' ') {
                    new_name.pop_back();
                }

                if (known_peers[key].nickname != new_name) {
                    known_peers[key].nickname = new_name;
                    save_peers();

                    InvalidateRect(hwnd, NULL, TRUE);
                }
            }
        }

        if ((HWND)lParam == active_edit &&
            (HIWORD(wParam) == EN_KILLFOCUS)) {

            wchar_t buffer[21]; // 20 + null terminator
            GetWindowTextW(active_edit, buffer, 21);

            known_peers[editing_key].nickname = buffer;
            save_peers();

            if (edit_fonts.count(active_edit)) {
                DeleteObject(edit_fonts[active_edit]);
                edit_fonts.erase(active_edit);
            }

            DestroyWindow(active_edit);
            active_edit = nullptr;

            InvalidateRect(hwnd, NULL, TRUE);
        }

        break;
    }

    case WM_TIMER:
    {
        if (GetTickCount() - copy_feedback_time > 1000) {
            KillTimer(hwnd, 2);
        }

        InvalidateRect(hwnd, NULL, TRUE);
        return 0;
    }

    case WM_DESTROY:
		RemoveClipboardFormatListener(hwnd);
        KillTimer(hwnd, 2);
        PostQuitMessage(0);
        return 0;

        // allow dragging window
    case WM_LBUTTONDOWN: {
        POINT pt = { LOWORD(lParam), HIWORD(lParam) };

        if (PtInRect(&status_rect, pt)) {
            g_enabled = !g_enabled;

            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }

        if (PtInRect(&sidebar_toggle_rect, pt)) {
            sidebar_open = !sidebar_open;

            int new_width = sidebar_open ? 260 + sidebar_width : 260;

            SetWindowPos(hwnd, NULL, 0, 0, new_width, 160,
                SWP_NOMOVE | SWP_NOZORDER);

            update_window_region(hwnd, new_width, 160);

            RedrawWindow(hwnd, NULL, NULL,
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);

            InvalidateRect(hwnd, NULL, TRUE);
            return 0;
        }

        if (PtInRect(&copykey_rect, pt)) {

            std::vector<unsigned char> key(
                MY_PUBLIC_KEY,
                MY_PUBLIC_KEY + crypto_box_PUBLICKEYBYTES
            );

            std::string encoded = PREFIX + base64_encode(key);

            internal_change = true;
            set_clipboard_text(utf8_to_wstring(encoded));

            copy_feedback_time = GetTickCount();
            SetTimer(hwnd, 2, 100, NULL);
            InvalidateRect(hwnd, NULL, TRUE);

            return 0;
        }

        if (sidebar_open) {

            int x_start = 260 + 15;
            int y = 20 - sidebar_scroll;

            POINT pt = { LOWORD(lParam), HIWORD(lParam) };

            for (auto& [key, peer] : known_peers) {

                RECT row = { x_start, y, x_start + sidebar_width - 30, y + 25 };

                if (PtInRect(&row, pt)) {

                    // set as active peer
                    current_target.assign(
                        (unsigned char*)key.data(),
                        (unsigned char*)key.data() + crypto_box_PUBLICKEYBYTES
                    );

                    has_target = true;
                    active_peer_key = key;

                    // update fingerprint display
                    last_contact_fp = fingerprint_from_key(
                        (const unsigned char*)key.data()
                    );

                    // refresh ui
                    InvalidateRect(hwnd, NULL, TRUE);

                    return 0;
                }

                y += 30;
            }
        }

        // existing drag logic
        ReleaseCapture();
        SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        return 0;
    }

    case WM_MBUTTONDOWN:
    {
        if (sidebar_open) {

            int x_start = 260 + 15;
            int y = 20 - sidebar_scroll;

            POINT pt = { LOWORD(lParam), HIWORD(lParam) };

            for (auto& [key, peer] : known_peers) {

                RECT row = { x_start, y, x_start + sidebar_width - 30, y + 25 };

                if (PtInRect(&row, pt)) {

                    std::vector<unsigned char> key_bytes(
                        (unsigned char*)key.data(),
                        (unsigned char*)key.data() + crypto_box_PUBLICKEYBYTES
                    );

                    std::string encoded = PREFIX + base64_encode(key_bytes);

                    internal_change = true;
                    set_clipboard_text(utf8_to_wstring(encoded));

                    copy_feedback_time = GetTickCount();
                    SetTimer(hwnd, 2, 100, NULL);

                    return 0;
                }

                y += 30;
            }
        }
        return 0;
    }

    case WM_RBUTTONDOWN:
    {
        if (sidebar_open) {

            int x_start = 260 + 15;
            int y = 20 - sidebar_scroll;

            POINT pt = { LOWORD(lParam), HIWORD(lParam) };

            for (auto& [key, peer] : known_peers) {

                RECT row = { x_start, y, x_start + sidebar_width - 30, y + 25 };

                if (PtInRect(&row, pt)) {

                    // destroy old edit if exists
                    if (active_edit) {

                        if (edit_fonts.count(active_edit)) {
                            DeleteObject(edit_fonts[active_edit]);
                            edit_fonts.erase(active_edit);
                        }

                        DestroyWindow(active_edit);
                        active_edit = nullptr;
                    }

                    // create edit box
                    active_edit = CreateWindowEx(
                        0,
                        L"EDIT",
                        peer.nickname.c_str(),
                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                        x_start,
                        y,
                        140,
                        22,
                        hwnd,
                        NULL,
                        GetModuleHandle(NULL),
                        NULL
                    );

                    SendMessage(active_edit, EM_LIMITTEXT, 20, 0);

                    original_edit_proc = (WNDPROC)SetWindowLongPtr(
                        active_edit,
                        GWLP_WNDPROC,
                        (LONG_PTR)EditProc
                    );

                    SetWindowLong(active_edit, GWL_STYLE,
                        GetWindowLong(active_edit, GWL_STYLE) & ~WS_BORDER);

                    HFONT font = CreateFontW(
                        16, 0, 0, 0,
                        FW_NORMAL,
                        FALSE, FALSE, FALSE,
                        DEFAULT_CHARSET,
                        OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS,
                        CLEARTYPE_QUALITY,
                        DEFAULT_PITCH | FF_DONTCARE,
                        L"Segoe UI"
                    );

                    SendMessage(active_edit, WM_SETFONT, (WPARAM)font, TRUE);

                    edit_fonts[active_edit] = font;

                    SetFocus(active_edit);

                    editing_key = key;

                    return 0;
                }

                y += 30;
            }
        }

        return 0;
    }

        // force normal cursor
    case WM_SETCURSOR: {
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);

        copy_hover = PtInRect(&copykey_rect, pt);

        if (PtInRect(&status_rect, pt)) {
            SetCursor(LoadCursor(nullptr, IDC_HAND));
            return TRUE;
        }

        if (PtInRect(&sidebar_toggle_rect, pt)) {
            SetCursor(LoadCursor(nullptr, IDC_HAND));
            return TRUE;
        }

        if (PtInRect(&copykey_rect, pt)) {
            SetCursor(LoadCursor(nullptr, IDC_HAND));
            return TRUE;
        }

        if (sidebar_open) {
            int x_start = 260 + 15;
            int y = 20 - sidebar_scroll;

            POINT pt;
            GetCursorPos(&pt);
            ScreenToClient(hwnd, &pt);

            for (auto& [key, peer] : known_peers) {
                RECT row = { x_start, y, x_start + sidebar_width - 30, y + 25 };

                if (PtInRect(&row, pt)) {
                    SetCursor(LoadCursor(nullptr, IDC_HAND));
                    return TRUE;
                }

                y += 30;
            }
        }

        SetCursor(LoadCursor(nullptr, IDC_ARROW));
        return TRUE;
    }
        // ESC closes window
    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_SIZE:
    {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        update_window_region(hwnd, width, height);
        break;
    }


    case WM_CLIPBOARDUPDATE: {
        if (!g_enabled) return 0;
        if (internal_change) {
            internal_change = false;
            return 0;
        }

        std::wstring wtext = get_clipboard_text();
        std::string text = wstring_to_utf8(wtext);

        static std::string last_processed;
		if (text == last_processed) return 0;

		last_processed = text;

        if (text.empty()) return 0;

        // if (text == last_clipboard_text) return 0;
        last_clipboard_text = text;

        if (text.find(PREFIX) != std::string::npos) {

            overlay_segments = build_segments(text);

            std::string replaced = rebuild_text(overlay_segments);

            if (replaced != text) {

                show_overlay(true);

                internal_change = true;
                set_clipboard_text(utf8_to_wstring(replaced));
            }
        }
        else {
            std::string encrypted = encrypt_message(text);

            internal_change = true;
            set_clipboard_text(utf8_to_wstring(encrypted));
        }

        return 0;
    }



    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

#pragma endregion

#pragma region overlay_proc

// Overlay proc

LRESULT CALLBACK OverlayProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        HBRUSH bg = CreateSolidBrush(RGB(20, 20, 22));
        FillRect(hdc, &ps.rcPaint, bg);
        DeleteObject(bg);

        SetBkMode(hdc, TRANSPARENT);

        HFONT font = CreateFontW(
            16, 0, 0, 0,
            FW_MEDIUM,
            FALSE, FALSE, FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            L"Segoe UI Emoji"
        );
        HFONT oldFont = (HFONT)SelectObject(hdc, font);

        SelectObject(hdc, font);

        int x = 12;
        int y = 10;
        int max_width = 380;

        int total_height = 0;

        for (auto& seg : overlay_segments) {
            RECT r = { x, y, x + max_width, 1000 };

            DrawTextW(
                hdc,
                seg.text.c_str(),
                -1,
                &r,
                DT_WORDBREAK | DT_CALCRECT
            );

            total_height += (r.bottom - r.top);
        }

        int width = max_width + 24;
        int height = total_height + 20;

        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0, 0,
            width,
            height,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE
        );

        int y_offset = y;

        for (auto& seg : overlay_segments) {

            RECT r = { x, y_offset, width - 12, height };

            if (seg.is_decrypted)
                SetTextColor(hdc, RGB(255, 80, 80));
            else
                SetTextColor(hdc, RGB(230, 230, 230));

            DrawTextW(
                hdc,
                seg.text.c_str(),
                -1,
                &r,
                DT_WORDBREAK
            );

            // measure again to move cursor properly
            RECT measure = { x, y_offset, width - 12, height };

            DrawTextW(
                hdc,
                seg.text.c_str(),
                -1,
                &measure,
                DT_WORDBREAK | DT_CALCRECT
            );

            y_offset += (measure.bottom - measure.top);
        }


        SelectObject(hdc, oldFont);
        DeleteObject(font);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY: {
        KillTimer(hwnd, 1);
        return 0;
    }

    case WM_TIMER: {
        POINT current;
        GetCursorPos(&current);

        int dx = abs(current.x - overlay_origin.x);
        int dy = abs(current.y - overlay_origin.y);

        // start fade when mouse moves
        if (!fading_out && (dx > 5 || dy > 5)) {
            fading_out = true;
        }

        if (!fading_out && GetTickCount() - overlay_spawn_time > 2000) {
            fading_out = true;
        }

        if (fading_out) {
            if (overlay_alpha > 10) {
                overlay_alpha -= 10;
                SetLayeredWindowAttributes(hwnd, 0, overlay_alpha, LWA_ALPHA);
            }
            else {
                ShowWindow(hwnd, SW_HIDE);
                KillTimer(hwnd, 1);

				overlay_active = false;
            }
        }

        return 0;
    }
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

#pragma endregion


#pragma region entry_point
// Entry point

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    if (sodium_init() < 0) return 1;
	// crypto_box_keypair(MY_PUBLIC_KEY, MY_SECRET_KEY); -- If you want new identity on each launch..

	// persistent identity
    if (!load_identity()) {
        crypto_box_keypair(MY_PUBLIC_KEY, MY_SECRET_KEY);
        save_identity();
    }

    instance_id = get_fingerprint();

    const wchar_t CLASS_NAME[] = L"TystWindow";

    // register window class
    WNDCLASS wc = {};

    wc.hIcon = (HICON)LoadImage(
        hInstance,
        MAKEINTRESOURCE(IDI_ICON1),
        IMAGE_ICON,
        256, 256,
        LR_DEFAULTCOLOR
    );

    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    // create window
    HWND hwnd = CreateWindowEx(
        0,
        CLASS_NAME,
        L"Tyst",
        WS_POPUP | WS_VISIBLE,
        100, 100, 260, 160,
        nullptr, nullptr, hInstance, nullptr
    );

    INITCOMMONCONTROLSEX icex{};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_WIN95_CLASSES;

    InitCommonControlsEx(&icex);

    tooltip_hwnd = CreateWindowEx(
        WS_EX_TOPMOST,
        TOOLTIPS_CLASS,
        NULL,
        WS_POPUP | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT,
        hwnd,
        NULL,
        hInstance,
        NULL
    );

    SetWindowPos(tooltip_hwnd, HWND_TOPMOST, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    TOOLINFO ti = {};
    ti.cbSize = sizeof(TOOLINFO);
    ti.uFlags = TTF_SUBCLASS;
    ti.hwnd = hwnd;
    ti.uId = 1;
    ti.lpszText = (LPWSTR)L"";

    GetClientRect(hwnd, &ti.rect);

    SendMessage(tooltip_hwnd, TTM_ADDTOOL, 0, (LPARAM)&ti);


    load_peers();

    save_peers();

    HICON hIcon = (HICON)LoadImage(
        hInstance,
        MAKEINTRESOURCE(IDI_ICON1),
        IMAGE_ICON,
        256, 256,
        LR_DEFAULTCOLOR
    );

    SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);

    main_hwnd = hwnd;

    // rounded window shape
    HRGN region = CreateRoundRectRgn(0, 0, 260, 160, 20, 20);
    SetWindowRgn(hwnd, region, TRUE);

    ShowWindow(hwnd, nCmdShow);

    const wchar_t OVERLAY_CLASS[] = L"TystOverlay";

    WNDCLASS owc = {};
    owc.lpfnWndProc = OverlayProc;
    owc.hInstance = hInstance;
    owc.lpszClassName = OVERLAY_CLASS;

    RegisterClass(&owc);

    overlay_hwnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED,
        OVERLAY_CLASS,
        L"",
        WS_POPUP,
        0, 0, 200, 50,
        nullptr, nullptr, hInstance, nullptr
    );

    HRGN rgn = CreateRoundRectRgn(0, 0, 400, 200, 16, 16);
    SetWindowRgn(overlay_hwnd, rgn, TRUE);

	AddClipboardFormatListener(hwnd);

    MSG msg;

    // Loop.
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }


    return 0;
}

#pragma endregion