#include <windows.h>
#include <string>
#include <iostream>
#include <sodium.h>
#include <vector>
#include <set>
// ==========================
// CONFIG / CONSTANTS
// ==========================

const std::string PREFIX = "SHHH#:";


// ==========================
// GLOBAL STATE (APP)
// ==========================

bool g_enabled = true;
bool internal_change = false;


// ==========================
// WINDOWS / HANDLES
// ==========================

HWND main_hwnd = nullptr;
HWND overlay_hwnd = nullptr;
DWORD overlay_spawn_time = 0;

// ==========================
// CLIPBOARD STATE
// ==========================

std::string last_clipboard_text;


// ==========================
// CRYPTO / IDENTITY
// ==========================

unsigned char MY_PUBLIC_KEY[crypto_box_PUBLICKEYBYTES];
unsigned char MY_SECRET_KEY[crypto_box_SECRETKEYBYTES];

std::vector<unsigned char> current_target;
bool has_target = false;

std::set<std::string> known_peers;
std::wstring last_contact_fp;
std::wstring instance_id;


// ==========================
// OVERLAY STATE
// ==========================

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


// ==========================
// UI / INTERACTION
// ==========================

RECT toggle_rect = { 150, 55, 200, 75 };
RECT status_rect = { 40, 50, 140, 80 };


// ==========================
// UTILITY FUNCTIONS
// ==========================

std::wstring to_wstring(const std::string& str);

std::string pubkey_to_string(const unsigned char* key) {
    return std::string((const char*)key, crypto_box_PUBLICKEYBYTES);
}
void save_peers() {
    FILE* f;
    if(fopen_s(&f,"peers.bin", "wb") != 0) return;
    if (!f) return;

    for (const auto& p : known_peers) {
        fwrite(p.data(), 1, p.size(), f);
    }

    fclose(f);
}

void load_peers() {
    FILE* f;
    if(fopen_s(&f,"peers.bin", "rb") != 0) return;
    if (!f) return;

    while (true) {
        char buf[crypto_box_PUBLICKEYBYTES];

        size_t read = fread(buf, 1, crypto_box_PUBLICKEYBYTES, f);
        if (read != crypto_box_PUBLICKEYBYTES) break;

        known_peers.insert(std::string(buf, crypto_box_PUBLICKEYBYTES));
    }

    fclose(f);
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

// --- Clipboard helpers ---

// Read text from clipboard
std::string get_clipboard_text() {
    if (!OpenClipboard(nullptr)) {
        return "";
    }

    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) {
        CloseClipboard();
        return "";
    }

    char* pszText = static_cast<char*>(GlobalLock(hData));
    if (!pszText) {
        CloseClipboard();
        return "";
    }

    std::string text(pszText);

    GlobalUnlock(hData);
    CloseClipboard();
    return text;
}

// Write text to clipboard
void set_clipboard_text(const std::string& text) {
    OpenClipboard(nullptr);
    EmptyClipboard();

    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    memcpy(GlobalLock(hGlob), text.c_str(), text.size() + 1);
    GlobalUnlock(hGlob);

    SetClipboardData(CF_TEXT, hGlob);
    CloseClipboard();
}


bool load_identity() {
    FILE* f;
    if(fopen_s(&f, "identity.bin", "rb") != 0) return false;
    if (!f) return false;

    fread(MY_PUBLIC_KEY, 1, crypto_box_PUBLICKEYBYTES, f);
    fread(MY_SECRET_KEY, 1, crypto_box_SECRETKEYBYTES, f);

    fclose(f);
    return true;
}

void save_identity() {
    FILE* f;
    if(fopen_s(&f,"identity.bin", "wb") != 0) return;
    if (!f) return;

    fwrite(MY_PUBLIC_KEY, 1, crypto_box_PUBLICKEYBYTES, f);
    fwrite(MY_SECRET_KEY, 1, crypto_box_SECRETKEYBYTES, f);

    fclose(f);
}

// --- Base64 helpers (libsodium) ---

// Encode binary → base64
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

// Decode base64 → binary
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

// --- Crypto ---

// Encrypt plaintext → base64 packet
std::string encrypt_message(const std::string& text) {

    // No target → send identity only
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

std::wstring fingerprint_from_key(const unsigned char* key) {
    std::vector<unsigned char> data(
        key,
        key + crypto_box_PUBLICKEYBYTES
    );

    std::string encoded = base64_encode(data);

    return std::wstring(encoded.begin(), encoded.begin() + 6);
}


std::string decrypt_message(const std::string& text) {
    std::string encoded = text.substr(PREFIX.size());

    std::vector<unsigned char> data = base64_decode(encoded);
    if (data.empty()) return "[Invalid data]";

    // --- NEW: identity message ---
    if (data.size() == crypto_box_PUBLICKEYBYTES) {
        std::string key_str = std::string(
            (char*)data.data(),
            crypto_box_PUBLICKEYBYTES
        );

        current_target.assign(data.begin(), data.end());
        has_target = true;

        std::wstring fp = fingerprint_from_key(data.data());
		last_contact_fp = fp;
        InvalidateRect(main_hwnd, NULL, TRUE);
        std::string fp_str(fp.begin(), fp.end());


        if (known_peers.find(key_str) == known_peers.end()) {
            known_peers.insert(key_str);
            save_peers();
            return "[New peer connected]";
        }

        return "[Connected to " + fp_str + "]";
    }

    // --- normal encrypted message ---
    size_t offset = 0;

    if (data.size() < crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
        return "[Invalid data]";
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
        return "[Decryption failed]";
    }

    // update active peer automatically
    current_target.assign(
        sender_pub,
        sender_pub + crypto_box_PUBLICKEYBYTES
    );

    has_target = true;

    std::string msg((char*)decrypted.data(), decrypted.size());

    std::wstring fp = fingerprint_from_key(sender_pub);
    std::string fp_str(fp.begin(), fp.end());

    return "[" + fp_str + "] " + msg;
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
        std::string decrypted = decrypt_message(block);

        segments.push_back({
            to_wstring(decrypted),
            true
            });

        pos = end;
    }

    return segments;
}

// Check if message starts with prefix
bool is_encrypted(const std::string& text) {
    return text.rfind(PREFIX, 0) == 0;
}


DWORD overlay_last_time = 0;

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

std::string rebuild_text(const std::vector<TextSegment>& segments) {
    std::string result;

    for (const auto& seg : segments) {
        result += std::string(seg.text.begin(), seg.text.end());
    }

    return result;
}

// --- Window rendering ---

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
            L"Verdana"
        );

        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        SetGraphicsMode(hdc, GM_ADVANCED);

        // background
        HBRUSH brush = CreateSolidBrush(RGB(28, 28, 30));
        FillRect(hdc, &ps.rcPaint, brush);
        DeleteObject(brush);

        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, font);

        // ---- TITLE ----
        SetTextColor(hdc, RGB(255, 255, 255));
        std::wstring title = L"Tyst [" + instance_id + L"]";
        TextOutW(hdc, 20, 20, title.c_str(), title.length());

        // ---- STATUS DOT ----
        HPEN pen = CreatePen(PS_NULL, 0, 0);
        HBRUSH dotBrush = CreateSolidBrush(
            g_enabled ? RGB(0, 200, 120) : RGB(120, 120, 120)
        );

        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, dotBrush);

        Ellipse(hdc, 20, 60, 34, 74);

        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);

        DeleteObject(dotBrush);
        DeleteObject(pen);

        // ---- STATUS TEXT ----
        SetTextColor(hdc, g_enabled ? RGB(0, 200, 120) : RGB(160, 160, 160));

        std::wstring status = g_enabled ? L"Enabled" : L"Disabled";
        TextOutW(hdc, 50, 58, status.c_str(), status.length());

        SetTextColor(hdc, RGB(180, 180, 180));
        std::wstring contact_text;

        if (has_target) {
            contact_text = L"→ " + last_contact_fp;
        }
        else {
            contact_text = L"→ No contact";
        }

        TextOutW(hdc, 50, 80, contact_text.c_str(), contact_text.length());

        // ---- BORDER ----
        int padding = 2;

        HBRUSH nullBrush = (HBRUSH)GetStockObject(NULL_BRUSH);
        SelectObject(hdc, nullBrush);

        // outer
        HPEN outerPen = CreatePen(PS_SOLID, 3, RGB(90, 60, 180));
        HPEN oldOuter = (HPEN)SelectObject(hdc, outerPen);

        RoundRect(hdc, padding, padding, 260 - padding, 120 - padding, 18, 18);

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
            120 - padding - 1,
            16,
            16
        );

        SelectObject(hdc, oldInner);
        DeleteObject(innerPen);

        // cleanup
        DeleteObject(font);

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
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

        // existing drag logic
        ReleaseCapture();
        SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        return 0;
    }
        // force normal cursor
    case WM_SETCURSOR: {
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hwnd, &pt);

        if (PtInRect(&status_rect, pt)) {
            SetCursor(LoadCursor(nullptr, IDC_HAND));
            return TRUE;
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

    case WM_CLIPBOARDUPDATE: {
        if (!g_enabled) return 0;
        if (internal_change) {
            internal_change = false;
            return 0;
        }

        std::string text = get_clipboard_text();
        if (text.empty()) return 0;

        if (text == last_clipboard_text) return 0;
        last_clipboard_text = text;

        if (text.find(PREFIX) != std::string::npos) {

            overlay_segments = build_segments(text);

            std::string replaced = rebuild_text(overlay_segments);

            if (replaced != text) {

                show_overlay(true);

                internal_change = true;
                set_clipboard_text(replaced);
            }
        }
        else {
            std::string encrypted = encrypt_message(text);

            internal_change = true;
            set_clipboard_text(encrypted);
        }

        return 0;
    }



    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

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
            L"Verdana"
        );

        SelectObject(hdc, font);

        int x = 12;
        int y = 10;
        int max_width = 380;

        // --- PASS 1: measure total height ---
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

        // --- PASS 2: draw ---
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

        DeleteObject(font);

        EndPaint(hwnd, &ps);
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


// Convert std::string → std::wstring (basic)
std::wstring to_wstring(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

std::wstring get_fingerprint() {
    std::vector<unsigned char> short_key(
        MY_PUBLIC_KEY,
        MY_PUBLIC_KEY + 6
    );

    std::string encoded = base64_encode(short_key);

    // trim padding + keep it short
    encoded = encoded.substr(0, 6);

    return std::wstring(encoded.begin(), encoded.end());
}


// --- Entry point ---

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    if (sodium_init() < 0) return 1;
	// crypto_box_keypair(MY_PUBLIC_KEY, MY_SECRET_KEY); -- If you want new identity on each launch..

	// persistent identity
    if (!load_identity()) {
        crypto_box_keypair(MY_PUBLIC_KEY, MY_SECRET_KEY);
        save_identity();
    }

    instance_id = get_fingerprint();

    load_peers();



    const wchar_t CLASS_NAME[] = L"TystWindow";

    // register window class
    WNDCLASS wc = {};
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
        100, 100, 260, 120,
        nullptr, nullptr, hInstance, nullptr
    );

    main_hwnd = hwnd;

    // rounded window shape
    HRGN region = CreateRoundRectRgn(0, 0, 260, 120, 20, 20);
    SetWindowRgn(hwnd, region, TRUE);

    ShowWindow(hwnd, nCmdShow);


    // TYST OVERLAY
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

    // main loop
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }


    return 0;
}