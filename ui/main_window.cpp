#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <cstdio>
#include "main_window.h"
#include "../core/app_data.h"
#include "../core/proxy_reader.h"

// ── Colours ─────────────────────────────────────────────────
static const COLORREF CLR_BG     = RGB(10,  14,  20);
static const COLORREF CLR_PANEL  = RGB(15,  20,  30);
static const COLORREF CLR_ACCENT = RGB(0,  210, 140);
static const COLORREF CLR_TEXT   = RGB(200, 220, 200);
static const COLORREF CLR_DIM    = RGB(80,  110, 90);
static const COLORREF CLR_WARN   = RGB(255, 160,  50);  // filter-off warning

// ── IDs ─────────────────────────────────────────────────────
static const int ID_TIMER          = 1001;
static const int ID_LB_PROC        = 1002;
static const int ID_LB_CONN        = 1003;
static const int ID_LB_LOG         = 1004;
static const int ID_BTN_FILTER     = 1005;
static const int ID_BTN_CLEARFOCUS = 1006;
static const int ID_BTN_CLEARLOG   = 1007;
static const int ID_BTN_PROXY      = 1008;

// ── Globals ──────────────────────────────────────────────────
static HWND   g_hwndMain       = nullptr;
static HWND   g_hwndProc       = nullptr;
static HWND   g_hwndConn       = nullptr;
static HWND   g_hwndLog        = nullptr;
static HWND   g_hwndFilter     = nullptr;
static HWND   g_hwndClearFocus = nullptr;  // [Show All] focus exit button
static HWND   g_hwndClearLog   = nullptr;  // [Clear Log] button
static HWND   g_hwndProxy      = nullptr;  // [API Proxy] button
static HBRUSH g_brBg           = nullptr;
static HBRUSH g_brPanel        = nullptr;
static HFONT  g_fontMono       = nullptr;
static HFONT  g_fontBold       = nullptr;
static bool   g_disclaimerOK   = false;
// Process focus state
static DWORD              g_selectedPID = 0;  // 0 = show all
static std::vector<DWORD> g_procOrder;        // listbox data index -> PID
static bool               g_proxyActive = false; // proxy state

// ── Resources ────────────────────────────────────────────────
static void CreateResources() {
    g_brBg    = CreateSolidBrush(CLR_BG);
    g_brPanel = CreateSolidBrush(CLR_PANEL);
    g_fontMono = CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,"Consolas");
    g_fontBold = CreateFontA(15,0,0,0,FW_BOLD,0,0,0,
        DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,"Consolas");
}
static void DestroyResources() {
    if(g_brBg)    { DeleteObject(g_brBg);    g_brBg=nullptr; }
    if(g_brPanel) { DeleteObject(g_brPanel); g_brPanel=nullptr; }
    if(g_fontMono){ DeleteObject(g_fontMono);g_fontMono=nullptr; }
    if(g_fontBold){ DeleteObject(g_fontBold);g_fontBold=nullptr; }
}

// ── Layout ───────────────────────────────────────────────────
static void DoLayout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd,&rc);
    int W=rc.right, H=rc.bottom;
    const int HEADER_H=42, TOOLBAR_H=32, LOG_H=140, PAD=5, LEFT_W=320;
    int bodyTop = HEADER_H + TOOLBAR_H + PAD;
    int bodyH   = H - bodyTop - LOG_H - PAD*2;
    // Toolbar row: [Filter:370] [ClearFocus:160] [ClearLog:120] [Proxy:200]
    int ty = HEADER_H + 4;
    SetWindowPos(g_hwndFilter,    nullptr, PAD,        ty, 370, 24, SWP_NOZORDER|SWP_NOACTIVATE);
    SetWindowPos(g_hwndClearFocus,nullptr, PAD+375,    ty, 160, 24, SWP_NOZORDER|SWP_NOACTIVATE);
    SetWindowPos(g_hwndClearLog,  nullptr, PAD+375+165,ty, 120, 24, SWP_NOZORDER|SWP_NOACTIVATE);
    SetWindowPos(g_hwndProxy,     nullptr, PAD+375+165+125,ty, 200, 24, SWP_NOZORDER|SWP_NOACTIVATE);
    SetWindowPos(g_hwndProc,nullptr, PAD,bodyTop, LEFT_W,bodyH, SWP_NOZORDER|SWP_NOACTIVATE);
    SetWindowPos(g_hwndConn,nullptr, LEFT_W+PAD*2,bodyTop, W-LEFT_W-PAD*3,bodyH, SWP_NOZORDER|SWP_NOACTIVATE);
    SetWindowPos(g_hwndLog, nullptr, PAD,H-LOG_H-PAD, W-PAD*2,LOG_H, SWP_NOZORDER|SWP_NOACTIVATE);
}

// ── Speed formatter ──────────────────────────────────────────
static std::string FmtSpeed(uint64_t bps) {
    char buf[32];
    if(bps >= 1024*1024)
        snprintf(buf,sizeof(buf),"%.1fMB/s", bps/(1024.0*1024.0));
    else if(bps >= 1024)
        snprintf(buf,sizeof(buf),"%.1fKB/s", bps/1024.0);
    else
        snprintf(buf,sizeof(buf),"%lluB/s",(unsigned long long)bps);
    return buf;
}

// ── Refresh ──────────────────────────────────────────────────
static void RefreshUI() {
    // Snapshot under lock
    std::vector<std::pair<DWORD,ProcessEntry>> procs;
    std::vector<ConnectionEntry> conns;
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        for(auto& [pid,pe] : g_state.processes)
            procs.push_back({pid,pe});
        conns = g_state.connections;
    }

    // Sort by total bandwidth desc, fallback to connCount
    std::sort(procs.begin(),procs.end(),[](auto& a,auto& b){
        uint64_t bwA = a.second.bpsIn + a.second.bpsOut;
        uint64_t bwB = b.second.bpsIn + b.second.bpsOut;
        if(bwA != bwB) return bwA > bwB;
        return a.second.connCount > b.second.connCount;
    });

    bool filterOn = g_state.filterEstablished.load();

    // Update filter button — short label that fits in 370px
    if(g_hwndFilter) {
        SetWindowTextA(g_hwndFilter,
            filterOn ? "[FILTER: ESTABLISHED ONLY]  click to show all states"
                     : "[FILTER: ALL STATES]  click for established-only");
    }

    // Compute total download BPS for percentage calc
    uint64_t totalBpsIn = 0;
    for(auto& [pid,pe] : procs) totalBpsIn += pe.bpsIn;
    if(totalBpsIn == 0) totalBpsIn = 1; // avoid div-by-zero

    // ── Left panel: process list with rank + % ──────────────
    int topIdx = (int)SendMessage(g_hwndProc,LB_GETTOPINDEX,0,0);
    SendMessage(g_hwndProc,LB_RESETCONTENT,0,0);
    g_procOrder.clear();  // rebuild PID map
    SendMessageA(g_hwndProc,LB_ADDSTRING,0,(LPARAM)" RNK  PROCESS              [C]  DL         UL        SHARE");
    SendMessageA(g_hwndProc,LB_ADDSTRING,0,(LPARAM)" --------------------------------------------------------");

    int rank = 0;
    for(auto& [pid,pe] : procs) {
        rank++;
        g_procOrder.push_back(pid);  // index 0 here = listbox row 2
        int pct = (int)((pe.bpsIn * 100) / totalBpsIn);
        char rnk[6];
        if(rank<=3) snprintf(rnk,sizeof(rnk),"[#%d]",rank);
        else        snprintf(rnk,sizeof(rnk),"    ");

        char line[200];
        if(pe.bpsIn > 0 || pe.bpsOut > 0) {
            snprintf(line,sizeof(line)," %s %-18s [%2d]  %-9s  %-9s  %2d%%",
                rnk, pe.name.c_str(), pe.connCount,
                FmtSpeed(pe.bpsIn).c_str(),
                FmtSpeed(pe.bpsOut).c_str(), pct);
        } else {
            snprintf(line,sizeof(line)," %s %-18s [%2d]  ---",
                rnk, pe.name.c_str(), pe.connCount);
        }
        SendMessageA(g_hwndProc,LB_ADDSTRING,0,(LPARAM)line);
    }
    SendMessage(g_hwndProc,LB_SETTOPINDEX,topIdx,0);

    // ── Right panel: grouped domain view (focus or all) ──────────
    int topConn = (int)SendMessage(g_hwndConn,LB_GETTOPINDEX,0,0);
    SendMessage(g_hwndConn,LB_RESETCONTENT,0,0);

    // If in focus mode, only show selected process
    bool focusMode = (g_selectedPID != 0);
    if(focusMode) {
        // Show focus banner
        char banner[120];
        snprintf(banner,sizeof(banner),"  [FOCUS MODE]  Showing: %s  (PID:%lu)  |  Press [Show All] to exit",
            "", (unsigned long)g_selectedPID);
        // Find the process name
        for(auto& [pid,pe] : procs)
            if(pid==g_selectedPID)
                snprintf(banner,sizeof(banner),"  [FOCUS]  %s  PID:%lu  |  click [Show All] or press ESC",
                    pe.name.c_str(),(unsigned long)pid);
        SendMessageA(g_hwndConn,LB_ADDSTRING,0,(LPARAM)banner);
        SendMessageA(g_hwndConn,LB_ADDSTRING,0,(LPARAM)"");
    }

    for(auto& [pid,pe] : procs) {
        if(focusMode && pid != g_selectedPID) continue;

        // Process header
        char hdr[160];
        if(pe.bpsIn > 0 || pe.bpsOut > 0)
            snprintf(hdr,sizeof(hdr)," > %-20s PID:%-6lu  DL:%-9s  UL:%s",
                pe.name.c_str(),(unsigned long)pid,
                FmtSpeed(pe.bpsIn).c_str(),
                FmtSpeed(pe.bpsOut).c_str());
        else
            snprintf(hdr,sizeof(hdr)," > %-20s PID:%-6lu  [%d conn]",
                pe.name.c_str(),(unsigned long)pid, pe.connCount);
        SendMessageA(g_hwndConn,LB_ADDSTRING,0,(LPARAM)hdr);

        // Grouped domain rows (pre-sorted by count desc)
        for(auto& ds : pe.domainStats) {
            char row[180];
            snprintf(row,sizeof(row),"    %-42s :%5u  x%-3d",
                ds.domain.c_str(), ds.port, ds.count);
            SendMessageA(g_hwndConn,LB_ADDSTRING,0,(LPARAM)row);
        }

        SendMessageA(g_hwndConn,LB_ADDSTRING,0,(LPARAM)"");
    }
    SendMessage(g_hwndConn,LB_SETTOPINDEX, focusMode ? 0 : topConn, 0);

    // Show/hide Clear Focus button
    ShowWindow(g_hwndClearFocus, focusMode ? SW_SHOW : SW_HIDE);

    // ── Log panel: append-only, NEVER cleared by refresh ────────
    {
        std::lock_guard<std::mutex> lk(g_state.mtx);
        static size_t lastCount = 0;
        size_t cur = g_state.logLines.size();
        // Only append, never reset — logs persist until user clears
        for(size_t i = lastCount; i < cur; i++)
            SendMessageA(g_hwndLog,LB_ADDSTRING,0,(LPARAM)g_state.logLines[i].c_str());
        lastCount = cur;
        int cnt = (int)SendMessage(g_hwndLog,LB_GETCOUNT,0,0);
        if(cnt > 0) SendMessage(g_hwndLog,LB_SETTOPINDEX,cnt-1,0);
    }
}

// ── Header paint ─────────────────────────────────────────────
static void PaintHeader(HWND hwnd) {
    RECT rc; GetClientRect(hwnd,&rc);
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd,&ps);
    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc,rc.right,42);
    HBITMAP old = (HBITMAP)SelectObject(mem,bmp);

    RECT hr={0,0,rc.right,42};
    FillRect(mem,&hr,g_brPanel);

    HPEN pen=CreatePen(PS_SOLID,1,CLR_ACCENT);
    HPEN op=(HPEN)SelectObject(mem,pen);
    MoveToEx(mem,0,41,nullptr); LineTo(mem,rc.right,41);
    SelectObject(mem,op); DeleteObject(pen);

    SetBkMode(mem,TRANSPARENT);
    HFONT of=(HFONT)SelectObject(mem,g_fontBold);
    SetTextColor(mem,CLR_ACCENT);
    RECT t1={12,4,rc.right-10,24};
    DrawTextA(mem,"  NetSense+  v1.0",-1,&t1,DT_LEFT|DT_SINGLELINE);
    SetTextColor(mem,CLR_DIM);
    SelectObject(mem,g_fontMono);
    RECT t2={12,23,rc.right-10,42};
    DrawTextA(mem,"  Real-time Network Analyzer  |  Phase 1..8  |  Personal / Educational Use Only",
              -1,&t2,DT_LEFT|DT_SINGLELINE);
    SelectObject(mem,of);

    BitBlt(hdc,0,0,rc.right,42,mem,0,0,SRCCOPY);
    SelectObject(mem,old); DeleteObject(bmp); DeleteDC(mem);
    EndPaint(hwnd,&ps);
}

// ── Main WndProc ─────────────────────────────────────────────
static LRESULT CALLBACK MainWndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE:
        CreateResources();
        // Toolbar buttons
        g_hwndFilter = CreateWindowExA(0,"BUTTON",
            "[FILTER: ESTABLISHED ONLY]  click to show all states",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,
            hwnd,(HMENU)ID_BTN_FILTER,nullptr,nullptr);
        SendMessage(g_hwndFilter,WM_SETFONT,(WPARAM)g_fontMono,FALSE);

        g_hwndClearFocus = CreateWindowExA(0,"BUTTON","[Show All]  ESC",
            WS_CHILD|BS_PUSHBUTTON,  // hidden until focus active
            0,0,0,0,hwnd,(HMENU)ID_BTN_CLEARFOCUS,nullptr,nullptr);
        SendMessage(g_hwndClearFocus,WM_SETFONT,(WPARAM)g_fontMono,FALSE);

        g_hwndClearLog = CreateWindowExA(0,"BUTTON","[Clear Log]",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,
            hwnd,(HMENU)ID_BTN_CLEARLOG,nullptr,nullptr);
        SendMessage(g_hwndClearLog,WM_SETFONT,(WPARAM)g_fontMono,FALSE);

        g_hwndProxy = CreateWindowExA(0,"BUTTON","[PROXY: OFF] Start mitmdump",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,
            hwnd,(HMENU)ID_BTN_PROXY,nullptr,nullptr);
        SendMessage(g_hwndProxy,WM_SETFONT,(WPARAM)g_fontMono,FALSE);

        g_hwndProc = CreateWindowExA(0,"LISTBOX",nullptr,
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT,
            0,0,0,0,hwnd,(HMENU)ID_LB_PROC,nullptr,nullptr);
        SendMessage(g_hwndProc,WM_SETFONT,(WPARAM)g_fontMono,TRUE);

        g_hwndConn = CreateWindowExA(0,"LISTBOX",nullptr,
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|LBS_NOINTEGRALHEIGHT,
            0,0,0,0,hwnd,(HMENU)ID_LB_CONN,nullptr,nullptr);
        SendMessage(g_hwndConn,WM_SETFONT,(WPARAM)g_fontMono,TRUE);

        g_hwndLog = CreateWindowExA(0,"LISTBOX",nullptr,
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|LBS_NOINTEGRALHEIGHT|LBS_OWNERDRAWFIXED|LBS_HASSTRINGS,
            0,0,0,0,hwnd,(HMENU)ID_LB_LOG,nullptr,nullptr);
        SendMessage(g_hwndLog,WM_SETFONT,(WPARAM)g_fontMono,TRUE);

        SetTimer(hwnd,ID_TIMER,2000,nullptr);
        return 0;

    case WM_MEASUREITEM: {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lp;
        if(mis->CtlID == ID_LB_LOG) mis->itemHeight = 16;
        return TRUE;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
        if(dis->itemID == -1) return 0;
        
        if(dis->hwndItem == g_hwndLog) {
            char buf[512] = {0};
            SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)buf);
            std::string text(buf);
            
            COLORREF fg = CLR_TEXT;
            if (text.find("[INSIGHT]") != std::string::npos) fg = RGB(255, 215, 0); // Gold/Yellow
            else if (text.find("[MITM REQ]") != std::string::npos) fg = RGB(0, 255, 255); // Cyan
            else if (text.find("[MITM RSP]") != std::string::npos) fg = RGB(150, 200, 255); // Light Blue
            else if (text.find("[REQ]") != std::string::npos) fg = RGB(255, 140, 0); // Orange
            else if (text.find("[RSP]") != std::string::npos) fg = RGB(144, 238, 144); // Light Green
            else if (text.find("[+]") != std::string::npos) fg = RGB(100, 255, 100); // Bright Green
            
            HBRUSH bgBrush = CreateSolidBrush(CLR_BG);
            FillRect(dis->hDC, &dis->rcItem, bgBrush);
            DeleteObject(bgBrush);
            
            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, fg);
            HFONT oldFont = (HFONT)SelectObject(dis->hDC, g_fontMono);
            
            RECT tr = dis->rcItem;
            tr.left += 4;
            DrawTextA(dis->hDC, text.c_str(), -1, &tr, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
            
            SelectObject(dis->hDC, oldFont);
            return TRUE;
        }
        return 0;
    }

    case WM_COMMAND: {
        WORD id  = LOWORD(wp);
        WORD ntf = HIWORD(wp);

        // Filter toggle
        if(id == ID_BTN_FILTER) {
            g_state.filterEstablished.store(!g_state.filterEstablished.load());
            RefreshUI();
        }

        // Clear focus (Show All)
        if(id == ID_BTN_CLEARFOCUS) {
            g_selectedPID = 0;
            SendMessage(g_hwndProc,LB_SETCURSEL,(WPARAM)-1,0);
            RefreshUI();
        }

        // Clear log
        if(id == ID_BTN_CLEARLOG) {
            SendMessage(g_hwndLog,LB_RESETCONTENT,0,0);
            std::lock_guard<std::mutex> lk(g_state.mtx);
            g_state.logLines.clear();
            // Reset the static counter in RefreshUI
        }

        // Proxy toggle
        if(id == ID_BTN_PROXY) {
            g_proxyActive = !g_proxyActive;
            if(g_proxyActive) {
                if(StartProxyServer()) {
                    SetWindowTextA(g_hwndProxy, "[PROXY: ON] Stop mitmdump");
                    g_state.addLog("[PROXY] Server started on 127.0.0.1:8080. Point your browser proxy here.");
                    g_state.addLog("[PROXY] To inspect HTTPS, go to http://mitm.it and install the cert.");
                } else {
                    g_proxyActive = false;
                    g_state.addLog("[PROXY] ERROR: Failed to start mitmdump. Is mitmproxy installed?");
                }
            } else {
                StopProxyServer();
                SetWindowTextA(g_hwndProxy, "[PROXY: OFF] Start mitmdump");
                g_state.addLog("[PROXY] Server stopped.");
            }
        }

        // Process list click -> focus mode
        if(id == ID_LB_PROC && ntf == LBN_SELCHANGE) {
            int sel = (int)SendMessage(g_hwndProc,LB_GETCURSEL,0,0);
            // Skip 2 header rows (index 0=header, 1=dashes)
            int dataIdx = sel - 2;
            if(dataIdx >= 0 && dataIdx < (int)g_procOrder.size()) {
                g_selectedPID = g_procOrder[dataIdx];
            } else {
                g_selectedPID = 0;
            }
            RefreshUI();
        }
        return 0;
    }

    case WM_KEYDOWN:
        if(wp == VK_ESCAPE && g_selectedPID != 0) {
            g_selectedPID = 0;
            SendMessage(g_hwndProc,LB_SETCURSEL,(WPARAM)-1,0);
            RefreshUI();
        }
        return 0;

    case WM_TIMER:
        if(wp==ID_TIMER){ RefreshUI(); InvalidateRect(hwnd,nullptr,FALSE); }
        return 0;

    case WM_SIZE:   DoLayout(hwnd); return 0;
    case WM_PAINT:  PaintHeader(hwnd); return 0;

    case WM_ERASEBKGND: {
        HDC h=(HDC)wp; RECT r; GetClientRect(hwnd,&r);
        FillRect(h,&r,g_brBg); return 1;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC h=(HDC)wp;
        SetTextColor(h,CLR_TEXT); SetBkColor(h,CLR_PANEL);
        return (LRESULT)g_brPanel;
    }
    case WM_CTLCOLORSTATIC: {
        HDC h=(HDC)wp;
        SetTextColor(h,CLR_TEXT); SetBkColor(h,CLR_BG);
        return (LRESULT)g_brBg;
    }
    case WM_DESTROY:
        KillTimer(hwnd,ID_TIMER);
        g_state.running=false;
        DestroyResources();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd,msg,wp,lp);
}

// ── Disclaimer ───────────────────────────────────────────────
static LRESULT CALLBACK DisclaimerProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    static HBRUSH hbr = nullptr;
    static HFONT  hfnt= nullptr;
    switch(msg) {
    case WM_CREATE:
        hbr  = CreateSolidBrush(RGB(10,14,20));
        hfnt = CreateFontA(14,0,0,0,FW_NORMAL,0,0,0,
            DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,FIXED_PITCH|FF_MODERN,"Consolas");

        {
            HWND hs = CreateWindowExA(0,"STATIC",
                "[!] LEGAL DISCLAIMER\r\n\r\n"
                "NetSense+ monitors YOUR device's network activity.\r\n\r\n"
                "[-] You must NOT use this tool to:\r\n"
                "    - Capture traffic of OTHER people\r\n"
                "    - Monitor public WiFi to spy on others\r\n"
                "    - Intercept HTTPS without consent\r\n\r\n"
                "[+] Legal use only:\r\n"
                "    - Your own device and network\r\n"
                "    - Educational / research purposes\r\n"
                "    - With explicit permission of the network owner\r\n\r\n"
                "HTTPS Inspection mode requires installing a root certificate.\r\n"
                "Only enable on your own machine.\r\n\r\n"
                "Misuse may violate the IT Act / CFAA and similar laws.\r\n\r\n"
                "By clicking ACCEPT you confirm you understand the above.",
                WS_CHILD|WS_VISIBLE|SS_LEFT,
                20,20,570,340,hwnd,nullptr,nullptr,nullptr);
            SendMessage(hs,WM_SETFONT,(WPARAM)hfnt,FALSE);
        }
        {
            HWND hb1 = CreateWindowExA(0,"BUTTON","[OK]  I Accept  -  Launch NetSense+",
                WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                20,380,280,36,hwnd,(HMENU)IDOK,nullptr,nullptr);
            SendMessage(hb1,WM_SETFONT,(WPARAM)hfnt,FALSE);

            HWND hb2 = CreateWindowExA(0,"BUTTON","[X]  Decline  -  Exit",
                WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                320,380,200,36,hwnd,(HMENU)IDCANCEL,nullptr,nullptr);
            SendMessage(hb2,WM_SETFONT,(WPARAM)hfnt,FALSE);
        }
        return 0;

    case WM_CTLCOLORSTATIC: {
        HDC h=(HDC)wp;
        SetBkMode(h,TRANSPARENT);
        SetTextColor(h,RGB(200,220,200));
        return (LRESULT)hbr;
    }
    case WM_ERASEBKGND: {
        HDC h=(HDC)wp; RECT r; GetClientRect(hwnd,&r);
        FillRect(h,&r,hbr); return 1;
    }
    case WM_COMMAND:
        if(LOWORD(wp)==IDOK)     { g_disclaimerOK=true;  DestroyWindow(hwnd); }
        if(LOWORD(wp)==IDCANCEL) { g_disclaimerOK=false; DestroyWindow(hwnd); }
        return 0;
    case WM_DESTROY:
        if(hbr) { DeleteObject(hbr); hbr=nullptr; }
        if(hfnt){ DeleteObject(hfnt);hfnt=nullptr; }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd,msg,wp,lp);
}

static bool ShowDisclaimer(HINSTANCE hInst) {
    g_disclaimerOK = false;
    WNDCLASSA wc{};
    wc.lpfnWndProc   = DisclaimerProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "NsDisclaimer";
    wc.hCursor       = LoadCursor(nullptr,IDC_ARROW);
    RegisterClassA(&wc);

    HWND hw = CreateWindowExA(WS_EX_APPWINDOW,"NsDisclaimer",
        "NetSense+ - Legal Disclaimer",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU,
        CW_USEDEFAULT,CW_USEDEFAULT,620,465,
        nullptr,nullptr,hInst,nullptr);
    ShowWindow(hw,SW_SHOW); UpdateWindow(hw);

    MSG m{};
    // Loop until WM_QUIT — properly consumes it so main loop is clean
    while(GetMessageA(&m,nullptr,0,0)) {
        TranslateMessage(&m); DispatchMessageA(&m);
    }
    return g_disclaimerOK;
}

// ── Public API ───────────────────────────────────────────────
void RequestUIRefresh() {
    if(g_hwndMain) InvalidateRect(g_hwndMain,nullptr,FALSE);
}

int RunUI(HINSTANCE hInstance, int nCmdShow) {
    if(!ShowDisclaimer(hInstance)) return 1;
    g_state.disclaimerAccepted = true;

    const char* CLS = "NetsenseMain";
    WNDCLASSA wc{};
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = CLS;
    wc.hbrBackground = CreateSolidBrush(CLR_BG);
    wc.hCursor       = LoadCursor(nullptr,IDC_ARROW);
    wc.hIcon         = LoadIcon(nullptr,IDI_APPLICATION);
    if(!RegisterClassA(&wc)) return -1;

    g_hwndMain = CreateWindowExA(WS_EX_APPWINDOW,CLS,
        "NetSense+ v1.0 - Real-time Network Analyzer",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,CW_USEDEFAULT,1150,720,
        nullptr,nullptr,hInstance,nullptr);
    if(!g_hwndMain) return -1;

    ShowWindow(g_hwndMain,nCmdShow); UpdateWindow(g_hwndMain);
    RefreshUI();

    MSG msg{};
    while(GetMessageA(&msg,nullptr,0,0)) {
        TranslateMessage(&msg); DispatchMessageA(&msg);
    }
    return (int)msg.wParam;
}
