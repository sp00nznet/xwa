/*
 * dplay: the DirectPlay the game gets, in place of Windows' (dplayx.dll).
 *
 * Windows' DirectPlay no longer finds sessions between two machines here (its
 * helper takes the enumeration and never answers), so the host provides the
 * part XvT uses, measured with dplog: DirectPlayCreate (only to see that
 * DirectPlay is there), and the lobby -- CreateAddress, Set/GetConnectionSettings
 * and Connect, which creates or joins the session and hands out its
 * IDirectPlay2A -- then GetCaps, CreatePlayer, CreateGroup, EnumPlayers, Send
 * and Receive.
 *
 * The session is a star over TCP: the host listens on DP_PORT, each joiner
 * connects to the address the game was given (Config.cfg's ipaddress), and
 * the host relays. Each machine is a node; a player's or group's DPID is
 * node << 16 | n, so every node names its own players without asking the
 * host. The host keeps the table of players and groups and tells every node
 * of each change, which the game sees as DirectPlay's system messages
 * (DPSYS_CREATEPLAYERORGROUP and so on).
 *
 * XVT_DPLOG=1 logs every call. A method XvT has not been seen to call logs
 * itself and returns DPERR_UNSUPPORTED.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dplay.h"

#define DP_PORT 47700

typedef DWORD DPID;
#define DP_OK                 0
#define DPERR_BUFFERTOOSMALL  0x8877001E
#define DPERR_INVALIDPLAYER   0x88770096
#define DPERR_NOSESSIONS      0x887700BC
#define DPERR_NOMESSAGES      0x887700BE
#define DPERR_NOCONNECTION    0x88770050
#define DPERR_UNSUPPORTED     0x80004001
#define DPERR_INVALIDPARAMS   0x80070057

#define DPSYS_CREATEPLAYERORGROUP  0x0003
#define DPSYS_DESTROYPLAYERORGROUP 0x0005
#define DPSYS_ADDPLAYERTOGROUP     0x0007
#define DPSYS_DELETEPLAYERFROMGROUP 0x0021
#define DPSYS_SESSIONLOST          0x0031

#define DPRECEIVE_TOPLAYER   0x2
#define DPRECEIVE_FROMPLAYER 0x4
#define DPRECEIVE_PEEK       0x8
#define DPLCONNECTION_JOINSESSION 0x1
#define DPENUMPLAYERS_LOCAL  0x8
#define DPENUMPLAYERS_REMOTE 0x10
#define DPENUMPLAYERS_GROUP  0x20

typedef struct { DWORD dwSize, dwFlags; char* shortName; char* longName; } DPNAME;
typedef struct {
    DWORD dwSize, dwFlags; GUID guidInstance, guidApplication;
    DWORD dwMaxPlayers, dwCurrentPlayers; char* name; char* password;
    DWORD r1, r2, u1, u2, u3, u4;
} DPSESSIONDESC2;
typedef struct {
    DWORD dwSize, dwFlags; DPSESSIONDESC2* lpSessionDesc; DPNAME* lpPlayerName;
    GUID guidSP; void* lpAddress; DWORD dwAddressSize;
} DPLCONNECTION;
typedef struct {
    DWORD dwSize, dwFlags, dwMaxBufferSize, dwMaxQueueSize, dwMaxPlayers,
          dwHundredBaud, dwLatency, dwMaxLocalPlayers, dwHeaderLength, dwTimeout;
} DPCAPS;
typedef struct {
    DWORD dwType, dwPlayerType; DPID dpId; DWORD dwCurrentPlayers;
    void* lpData; DWORD dwDataSize; DPNAME dpnName; DPID dpIdParent; DWORD dwFlags;
} DPMSG_CREATEPLAYERORGROUP;
typedef struct {
    DWORD dwType, dwPlayerType; DPID dpId; void* lpLocalData; DWORD dwLocalDataSize;
    void* lpRemoteData; DWORD dwRemoteDataSize; DPNAME dpnName; DPID dpIdParent; DWORD dwFlags;
} DPMSG_DESTROYPLAYERORGROUP;
typedef struct { DWORD dwType; DPID dpIdGroup, dpIdPlayer; } DPMSG_GROUPMEMBER;

typedef BOOL (WINAPI *enum_players_cb)(DPID, DWORD, const DPNAME*, DWORD, void*);

static int g_log = -1;
#define LOG(...) do { if (g_log < 0) g_log = getenv("XVT_DPLOG") != NULL; if (g_log) printf("[dplay] " __VA_ARGS__); } while (0)

/* ---- the session's state, shared by the game's thread and the network threads ---- */

#define MAXP 64
typedef struct { DPID id; int group; char name[64]; DPID parent; HANDLE event; DPID members[MAXP]; int nmembers; } Player;
typedef struct Msg { struct Msg* next; DPID from, to; DWORD size; uint8_t data[1]; } Msg;

static CRITICAL_SECTION g_lock;
static int g_node;                 /* 1 the host, 2.. joiners; 0 no session */
static DWORD g_next = 1;           /* this node's next DPID */
static Player g_players[MAXP];
static int g_nplayers;
static Msg *g_head, *g_tail;
static DPSESSIONDESC2 g_sd;
static char g_session_name[64];
static SOCKET g_up = INVALID_SOCKET;          /* a joiner's connection to the host */
static SOCKET g_down[16];                     /* the host's connections, by node - 2 */
static DPLCONNECTION g_conn;                  /* the last SetConnectionSettings, deep-copied */
static DPSESSIONDESC2 g_conn_sd;
static DPNAME g_conn_name;
static char g_conn_short[64], g_conn_long[64], g_conn_sname[64], g_conn_addr[64];

static Player* find(DPID id) { for (int i = 0; i < g_nplayers; i++) if (g_players[i].id == id) return &g_players[i]; return NULL; }
static int node_of(DPID id) { return (int)(id >> 16); }

static void queue(DPID from, DPID to, const void* data, DWORD size) {
    Msg* m = (Msg*)malloc(sizeof *m + size);
    m->next = NULL, m->from = from, m->to = to, m->size = size;
    memcpy(m->data, data, size);
    if (g_tail) g_tail->next = m; else g_head = m;
    g_tail = m;
    Player* p = find(to);
    if (p && p->event) SetEvent(p->event);
}

/* ---- the wire: [len][type][from][to] then the payload ---- */

enum { W_HELLO = 1, W_WELCOME, W_ADD, W_DEL, W_JOINGROUP, W_LEAVEGROUP, W_DATA };
typedef struct { DWORD len, type, from, to; } Hdr;
typedef struct { DPID id; DWORD group; DPID parent; char name[64]; } WPlayer;

/* One message, whole, and one sender at a time: the host's reader threads
 * forward to a node while the game sends to it, and two threads' header and
 * payload interleaving on one connection garbled it (three players: the
 * third was dropped). */
static void send_on(SOCKET s, DWORD type, DPID from, DPID to, const void* p, DWORD n) {
    static SRWLOCK one = SRWLOCK_INIT;
    if (s == INVALID_SOCKET) return;
    char* b = (char*)malloc(sizeof(Hdr) + n);
    Hdr h = { sizeof h + n, type, from, to };
    memcpy(b, &h, sizeof h);
    if (n) memcpy(b + sizeof h, p, n);
    AcquireSRWLockExclusive(&one);
    for (int sent = 0, r; sent < (int)h.len; sent += r)
        if ((r = send(s, b + sent, (int)h.len - sent, 0)) <= 0) break;
    ReleaseSRWLockExclusive(&one);
    free(b);
}
/* Out to every other node (the host), or up to the host (a joiner). */
static void broadcast(DWORD type, DPID from, DPID to, const void* p, DWORD n, int except_node) {
    if (g_node == 1) { for (int i = 0; i < 16; i++) if (i + 2 != except_node) send_on(g_down[i], type, from, to, p, n); }
    else send_on(g_up, type, from, to, p, n);
}
static int recv_all(SOCKET s, void* p, int n) {
    for (int got = 0; got < n; ) { int r = recv(s, (char*)p + got, n - got, 0); if (r <= 0) return 0; got += r; }
    return 1;
}

static void sys_create(const Player* p) {
    DPMSG_CREATEPLAYERORGROUP m = { DPSYS_CREATEPLAYERORGROUP, p->group ? 0u : 1u, p->id, (DWORD)g_nplayers };
    m.dpnName.dwSize = sizeof m.dpnName;
    m.dpnName.shortName = (char*)p->name;
    m.dpIdParent = p->parent;
    queue(0, 0, &m, sizeof m);
}
static void add_player(const WPlayer* w, int tell_game) {
    if (find(w->id) || g_nplayers == MAXP) return;
    Player* p = &g_players[g_nplayers++];
    memset(p, 0, sizeof *p);
    p->id = w->id, p->group = (int)w->group, p->parent = w->parent;
    memcpy(p->name, w->name, sizeof p->name - 1);
    if (!p->group) g_sd.dwCurrentPlayers++;
    if (tell_game) sys_create(p);
}
static void del_player(DPID id, int tell_game) {
    Player* p = find(id);
    if (!p) return;
    if (tell_game) {
        DPMSG_DESTROYPLAYERORGROUP m = { DPSYS_DESTROYPLAYERORGROUP, p->group ? 0u : 1u, p->id };
        m.dpnName.dwSize = sizeof m.dpnName, m.dpnName.shortName = p->name;
        queue(0, 0, &m, sizeof m);
    }
    if (!p->group && g_sd.dwCurrentPlayers) g_sd.dwCurrentPlayers--;
    *p = g_players[--g_nplayers];
}
static void group_member(DPID group, DPID player, int add, int tell_game) {
    Player* g = find(group);
    if (!g) return;
    int i;
    for (i = 0; i < g->nmembers && g->members[i] != player; i++) ;
    if (add && i == g->nmembers && g->nmembers < MAXP) g->members[g->nmembers++] = player;
    if (!add && i < g->nmembers) g->members[i] = g->members[--g->nmembers];
    if (tell_game) {
        DPMSG_GROUPMEMBER m = { add ? DPSYS_ADDPLAYERTOGROUP : DPSYS_DELETEPLAYERFROMGROUP, group, player };
        queue(0, 0, &m, sizeof m);
    }
}

/* A message for 'to' (a player, a group, or 0 for everyone) reaching this
 * node: the local players it is for get it. */
static void deliver(DPID from, DPID to, const void* data, DWORD n) {
    Player* g = to ? find(to) : NULL;
    for (int i = 0; i < g_nplayers; i++) {
        Player* p = &g_players[i];
        if (p->group || node_of(p->id) != g_node || p->id == from) continue;
        int mine = !to || p->id == to;
        for (int j = 0; g && g->group && j < g->nmembers && !mine; j++) mine = g->members[j] == p->id;
        if (mine) queue(from, p->id, data, n);
    }
}

static void handle(int from_node, Hdr* h, uint8_t* p) {
    DWORD n = h->len - sizeof *h;
    EnterCriticalSection(&g_lock);
    switch (h->type) {
    case W_ADD: add_player((WPlayer*)p, 1); break;
    case W_DEL: del_player(h->from, 1); break;
    case W_JOINGROUP: group_member(h->to, h->from, 1, 1); break;
    case W_LEAVEGROUP: group_member(h->to, h->from, 0, 1); break;
    case W_DATA: deliver(h->from, h->to, p, n); break;
    }
    LeaveCriticalSection(&g_lock);
    /* The host passes on what it hears to the other nodes. */
    if (g_node == 1 && h->type != W_HELLO) broadcast(h->type, h->from, h->to, p, n, from_node);
}

static DWORD WINAPI reader(LPVOID arg) {
    int node = (int)(intptr_t)arg;
    SOCKET s = node ? g_down[node - 2] : g_up;
    uint8_t* b = (uint8_t*)malloc(65536);
    Hdr h;
    while (recv_all(s, &h, sizeof h) && h.len >= sizeof h && h.len - sizeof h <= 65536 && recv_all(s, b, (int)(h.len - sizeof h)))
        handle(node, &h, b);
    LOG("node %d disconnected\n", node ? node : 1);
    EnterCriticalSection(&g_lock);
    if (node) {   /* the host: that node's players are gone */
        g_down[node - 2] = INVALID_SOCKET;
        for (int i = g_nplayers - 1; i >= 0; i--)
            if (node_of(g_players[i].id) == node) {
                DPID id = g_players[i].id;
                del_player(id, 1);
                LeaveCriticalSection(&g_lock);
                broadcast(W_DEL, id, 0, NULL, 0, node);
                EnterCriticalSection(&g_lock);
            }
    } else {      /* a joiner: the session is over */
        DWORD lost = DPSYS_SESSIONLOST;
        queue(0, 0, &lost, sizeof lost);
    }
    LeaveCriticalSection(&g_lock);
    free(b);
    closesocket(s);
    return 0;
}

static WPlayer wplayer(const Player* p) {
    WPlayer w = { p->id, (DWORD)p->group, p->parent };
    memcpy(w.name, p->name, sizeof w.name);
    return w;
}

/* The host takes joiners: each gets a node number, the session and the table. */
static DWORD WINAPI listener(LPVOID arg) {
    SOCKET ls = (SOCKET)(uintptr_t)arg;
    for (;;) {
        SOCKET s = accept(ls, NULL, NULL);
        if (s == INVALID_SOCKET) return 0;
        Hdr h;
        uint8_t name[64];
        if (!recv_all(s, &h, sizeof h) || h.type != W_HELLO || h.len > sizeof h + sizeof name || !recv_all(s, name, (int)(h.len - sizeof h))) { closesocket(s); continue; }
        EnterCriticalSection(&g_lock);
        int i;
        for (i = 0; i < 16 && g_down[i] != INVALID_SOCKET; i++) ;
        if (i == 16 || g_sd.dwCurrentPlayers >= (g_sd.dwMaxPlayers ? g_sd.dwMaxPlayers : MAXP)) { LeaveCriticalSection(&g_lock); closesocket(s); continue; }
        int node = i + 2;
        static uint8_t w[sizeof(DPSESSIONDESC2) + 64 + MAXP * sizeof(WPlayer) + MAXP * MAXP * 8];
        DWORD n = 0;
        memcpy(w, &g_sd, sizeof g_sd), n += sizeof g_sd;
        memcpy(w + n, g_session_name, 64), n += 64;
        for (int j = 0; j < g_nplayers; j++) { WPlayer wp = wplayer(&g_players[j]); memcpy(w + n, &wp, sizeof wp), n += sizeof wp; }
        int nplayers = g_nplayers;
        DWORD gm = 0;   /* then each group's members: (group, player) pairs */
        for (int j = 0; j < g_nplayers; j++)
            for (int k = 0; k < g_players[j].nmembers; k++) { DPID pr[2] = { g_players[j].id, g_players[j].members[k] }; memcpy(w + n + 4 + gm * 8, pr, 8); gm++; }
        memcpy(w + n, &gm, 4), n += 4 + gm * 8;
        g_down[i] = s;
        LeaveCriticalSection(&g_lock);
        send_on(s, W_WELCOME, (DWORD)node, (DWORD)nplayers, w, n);
        LOG("node %d joined (%.63s)\n", node, (char*)name);
        CloseHandle(CreateThread(NULL, 0, reader, (LPVOID)(intptr_t)node, 0, NULL));
    }
}

static int net_up(void) {
    static int done;
    if (!done) { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); InitializeCriticalSection(&g_lock); done = 1; }
    return 1;
}

static HRESULT host_session(void) {
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a = { AF_INET, htons(DP_PORT) };
    BOOL yes = TRUE;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof yes);
    if (bind(ls, (struct sockaddr*)&a, sizeof a) || listen(ls, 8)) { LOG("cannot listen on %d\n", DP_PORT); closesocket(ls); return DPERR_NOCONNECTION; }
    for (int i = 0; i < 16; i++) g_down[i] = INVALID_SOCKET;
    g_node = 1;
    CloseHandle(CreateThread(NULL, 0, listener, (LPVOID)(uintptr_t)ls, 0, NULL));
    LOG("hosting \"%s\" on port %d\n", g_session_name, DP_PORT);
    return DP_OK;
}

static HRESULT join_session(const char* ip) {
    struct addrinfo hints = { 0 }, *ai = NULL;
    hints.ai_family = AF_INET, hints.ai_socktype = SOCK_STREAM;
    char port[8];
    _snprintf(port, sizeof port, "%d", DP_PORT);
    if (getaddrinfo(ip, port, &hints, &ai) || !ai) { LOG("cannot resolve \"%s\"\n", ip); return DPERR_NOSESSIONS; }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int r = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
    freeaddrinfo(ai);
    if (r) { LOG("no session at %s\n", ip); closesocket(s); return DPERR_NOSESSIONS; }
    send_on(s, W_HELLO, 0, 0, g_conn_short, sizeof g_conn_short);
    Hdr h;
    static uint8_t w[sizeof(DPSESSIONDESC2) + 64 + MAXP * sizeof(WPlayer) + MAXP * MAXP * 8 + 4];
    if (!recv_all(s, &h, sizeof h) || h.type != W_WELCOME || h.len - sizeof h > sizeof w || !recv_all(s, w, (int)(h.len - sizeof h))) {
        LOG("the host at %s turned us away\n", ip); closesocket(s); return DPERR_NOSESSIONS;
    }
    EnterCriticalSection(&g_lock);
    g_node = (int)h.from;
    memcpy(&g_sd, w, sizeof g_sd);
    memcpy(g_session_name, w + sizeof g_sd, 64);
    g_sd.name = g_session_name, g_sd.password = NULL, g_sd.dwCurrentPlayers = 0;
    uint8_t* q = w + sizeof g_sd + 64;
    for (DWORD i = 0; i < h.to; i++, q += sizeof(WPlayer)) add_player((WPlayer*)q, 0);
    DWORD gm;
    memcpy(&gm, q, 4), q += 4;
    for (DWORD i = 0; i < gm; i++, q += 8) group_member(((DPID*)q)[0], ((DPID*)q)[1], 1, 0);
    g_up = s;
    LeaveCriticalSection(&g_lock);
    CloseHandle(CreateThread(NULL, 0, reader, (LPVOID)0, 0, NULL));
    LOG("joined \"%s\" at %s as node %d, %lu players\n", g_session_name, ip, g_node, g_sd.dwCurrentPlayers);
    return DP_OK;
}

/* ---- COM plumbing: one object per interface family, reference counts kept ---- */

typedef struct { void** vt; LONG refs; } Obj;

static HRESULT WINAPI o_qi(Obj* o, const GUID* iid, void** out) {
    LOG("QueryInterface {%08lX-%04X-%04X}\n", iid->Data1, iid->Data2, iid->Data3);
    InterlockedIncrement(&o->refs);
    *out = o;
    return DP_OK;
}
static ULONG WINAPI o_addref(Obj* o) { return (ULONG)InterlockedIncrement(&o->refs); }
static ULONG WINAPI o_release(Obj* o) { return (ULONG)InterlockedDecrement(&o->refs); }   /* objects live for the run */

/* Each unprovided method takes its own number of arguments: one stub per count. */
#define STUB(k) \
    static HRESULT __declspec(naked) unsup##k(void) { __asm push k __asm call unsup_log __asm mov eax, DPERR_UNSUPPORTED __asm ret ((k) * 4 + 4) }
static void __stdcall unsup_log(int nargs) { printf("[dplay] a method with %d arguments that is not provided\n", nargs); }
STUB(0) STUB(1) STUB(2) STUB(3) STUB(4) STUB(5) STUB(6) STUB(9)

/* ---- the lobby ---- */

static HRESULT WINAPI l_connect(Obj* o, DWORD flags, void** out, void* outer);
static HRESULT WINAPI l_create_address(Obj* o, const GUID* sp, const GUID* type, const void* data, DWORD size, void* addr, DWORD* addr_size) {
    DWORD need = 4 + size;
    LOG("CreateAddress \"%.*s\" (%lu bytes, buffer %lu)\n", (int)size, (const char*)data, size, addr_size ? *addr_size : 0);
    if (!addr_size) return DPERR_INVALIDPARAMS;
    if (!addr || *addr_size < need) { *addr_size = need; return DPERR_BUFFERTOOSMALL; }
    memcpy(addr, "XVTA", 4);
    memcpy((char*)addr + 4, data, size);
    *addr_size = need;
    return DP_OK;
}
static void copy_str(char* to, size_t n, const char* from) { to[0] = 0; if (from) { strncpy(to, from, n - 1); to[n - 1] = 0; } }
static HRESULT WINAPI l_set_connection(Obj* o, DWORD flags, DWORD app, const DPLCONNECTION* c) {
    if (!c) return DPERR_INVALIDPARAMS;
    g_conn = *c;
    if (c->lpSessionDesc) { g_conn_sd = *c->lpSessionDesc; copy_str(g_conn_sname, sizeof g_conn_sname, c->lpSessionDesc->name); g_conn_sd.name = g_conn_sname; g_conn_sd.password = NULL; g_conn.lpSessionDesc = &g_conn_sd; }
    if (c->lpPlayerName) {
        g_conn_name = *c->lpPlayerName;
        copy_str(g_conn_short, sizeof g_conn_short, c->lpPlayerName->shortName);
        copy_str(g_conn_long, sizeof g_conn_long, c->lpPlayerName->longName);
        g_conn_name.shortName = g_conn_short, g_conn_name.longName = g_conn_long;
        g_conn.lpPlayerName = &g_conn_name;
    }
    memset(g_conn_addr, 0, sizeof g_conn_addr);
    if (c->lpAddress && c->dwAddressSize > 4 && !memcmp(c->lpAddress, "XVTA", 4))
        memcpy(g_conn_addr, (char*)c->lpAddress + 4, min(c->dwAddressSize - 4, sizeof g_conn_addr - 1));
    g_conn.lpAddress = g_conn_addr, g_conn.dwAddressSize = (DWORD)strlen(g_conn_addr) + 1;
    LOG("SetConnectionSettings flags %08lX: %s \"%s\" max %lu, player \"%s\", address \"%s\"\n", c->dwFlags,
        c->dwFlags & DPLCONNECTION_JOINSESSION ? "join" : "create", g_conn_sname, g_conn_sd.dwMaxPlayers, g_conn_short, g_conn_addr);
    return DP_OK;
}
/* The settings back, as one block: the struct, then what it points to. */
static HRESULT WINAPI l_get_connection(Obj* o, DWORD app, void* data, DWORD* size) {
    DWORD need = sizeof(DPLCONNECTION) + sizeof(DPSESSIONDESC2) + sizeof(DPNAME) + 64 * 4;
    if (!size) return DPERR_INVALIDPARAMS;
    if (!data || *size < need) { *size = need; return DPERR_BUFFERTOOSMALL; }
    uint8_t* b = (uint8_t*)data;
    DPLCONNECTION* c = (DPLCONNECTION*)b;
    DPSESSIONDESC2* sd = (DPSESSIONDESC2*)(b + sizeof *c);
    DPNAME* nm = (DPNAME*)(sd + 1);
    char* s = (char*)(nm + 1);
    *c = g_conn, *sd = g_conn_sd, *nm = g_conn_name;
    memcpy(s, g_conn_sname, 64), memcpy(s + 64, g_conn_short, 64), memcpy(s + 128, g_conn_long, 64), memcpy(s + 192, g_conn_addr, 64);
    sd->name = s, nm->shortName = s + 64, nm->longName = s + 128;
    c->lpSessionDesc = sd, c->lpPlayerName = nm, c->lpAddress = s + 192;
    *size = need;
    LOG("GetConnectionSettings\n");
    return DP_OK;
}

static void* g_lobby_vt[] = {
    o_qi, o_addref, o_release,
    l_connect,          /* 3 Connect */
    l_create_address,   /* 4 CreateAddress */
    unsup4,             /* 5 EnumAddress(cb, addr, size, ctx) */
    unsup4,             /* 6 EnumAddressTypes(cb, sp, ctx, flags) */
    unsup3,             /* 7 EnumLocalApplications(cb, ctx, flags) */
    l_get_connection,   /* 8 GetConnectionSettings */
    unsup5,             /* 9 ReceiveLobbyMessage */
    unsup4,             /* 10 RunApplication */
    unsup4,             /* 11 SendLobbyMessage */
    l_set_connection,   /* 12 SetConnectionSettings */
    unsup3,             /* 13 SetLobbyMessageEvent */
    unsup4,             /* 14 CreateCompoundAddress (IDirectPlayLobby2) */
    unsup4,             /* 15 ConnectEx (3) */
    unsup2,             /* 16 RegisterApplication */
    unsup2,             /* 17 UnregisterApplication */
    unsup2,             /* 18 WaitForConnectionSettings */
};
static Obj g_lobby = { g_lobby_vt, 1 };

/* ---- the session: IDirectPlay2A..4A ---- */

static HRESULT WINAPI d_close(Obj* o) {
    LOG("Close\n");
    EnterCriticalSection(&g_lock);
    for (int i = g_nplayers - 1; i >= 0; i--)
        if (node_of(g_players[i].id) == g_node) { DPID id = g_players[i].id; del_player(id, 0); broadcast(W_DEL, id, 0, NULL, 0, 0); }
    LeaveCriticalSection(&g_lock);
    if (g_up != INVALID_SOCKET) { closesocket(g_up); g_up = INVALID_SOCKET; }
    return DP_OK;
}
static HRESULT create(DPID* id, const DPNAME* name, HANDLE ev, DPID parent, int group) {
    if (!id) return DPERR_INVALIDPARAMS;
    EnterCriticalSection(&g_lock);
    WPlayer w = { (DPID)(g_node << 16 | g_next++), (DWORD)group, parent };
    if (name && name->shortName) copy_str(w.name, sizeof w.name, name->shortName);
    add_player(&w, 0);
    Player* p = find(w.id);
    if (p) p->event = ev;
    LeaveCriticalSection(&g_lock);
    broadcast(W_ADD, w.id, 0, &w, sizeof w, 0);
    *id = w.id;
    LOG("Create%s \"%s\" -> %08lX\n", group ? "Group" : "Player", w.name, w.id);
    return DP_OK;
}
static HRESULT WINAPI d_create_group(Obj* o, DPID* id, const DPNAME* name, void* data, DWORD size, DWORD flags) { return create(id, name, NULL, 0, 1); }
static HRESULT WINAPI d_create_player(Obj* o, DPID* id, const DPNAME* name, HANDLE ev, void* data, DWORD size, DWORD flags) { return create(id, name, ev, 0, 0); }
static HRESULT WINAPI d_add_to_group(Obj* o, DPID group, DPID player) {
    LOG("AddPlayerToGroup %08lX %08lX\n", group, player);
    EnterCriticalSection(&g_lock); group_member(group, player, 1, 0); LeaveCriticalSection(&g_lock);
    broadcast(W_JOINGROUP, player, group, NULL, 0, 0);
    return DP_OK;
}
static HRESULT WINAPI d_delete_from_group(Obj* o, DPID group, DPID player) {
    LOG("DeletePlayerFromGroup %08lX %08lX\n", group, player);
    EnterCriticalSection(&g_lock); group_member(group, player, 0, 0); LeaveCriticalSection(&g_lock);
    broadcast(W_LEAVEGROUP, player, group, NULL, 0, 0);
    return DP_OK;
}
static HRESULT WINAPI d_destroy(Obj* o, DPID id) {
    LOG("Destroy %08lX\n", id);
    EnterCriticalSection(&g_lock); del_player(id, 0); LeaveCriticalSection(&g_lock);
    broadcast(W_DEL, id, 0, NULL, 0, 0);
    return DP_OK;
}
/* The table, through the game's callback: copied out first, as the callback
 * may call back in. */
static HRESULT enum_players(DPID group, DWORD flags, enum_players_cb cb, void* ctx, int groups) {
    Player list[MAXP];
    int n = 0;
    EnterCriticalSection(&g_lock);
    Player* g = group ? find(group) : NULL;
    for (int i = 0; i < g_nplayers; i++) {
        Player* p = &g_players[i];
        if (p->group != groups) continue;
        if (g) { int in = 0; for (int j = 0; j < g->nmembers; j++) in |= g->members[j] == p->id; if (!in) continue; }
        int local = node_of(p->id) == g_node;
        if ((flags & DPENUMPLAYERS_LOCAL && !local) || (flags & DPENUMPLAYERS_REMOTE && local)) continue;
        list[n++] = *p;
    }
    LeaveCriticalSection(&g_lock);
    LOG("Enum%s %08lX flags %08lX: %d\n", groups ? "Groups" : "Players", group, flags, n);
    for (int i = 0; i < n; i++) {
        DPNAME nm = { sizeof nm, 0, list[i].name, list[i].name };
        DWORD f = node_of(list[i].id) == g_node ? DPENUMPLAYERS_LOCAL : DPENUMPLAYERS_REMOTE;
        if (!cb(list[i].id, groups ? 0 : 1, &nm, f | (groups ? DPENUMPLAYERS_GROUP : 0), ctx)) break;
    }
    return DP_OK;
}
static HRESULT WINAPI d_enum_group_players(Obj* o, DPID g, GUID* inst, enum_players_cb cb, void* ctx, DWORD flags) { return enum_players(g, flags, cb, ctx, 0); }
static HRESULT WINAPI d_enum_groups(Obj* o, GUID* inst, enum_players_cb cb, void* ctx, DWORD flags) { return enum_players(0, flags, cb, ctx, 1); }
static HRESULT WINAPI d_enum_players(Obj* o, GUID* inst, enum_players_cb cb, void* ctx, DWORD flags) { return enum_players(0, flags, cb, ctx, 0); }
static HRESULT WINAPI d_enum_sessions(Obj* o, DPSESSIONDESC2* sd, DWORD timeout, void* cb, void* ctx, DWORD flags) { printf("[dplay] EnumSessions not provided\n"); return DPERR_UNSUPPORTED; }
static HRESULT WINAPI d_get_caps(Obj* o, DPCAPS* c, DWORD flags) {
    if (!c) return DPERR_INVALIDPARAMS;
    DWORD sz = c->dwSize;
    memset(c, 0, sz < sizeof *c ? sz : sizeof *c);
    c->dwSize = sz, c->dwFlags = g_node == 1 ? 0x2 /* DPCAPS_ISHOST */ : 0, c->dwMaxBufferSize = 65000, c->dwMaxPlayers = MAXP;
    c->dwHundredBaud = 1000000, c->dwLatency = 20, c->dwMaxLocalPlayers = MAXP, c->dwTimeout = 5000;
    LOG("GetCaps\n");
    return DP_OK;
}
static HRESULT get_name(DPID id, void* data, DWORD* size) {
    EnterCriticalSection(&g_lock);
    Player* p = find(id);
    char name[64];
    if (p) memcpy(name, p->name, sizeof name);
    LeaveCriticalSection(&g_lock);
    if (!p) return DPERR_INVALIDPLAYER;
    DWORD need = sizeof(DPNAME) + 64;
    if (!size) return DPERR_INVALIDPARAMS;
    if (!data || *size < need) { *size = need; return DPERR_BUFFERTOOSMALL; }
    DPNAME* nm = (DPNAME*)data;
    char* s = (char*)(nm + 1);
    memcpy(s, name, 64);
    nm->dwSize = sizeof *nm, nm->dwFlags = 0, nm->shortName = s, nm->longName = s;
    *size = need;
    return DP_OK;
}
static HRESULT WINAPI d_get_group_name(Obj* o, DPID id, void* data, DWORD* size) { return get_name(id, data, size); }
static HRESULT WINAPI d_get_player_name(Obj* o, DPID id, void* data, DWORD* size) { return get_name(id, data, size); }
static HRESULT WINAPI d_get_message_count(Obj* o, DPID id, DWORD* n) {
    DWORD c = 0;
    EnterCriticalSection(&g_lock);
    for (Msg* m = g_head; m; m = m->next) c += !id || m->to == id || m->to == 0;
    LeaveCriticalSection(&g_lock);
    if (n) *n = c;
    return DP_OK;
}
static HRESULT WINAPI d_get_session_desc(Obj* o, void* data, DWORD* size) {
    DWORD need = sizeof(DPSESSIONDESC2) + 64;
    if (!size) return DPERR_INVALIDPARAMS;
    if (!data || *size < need) { *size = need; return DPERR_BUFFERTOOSMALL; }
    DPSESSIONDESC2* sd = (DPSESSIONDESC2*)data;
    EnterCriticalSection(&g_lock);
    *sd = g_sd;
    memcpy(sd + 1, g_session_name, 64);
    LeaveCriticalSection(&g_lock);
    sd->name = (char*)(sd + 1), sd->password = NULL;
    *size = need;
    LOG("GetSessionDesc\n");
    return DP_OK;
}
static HRESULT WINAPI d_set_session_desc(Obj* o, const DPSESSIONDESC2* sd, DWORD flags) {
    if (!sd) return DPERR_INVALIDPARAMS;
    EnterCriticalSection(&g_lock);
    DWORD cur = g_sd.dwCurrentPlayers;
    g_sd = *sd, g_sd.dwCurrentPlayers = cur;
    copy_str(g_session_name, sizeof g_session_name, sd->name);
    g_sd.name = g_session_name, g_sd.password = NULL;
    LeaveCriticalSection(&g_lock);
    LOG("SetSessionDesc\n");
    return DP_OK;
}
static HRESULT WINAPI d_initialize(Obj* o, GUID* g) { return 0x88770078; /* DPERR_ALREADYINITIALIZED */ }
static HRESULT WINAPI d_open(Obj* o, DPSESSIONDESC2* sd, DWORD flags) { printf("[dplay] Open not provided\n"); return DPERR_UNSUPPORTED; }
static HRESULT WINAPI d_receive(Obj* o, DPID* from, DPID* to, DWORD flags, void* data, DWORD* size) {
    if (!size) return DPERR_INVALIDPARAMS;
    EnterCriticalSection(&g_lock);
    Msg *m, *prev = NULL;
    for (m = g_head; m; prev = m, m = m->next) {
        if (flags & DPRECEIVE_TOPLAYER && to && m->to != *to) continue;
        if (flags & DPRECEIVE_FROMPLAYER && from && m->from != *from) continue;
        break;
    }
    HRESULT hr = DPERR_NOMESSAGES;
    if (m) {
        if (!data || *size < m->size) { *size = m->size; hr = DPERR_BUFFERTOOSMALL; }
        else {
            memcpy(data, m->data, m->size);
            *size = m->size;
            if (from) *from = m->from;
            if (to) *to = m->to;
            if (!(flags & DPRECEIVE_PEEK)) {
                if (prev) prev->next = m->next; else g_head = m->next;
                if (g_tail == m) g_tail = prev;
                if (g_log > 0 && m->from == 0) printf("[dplay] system message %08lX\n", *(DWORD*)m->data);
                free(m);
            }
            hr = DP_OK;
        }
    }
    LeaveCriticalSection(&g_lock);
    return hr;
}
static HRESULT WINAPI d_send(Obj* o, DPID from, DPID to, DWORD flags, const void* data, DWORD size) {
    if (!data && size) return DPERR_INVALIDPARAMS;
    EnterCriticalSection(&g_lock);
    deliver(from, to, data, size);   /* the local players it is for */
    LeaveCriticalSection(&g_lock);
    /* Every other node that has one of the recipients (or all of them: the
     * host forwards, and each node keeps only what is for its own players). */
    if (!to || node_of(to) != g_node || (find(to) && find(to)->group))
        broadcast(W_DATA, from, to, data, size, 0);
    return DP_OK;
}
static HRESULT WINAPI d_ok3(Obj* o, DWORD a, DWORD b, DWORD c) { return DP_OK; }
static HRESULT WINAPI d_ok4(Obj* o, DWORD a, DWORD b, DWORD c, DWORD d) { return DP_OK; }
static HRESULT WINAPI d_get_player_caps(Obj* o, DPID id, DPCAPS* c, DWORD flags) { return d_get_caps(o, c, flags); }
static HRESULT WINAPI d_get_data(Obj* o, DPID id, void* data, DWORD* size, DWORD flags) { if (size) *size = 0; return DP_OK; }
static HRESULT WINAPI d_set_name(Obj* o, DPID id, const DPNAME* name, DWORD flags) {
    EnterCriticalSection(&g_lock);
    Player* p = find(id);
    if (p && name && name->shortName) copy_str(p->name, sizeof p->name, name->shortName);
    LeaveCriticalSection(&g_lock);
    return p ? DP_OK : DPERR_INVALIDPLAYER;
}

static void* g_dp_vt[] = {
    o_qi, o_addref, o_release,
    d_add_to_group,        /* 3 */
    d_close,               /* 4 */
    d_create_group,        /* 5 */
    d_create_player,       /* 6 */
    d_delete_from_group,   /* 7 */
    d_destroy,             /* 8 DestroyGroup */
    d_destroy,             /* 9 DestroyPlayer */
    d_enum_group_players,  /* 10 */
    d_enum_groups,         /* 11 */
    d_enum_players,        /* 12 */
    d_enum_sessions,       /* 13 */
    d_get_caps,            /* 14 */
    d_get_data,            /* 15 GetGroupData */
    d_get_group_name,      /* 16 */
    d_get_message_count,   /* 17 */
    unsup3,                /* 18 GetPlayerAddress */
    d_get_player_caps,     /* 19 */
    d_get_data,            /* 20 GetPlayerData */
    d_get_player_name,     /* 21 */
    d_get_session_desc,    /* 22 */
    d_initialize,          /* 23 */
    d_open,                /* 24 */
    d_receive,             /* 25 */
    d_send,                /* 26 */
    d_ok4,                 /* 27 SetGroupData */
    d_set_name,            /* 28 SetGroupName */
    d_ok4,                 /* 29 SetPlayerData */
    d_set_name,            /* 30 SetPlayerName */
    d_set_session_desc,    /* 31 */
    unsup2, unsup6, unsup2, unsup4, unsup5, unsup4, unsup2, unsup4,   /* 32-39 (IDirectPlay3) */
    unsup4, unsup3, unsup2, unsup2, unsup2, unsup4, unsup2,           /* 40-46 */
    unsup2, unsup2, unsup9, unsup5, unsup2, unsup3,                   /* 47-52 (IDirectPlay4) */
};
static Obj g_dp = { g_dp_vt, 1 };

static HRESULT WINAPI l_connect(Obj* o, DWORD flags, void** out, void* outer) {
    if (!out) return DPERR_INVALIDPARAMS;
    net_up();
    if (g_node) { *out = &g_dp; o_addref(&g_dp); return DP_OK; }
    memset(&g_sd, 0, sizeof g_sd);
    copy_str(g_session_name, sizeof g_session_name, g_conn_sname);
    g_sd = g_conn_sd, g_sd.name = g_session_name, g_sd.dwCurrentPlayers = 0;
    HRESULT hr = g_conn.dwFlags & DPLCONNECTION_JOINSESSION ? join_session(g_conn_addr) : host_session();
    LOG("Connect -> %08lX\n", hr);
    if (hr) return hr;
    *out = &g_dp;
    o_addref(&g_dp);
    return DP_OK;
}

/* DirectPlayCreate: XvT only asks, to see that DirectPlay is there. */
static Obj g_dp1 = { g_dp_vt, 1 };
HRESULT dplay_create(void** out) { if (!out) return DPERR_INVALIDPARAMS; *out = &g_dp1; LOG("DirectPlayCreate\n"); return DP_OK; }
HRESULT dplay_lobby_create(void** out) { if (!out) return DPERR_INVALIDPARAMS; *out = &g_lobby; LOG("DirectPlayLobbyCreateA\n"); return DP_OK; }
