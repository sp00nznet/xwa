/*
 * hookbake <game dir> <exe in> <exe out> [tools/hook_codewrites.txt]
 *
 * Applies the byte patches of every XWA hook DLL (hook_*.dll in the game dir,
 * the XWA Upgrade's "hooks") to an exe, so the patched code can be lifted.
 * The hooks' own loader (dinput.dll) writes these patches into memory at run
 * time, which a recompiled game never executes. Each hook exports
 * GetHookPatch(i) -> { name, count, items[] }, an item being a file offset and
 * "from"/"to" hex strings. A patch whose bytes match neither "from" nor "to"
 * is reported and skipped, as the loader would refuse it.
 *
 * The exe is mapped at 0x400000 first: some hooks read the game's memory
 * while they load. Build 32-bit with a base clear of the image:
 *   cl /nologo /O1 hookbake.c /link /BASE:0x60000000 /DYNAMICBASE:NO /STACK:0x40000
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

typedef struct { int Offset; const char* From; const char* To; } item_t;
typedef struct { const char* Name; int Count; const item_t* Items; } patch_t;

static unsigned char* g_exe;
static const char* g_sites = "";   /* tools/hook_codewrites.txt, optional */
static FILE* g_ptrs;                /* <exe out>.ptrsites */
static long g_size;

/* A hook's patch offset is "address - 0x400C00" (its loader writes memory
 * there), which equals the file offset only in .text. Find the file bytes
 * behind that address; NULL if they are not in the file (n bytes wanted). */
static unsigned char* at(int off, size_t n) {
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(g_exe + ((IMAGE_DOS_HEADER*)g_exe)->e_lfanew);
    uint32_t rva = (uint32_t)off + 0x400C00 - nt->OptionalHeader.ImageBase;
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
        if (rva >= s->VirtualAddress && rva + n <= s->VirtualAddress + s->SizeOfRawData)
            return g_exe + s->PointerToRawData + (rva - s->VirtualAddress);
    return NULL;
}

static int hexeq(const unsigned char* p, const char* hex) {
    for (; hex[0] && hex[1]; hex += 2, p++) {
        char b[3] = { hex[0], hex[1], 0 };
        if (*p != (unsigned char)strtoul(b, NULL, 16)) return 0;
    }
    return 1;
}

static void hexput(unsigned char* p, const char* hex) {
    for (; hex[0] && hex[1]; hex += 2, p++) {
        char b[3] = { hex[0], hex[1], 0 };
        *p = (unsigned char)strtoul(b, NULL, 16);
    }
}

/* Map the image's sections at their addresses so a hook's load-time reads land. */
static void map_image(void) {
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(g_exe + ((IMAGE_DOS_HEADER*)g_exe)->e_lfanew);
    /* The launching copy reserved the range in this process before its loader ran (main). */
    unsigned char* base = VirtualAlloc((void*)(uintptr_t)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT, PAGE_READWRITE);
    if (!base) {
        printf("warning: could not map the image at %08lX; in the way:\n", nt->OptionalHeader.ImageBase);
        MEMORY_BASIC_INFORMATION mi;
        for (uintptr_t a = nt->OptionalHeader.ImageBase; a < nt->OptionalHeader.ImageBase + nt->OptionalHeader.SizeOfImage
             && VirtualQuery((void*)a, &mi, sizeof mi); a += mi.RegionSize)
            if (mi.State != MEM_FREE) printf("  %08lX +%08lX type %lX\n", (unsigned long)a, (unsigned long)mi.RegionSize, mi.Type);
        return;
    }
    memcpy(base, g_exe, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++)
        memcpy(base + s->VirtualAddress, g_exe + s->PointerToRawData, min(s->SizeOfRawData, s->Misc.VirtualSize));
}

int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) { printf("usage: hookbake <game dir> <exe in> <exe out> [live sites]\n"); return 2; }
    char sites_full[MAX_PATH] = "";
    if (argc == 5) GetFullPathNameA(argv[4], MAX_PATH, sites_full, NULL), g_sites = sites_full;
    /* Early process setup fills 0x400000 before main, so start again suspended
     * with the image's range reserved (0x400000 + 8 MB covers XWA's 0x712000). */
    if (!getenv("HOOKBAKE_CHILD")) {
        STARTUPINFOA si = { sizeof si };
        PROCESS_INFORMATION pi;
        DWORD code = 1;
        SetEnvironmentVariableA("HOOKBAKE_CHILD", "1");
        if (!CreateProcessA(NULL, GetCommandLineA(), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return 1;
        if (!VirtualAllocEx(pi.hProcess, (void*)0x400000, 0x800000, MEM_RESERVE, PAGE_READWRITE))
            printf("warning: could not reserve 0x400000 in the child (%lu)\n", GetLastError());
        ResumeThread(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
        return (int)code;
    }
    FILE* f = fopen(argv[2], "rb");
    if (!f) { printf("cannot read %s\n", argv[2]); return 1; }
    fseek(f, 0, SEEK_END); g_size = ftell(f); fseek(f, 0, SEEK_SET);
    g_exe = malloc(g_size); fread(g_exe, 1, g_size, f); fclose(f);
    char out[MAX_PATH]; GetFullPathNameA(argv[3], MAX_PATH, out, NULL);
    map_image();

    /* <exe out>.ptrsites: the dwords of the patches that hold this process's pointers */
    char ptrs[MAX_PATH + 16];
    snprintf(ptrs, sizeof ptrs, "%s.ptrsites", out);
    g_ptrs = fopen(ptrs, "w");
    if (g_ptrs) fprintf(g_ptrs, "# Patch dwords holding hook DLL addresses: read live (tools/hookbake.c)\n");
    int nptr = 0;

    SetCurrentDirectoryA(argv[1]);
    SetDllDirectoryA(".");
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("hook_*.dll", &fd);
    int applied = 0, bad = 0;
    for (BOOL more = h != INVALID_HANDLE_VALUE; more; more = FindNextFileA(h, &fd)) {
        HMODULE m = LoadLibraryA(fd.cFileName);
        if (!m) { printf("%-28s does not load (%lu)\n", fd.cFileName, GetLastError()); continue; }
        const patch_t* (*get)(int) = (const patch_t* (*)(int))GetProcAddress(m, "GetHookPatch");
        int n = 0;
        for (int i = 0; get && get(i); i++) {
            const patch_t* p = get(i);
            int ok = 1;
            for (int k = 0; k < p->Count && ok; k++) {
                const item_t* it = &p->Items[k];
                if (strlen(it->From) != strlen(it->To) || !at(it->Offset, strlen(it->To) / 2))
                    ok = 0;
                else ok = hexeq(at(it->Offset, 0), it->From) || hexeq(at(it->Offset, 0), it->To);
            }
            if (!ok) {
                printf("%-28s skipped \"%s\": the bytes match neither side\n", fd.cFileName, p->Name);
                for (int k = 0; k < p->Count; k++) {
                    const item_t* it = &p->Items[k];
                    if (!at(it->Offset, strlen(it->From) / 2) || hexeq(at(it->Offset, 0), it->From) || hexeq(at(it->Offset, 0), it->To)) continue;
                    printf("    at %06X want %s, have ", it->Offset, it->From);
                    for (size_t j = 0; j < strlen(it->From) / 2; j++) printf("%02X", at(it->Offset, 0)[j]);
                    printf("\n");
                }
                bad++;
                continue;
            }
            for (int k = 0; k < p->Count; k++) {
                const item_t* it = &p->Items[k];
                hexput(at(it->Offset, 0), it->To);
                /* A dword that looks like a pointer past the image is the address
                 * of something in a hook DLL or its heap, made in this process:
                 * the game's differs. The lifter reads it live (host.c applies
                 * the same patches in the game). Every alignment is listed; the
                 * lifter only uses the ones that are an instruction's operand. */
                int len = (int)strlen(it->To) / 2;
                for (int j = 0; j + 4 <= len; j++) {
                    uint32_t v;
                    memcpy(&v, at(it->Offset, 0) + j, 4);
                    if (v >= 0xB11000 && v < 0x80000000u && g_ptrs) fprintf(g_ptrs, "0x%06X\n", it->Offset + 0x400C00 + j), nptr++;
                }
            }
            n++;
        }
        printf("%-28s %d patches\n", fd.cFileName, n);
        applied += n;
    }
    /* What the hooks wrote into the code while the game ran (host.c code_watch,
     * hook_codewrites.log): a jump made unconditional, an instruction removed.
     * Bytes inside a dword the lifter reads live (tools/hook_codewrites.txt)
     * are left alone: those hold heap and DLL addresses that change per run. */
    int baked = 0;
    FILE* log = fopen("hook_codewrites.log", "r");
    char line[512];
    static unsigned char live[0x1A8000];
    FILE* sites = fopen(g_sites, "r");
    while (sites && fgets(line, sizeof line, sites))
        if (line[0] == '0') for (unsigned a = strtoul(line, NULL, 16), k = 0; k < 4; k++)
            if (a + k >= 0x401000 && a + k < 0x5A9000) live[a + k - 0x401000] = 1;
    if (sites) fclose(sites);
    while (log && fgets(line, sizeof line, log)) {
        char* sp = strchr(line, ' ');
        if (!sp) continue;
        unsigned a = strtoul(line, NULL, 16);
        for (char* h = sp + 1; isxdigit((unsigned char)h[0]) && isxdigit((unsigned char)h[1]); h += 2, a++) {
            char b[3] = { h[0], h[1], 0 };
            unsigned char* p = a >= 0x401000 && a < 0x5A9000 && !live[a - 0x401000] ? at((int)(a - 0x400C00), 1) : NULL;
            if (p) *p = (unsigned char)strtoul(b, NULL, 16), baked++;
        }
    }
    if (log) { fclose(log); printf("%d recorded code bytes baked\n", baked); }
    if (g_ptrs) { fclose(g_ptrs); printf("%d pointer dwords -> %s\n", nptr, ptrs); }

    f = fopen(out, "wb");
    if (!f) { printf("cannot write %s\n", out); return 1; }
    fwrite(g_exe, 1, g_size, f); fclose(f);
    printf("%d patches applied, %d skipped -> %s\n", applied, bad, out);
    return bad != 0;
}
