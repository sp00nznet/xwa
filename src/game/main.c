/*
 * X-Wing Alliance Static Recompilation - Entry Point
 *
 * Sets up the memory layout, initializes the register model,
 * installs the VEH crash handler, and launches the recompiled game.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <dbghelp.h>
#include "recomp/recomp_types.h"

/* ============================================================
 * Global Register Definitions
 * ============================================================ */

uint32_t g_eax = 0, g_ecx = 0, g_edx = 0, g_esp = 0;
uint32_t g_ebx = 0, g_esi = 0, g_edi = 0;
uint16_t g_seg_cs = 0, g_seg_ds = 0, g_seg_es = 0;
uint16_t g_seg_fs = 0, g_seg_gs = 0, g_seg_ss = 0;

/* Memory base offset (0 for fixed-base mapping) */
ptrdiff_t g_mem_base = 0;

/* Simulated FS segment (Thread Environment Block) */
uint32_t g_fs_seg[256] = {0};

/* ICALL trace */
uint32_t g_icall_trace[ICALL_TRACE_SIZE] = {0};
uint32_t g_icall_trace_idx = 0;
uint32_t g_icall_count = 0;

/* Call depth tracking */
uint32_t g_call_depth = 0;
uint32_t g_call_depth_max = 0;

/* ============================================================
 * Memory Layout Constants (from PE analysis)
 *
 * .text:  0x00401000 - 0x005A8B20  (code, not mapped - we ARE the code)
 * .rdata: 0x005A9000 - 0x005ADA24  (read-only data)
 * .data:  0x005AE000 - 0x00B0F974  (read/write data)
 *
 * We map ONE contiguous region from stack base through data end.
 * This ensures g_mem_base works for both stack and data accesses.
 * ============================================================ */

#define XWA_IMAGE_BASE    0x00400000
#define XWA_DATA_START    0x005A9000  /* .rdata start */
#define XWA_DATA_END      0x00B10000  /* end of .data (rounded up) */
#define XWA_STACK_BASE    0x00100000  /* simulated stack start */
#define XWA_STACK_SIZE    0x00800000  /* 8 MB stack */
#define XWA_STACK_TOP     (XWA_STACK_BASE + XWA_STACK_SIZE)

/* Entire mapped region: from stack through data end */
#define XWA_REGION_START  XWA_STACK_BASE
#define XWA_REGION_END    XWA_DATA_END
#define XWA_REGION_SIZE   (XWA_REGION_END - XWA_REGION_START)

static void*  g_region_alloc = NULL;

/* ============================================================
 * VEH Crash Handler
 * ============================================================ */

static uint32_t g_seh_skip_count = 0;
static uint32_t g_esp_initial = 0;
static uint32_t g_esp_min = 0xFFFFFFFF;

static void dump_icall_trace(void) {
    fprintf(stderr, "\n=== ICALL Trace (last %d calls) ===\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        uint32_t idx = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx]) {
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_icall_trace[idx]);
        }
    }
    fprintf(stderr, "Total indirect calls: %u\n", g_icall_count);
}

static void dump_registers(void) {
    fprintf(stderr, "\n=== Recomp Register State ===\n");
    fprintf(stderr, "  EAX=0x%08X  ECX=0x%08X  EDX=0x%08X  EBX=0x%08X\n",
            g_eax, g_ecx, g_edx, g_ebx);
    fprintf(stderr, "  ESP=0x%08X  ESI=0x%08X  EDI=0x%08X\n",
            g_esp, g_esi, g_edi);
}

static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* Only handle access violations */
    if (code != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    fprintf(stderr, "\n=== CRASH: Access Violation ===\n");
    fprintf(stderr, "  Faulting address: 0x%p\n", (void*)ep->ExceptionRecord->ExceptionAddress);
    if (ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "  %s at 0x%p\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    }

    dump_registers();
    fprintf(stderr, "  Stack usage: %u bytes (initial ESP=0x%08X, min ESP=0x%08X)\n",
            g_esp_initial - g_esp, g_esp_initial, g_esp_min);
    fprintf(stderr, "  Call depth: %u (max: %u)\n", g_call_depth, g_call_depth_max);
    dump_icall_trace();

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ============================================================
 * Dispatch Table Lookup (binary search)
 * ============================================================ */

recomp_func_t recomp_lookup(uint32_t va) {
    int lo = 0;
    int hi = (int)recomp_dispatch_count - 1;

    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t mid_va = recomp_dispatch_table[mid].address;
        if (mid_va == va) {
            return recomp_dispatch_table[mid].func;
        } else if (mid_va < va) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return NULL;
}

/* Manual override table (populated as needed) */
static recomp_dispatch_entry_t g_manual_overrides[] = {
    { 0, NULL }  /* sentinel */
};
static const int g_manual_override_count = 0;

recomp_func_t recomp_lookup_manual(uint32_t va) {
    for (int i = 0; i < g_manual_override_count; i++) {
        if (g_manual_overrides[i].address == va) {
            return g_manual_overrides[i].func;
        }
    }
    return NULL;
}

/* Import bridge table (populated during init) */
#define MAX_IMPORT_BRIDGES 256
recomp_dispatch_entry_t g_import_bridges[MAX_IMPORT_BRIDGES];
int g_import_bridge_count = 0;

recomp_func_t recomp_lookup_import(uint32_t va) {
    for (int i = 0; i < g_import_bridge_count; i++) {
        if (g_import_bridges[i].address == va) {
            return g_import_bridges[i].func;
        }
    }
    return NULL;
}

/* ============================================================
 * Memory Setup
 * ============================================================ */

static int setup_memory(const char* data_file) {
    /*
     * Allocate one contiguous region covering both the simulated stack
     * and original data sections. A single g_mem_base offset translates
     * all original VAs to real addresses.
     *
     * We try to map at the original addresses first (g_mem_base = 0),
     * but fall back to wherever the OS gives us.
     */

    printf("[*] Allocating %u MB region (0x%08X - 0x%08X)\n",
           (unsigned)(XWA_REGION_SIZE / (1024*1024)), XWA_REGION_START, XWA_REGION_END);

    /* Debug: check what's at our target addresses */
    {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t scan = XWA_REGION_START;
        printf("[*] Memory map at target range:\n");
        while (scan < XWA_REGION_END) {
            if (VirtualQuery((void*)scan, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.State != MEM_FREE) {
                printf("    0x%08X-0x%08X: State=0x%lX Type=0x%lX\n",
                       (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                       mbi.State, mbi.Type);
            }
            scan += mbi.RegionSize;
            if (mbi.RegionSize == 0) break;
        }
    }

    /* Strategy: The CRT heap often reserves 0x400000-0xBFB000 on Windows 10/11.
     * Our data sections fall within that range (0x5A9000-0xB10000).
     * We can COMMIT pages within an existing reservation using just MEM_COMMIT. */

    /* Try 1: Full region at exact addresses */
    g_region_alloc = VirtualAlloc(
        (void*)(uintptr_t)XWA_REGION_START,
        XWA_REGION_SIZE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (g_region_alloc) {
        g_mem_base = 0;
        printf("[*] Mapped at original addresses (g_mem_base = 0)\n");
        goto alloc_done;
    }

    /* Try 2: Commit pages within existing reservation (data section) */
    {
        void* data_try = VirtualAlloc(
            (void*)(uintptr_t)XWA_DATA_START,
            XWA_DATA_END - XWA_DATA_START,
            MEM_COMMIT,  /* just commit, don't reserve */
            PAGE_READWRITE
        );
        if (data_try == (void*)(uintptr_t)XWA_DATA_START) {
            printf("[*] Data committed at original VA 0x%08X (within existing reservation)\n",
                   XWA_DATA_START);
            g_mem_base = 0;
            g_region_alloc = data_try;

            /* Stack: also try to commit at original address, else use real address */
            void* stack_try = VirtualAlloc(
                (void*)(uintptr_t)XWA_STACK_BASE, XWA_STACK_SIZE,
                MEM_COMMIT, PAGE_READWRITE);
            if (!stack_try) {
                stack_try = VirtualAlloc(
                    (void*)(uintptr_t)XWA_STACK_BASE, XWA_STACK_SIZE,
                    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            }
            if (stack_try == (void*)(uintptr_t)XWA_STACK_BASE) {
                printf("[*] Stack committed at original VA 0x%08X\n", XWA_STACK_BASE);
            } else {
                /* Stack at different address - use REAL address for ESP */
                if (!stack_try) {
                    stack_try = VirtualAlloc(NULL, XWA_STACK_SIZE,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                }
                if (!stack_try) {
                    fprintf(stderr, "ERROR: Failed to allocate stack\n");
                    return 0;
                }
                /* With g_mem_base=0, ESP must be real address since MEM32 won't translate */
                g_esp = (uint32_t)((uintptr_t)stack_try + XWA_STACK_SIZE - 16);
                printf("[*] Stack at %p (real addr, ESP=0x%08X)\n", stack_try, g_esp);
            }
            goto alloc_done;
        }
    }

    /* Try 3: Complete fallback - let OS pick */
    printf("[*] Fixed allocation failed, using OS-picked address...\n");
    g_region_alloc = VirtualAlloc(NULL, XWA_REGION_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!g_region_alloc) {
        fprintf(stderr, "ERROR: Failed to allocate %u MB region\n",
                (unsigned)(XWA_REGION_SIZE / (1024*1024)));
        return 0;
    }
    g_mem_base = (ptrdiff_t)((uintptr_t)g_region_alloc - XWA_REGION_START);
    printf("[*] Region at %p (offset %lld from original)\n",
           g_region_alloc, (long long)g_mem_base);

alloc_done:

memory_ready:
    /* Set initial stack pointer (as a VIRTUAL address, translated via ADDR) */
    if (g_esp == 0) {
        g_esp = XWA_STACK_TOP - 16;
    }

    /* Load .rdata and .data sections from the original binary */
    if (data_file) {
        FILE* f = fopen(data_file, "rb");
        if (f) {
            /*
             * Section offsets from PE section headers:
             * .rdata: file offset 0x001A8000, VA 0x005A9000, VSize 0x4A24, RawSize 0x4C00
             * .data:  file offset 0x001ACC00, VA 0x005AE000, VSize 0x561974, RawSize 0x60600
             * BSS (zero-initialized) portion of .data is VSize - RawSize = 0x501374 bytes,
             * which is already zeroed by VirtualAlloc. Only read the on-disk RawSize.
             */
            /* Read .rdata (VSize) */
            fseek(f, 0x001A8000, SEEK_SET);
            fread((void*)ADDR(0x005A9000), 1, 0x4A24, f);

            /* Read .data (RawSize only; rest is BSS, already zero from VirtualAlloc) */
            fseek(f, 0x001ACC00, SEEK_SET);
            fread((void*)ADDR(0x005AE000), 1, 0x60600, f);

            fclose(f);
            printf("[*] Loaded data sections from %s\n", data_file);
        } else {
            fprintf(stderr, "WARNING: Could not open %s for data loading\n", data_file);
        }
    }

    return 1;
}

static void cleanup_memory(void) {
    if (g_region_alloc) {
        VirtualFree(g_region_alloc, 0, MEM_RELEASE);
        g_region_alloc = NULL;
    }
}

/* ============================================================
 * Entry Point
 * ============================================================ */

/* Forward declaration of the recompiled game entry points */
extern void sub_0050A4A0(void);  /* WinMain */
extern void sub_0059CD60(void);  /* CRT startup (calls WinMain internally) */

/* Import bridge registration (generated by gen_bridges.py) */
extern void register_import_bridges(void);

int main(int argc, char* argv[]) {
    printf("=== X-Wing Alliance Static Recompilation ===\n");
    printf("=== Phase 2: Recompilation Infrastructure  ===\n\n");

    /* Default path to original binary for data loading */
    const char* data_file = NULL;
    if (argc > 1) {
        data_file = argv[1];
    }

    /* Install VEH crash handler */
    AddVectoredExceptionHandler(1, veh_handler);
    printf("[*] VEH crash handler installed\n");

    /* Set up memory layout */
    if (!setup_memory(data_file)) {
        fprintf(stderr, "FATAL: Memory setup failed\n");
        return 1;
    }
    printf("[*] Memory layout initialized\n");
    printf("    Region: %p (VA 0x%08X - 0x%08X)\n",
           g_region_alloc, XWA_REGION_START, XWA_REGION_END);
    printf("    Stack:  VA 0x%08X - 0x%08X (ESP = 0x%08X)\n",
           XWA_STACK_BASE, XWA_STACK_TOP, g_esp);
    printf("    Data:   VA 0x%08X - 0x%08X\n", XWA_DATA_START, XWA_DATA_END);
    printf("    Offset: %lld\n", (long long)g_mem_base);

    /* Register import bridges (maps IAT slots to bridge functions) */
    register_import_bridges();

    printf("\n[*] XWA recomp infrastructure ready.\n");
    printf("[*] Dispatch table: %u functions\n", recomp_dispatch_count);

    if (!data_file) {
        printf("[*] To run game: pass path to xwingalliance.exe as argument\n");
        cleanup_memory();
        return 0;
    }

    /*
     * Call WinMain directly, bypassing the original CRT startup.
     * The VC6 CRT startup (sub_0059CD60) initializes the C runtime heap,
     * stdio, SEH, etc. - but those are already provided by our real CRT.
     * The original CRT's heap metadata in .data points to addresses that
     * don't exist in our process, causing crashes.
     *
     * WinMain(hInstance, hPrevInstance=NULL, lpCmdLine, nCmdShow=SW_SHOWDEFAULT)
     * Args pushed right-to-left on simulated stack.
     */
    HINSTANCE hInst = GetModuleHandleA(NULL);
    LPSTR cmdLine = GetCommandLineA();

    /* Store command line string in mapped memory so game code can access it */
    uint32_t cmdline_va = XWA_DATA_END - 0x400;  /* use end of data region as scratch */
    strncpy((char*)ADDR(cmdline_va), cmdLine, 0x3FF);
    ((char*)ADDR(cmdline_va))[0x3FF] = '\0';

    g_esp_initial = g_esp;
    g_esp_min = g_esp;

    /* Disable VC6 small-block heap (SBH) - route all malloc to HeapAlloc.
     * We bypassed the CRT startup (_heap_init, __sbh_heap_init) which would
     * normally initialize the SBH lock table. Without it, _lock(9) tries to
     * lazily allocate a CRITICAL_SECTION via malloc, which re-enters the SBH
     * path and creates infinite recursion. Setting __sbh_threshold to 0 forces
     * _heap_alloc_base to use the HeapAlloc fallback for all sizes. */
    MEM32(0x60DC1C) = 0;  /* Disable SBH - force HeapAlloc for all sizes */

    /* Initialize CRT heap handle to our process heap */
    MEM32(0xB0E828) = (uint32_t)(uintptr_t)GetProcessHeap();

    /* Pre-initialize CRT lock table at 0x60B1C8 + locknum*4.
     * VC6 CRT _lock() lazily allocates CRITICAL_SECTION structs and
     * recursively calls _lock(0x11) to protect the allocation. Without
     * pre-initialized locks, this creates infinite recursion.
     * Lock 0x11 (heap lock) must be initialized first. */
    {
        #define CRT_MAX_LOCKS 36
        static CRITICAL_SECTION crt_locks[CRT_MAX_LOCKS];
        for (int i = 0; i < CRT_MAX_LOCKS; i++) {
            InitializeCriticalSection(&crt_locks[i]);
            MEM32(i * 4 + 0x60B1C8) = (uint32_t)(uintptr_t)&crt_locks[i];
        }
        printf("[*] Pre-initialized %d CRT locks\n", CRT_MAX_LOCKS);
    }

    /* Verify data section loaded correctly */
    printf("[*] Data check: 0x5FFEEC = \"%s\"\n", (char*)ADDR(0x5FFEEC));
    printf("[*] Data check: 0x5FFEE4 = \"%s\"\n", (char*)ADDR(0x5FFEE4));
    printf("[*] Data check: 0x631860 = \"%s\"\n", (char*)ADDR(0x631860));

    printf("[*] Launching WinMain (sub_0050A4A0)...\n");
    printf("    hInstance = %p, cmdLine = \"%s\"\n", hInst, cmdLine);
    fflush(stdout);

    /* Push WinMain args: nCmdShow, lpCmdLine, hPrevInstance, hInstance, return addr */
    PUSH32(g_esp, 0x0Au);              /* nCmdShow = SW_SHOWDEFAULT */
    PUSH32(g_esp, cmdline_va);         /* lpCmdLine (VA in mapped memory) */
    PUSH32(g_esp, 0);                  /* hPrevInstance = NULL */
    PUSH32(g_esp, (uint32_t)(uintptr_t)hInst);  /* hInstance */
    PUSH32(g_esp, 0xDEAD0000u);        /* dummy return address */
    sub_0050A4A0();

    printf("[*] WinMain returned (eax = 0x%08X)\n", g_eax);

    cleanup_memory();
    return 0;
}
