/*
 * X-Wing Alliance Static Recompilation - Entry Point
 *
 * Sets up the memory layout, initializes the register model,
 * installs the VEH crash handler, and launches the recompiled game.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>  /* NtCurrentTeb() */
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
uint32_t g_total_calls = 0;
uint32_t g_total_icalls = 0;
int g_heap_check_enabled = 0;
uint32_t g_heap_check_last_ok_call = 0;
uint32_t g_heap_check_last_ok_va = 0;

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
#define XWA_DATA_END      0x00BFB000  /* end of uncommitted region in 0x400000 heap reservation */
#define XWA_EXTENDED_END  0x02000000  /* max address for demand-paged BSS extension */
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

static void dump_trace_ring(void) {
    fprintf(stderr, "\n=== Trace Ring Buffer (last %d entries) ===\n", TRACE_RING_SIZE);
    uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
    for (uint32_t i = start; i < g_trace_ring_idx; i++) {
        uint32_t idx = i & (TRACE_RING_SIZE - 1);
        if (g_trace_ring[idx][0]) {
            fprintf(stderr, "  %s", g_trace_ring[idx]);
        }
    }
}

/* Helper: write string to Win32 HANDLE */
static void wf(HANDLE h, const char* s) {
    DWORD w;
    WriteFile(h, s, (DWORD)strlen(s), &w, NULL);
}

static uint32_t g_demand_page_count = 0;

static LONG WINAPI veh_handler(EXCEPTION_POINTERS* ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* Demand-paging: auto-commit pages for accesses in the extended BSS range.
     * The original game's data extends past the PE .data VSize, and we can't
     * pre-reserve everything due to existing allocations (DLLs, heap, etc.). */
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        uintptr_t fault_addr = ep->ExceptionRecord->ExceptionInformation[1];
        if (fault_addr >= XWA_DATA_START && fault_addr < XWA_EXTENDED_END) {
            uintptr_t page = fault_addr & ~0xFFFu;
            void* p = NULL;

            /* Strategy 1: Commit within existing reservation */
            p = VirtualAlloc((void*)page, 0x1000, MEM_COMMIT, PAGE_READWRITE);

            /* Strategy 2: Change protection on already-committed pages */
            if (!p) {
                DWORD old_prot;
                if (VirtualProtect((void*)page, 0x1000, PAGE_READWRITE, &old_prot)) {
                    p = (void*)page;
                }
            }

            /* Strategy 2b: For MEM_MAPPED pages, try PAGE_WRITECOPY */
            if (!p) {
                DWORD old_prot;
                if (VirtualProtect((void*)page, 0x1000, PAGE_WRITECOPY, &old_prot)) {
                    p = (void*)page;
                }
            }

            /* Strategy 3: Reserve+commit in free space at 64KB-aligned base */
            if (!p) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery((void*)page, &mbi, sizeof(mbi)) && mbi.State == MEM_FREE) {
                    uintptr_t block = page & ~0xFFFFu;
                    p = VirtualAlloc((void*)block, 0x10000,
                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                }
            }

            if (p) {
                g_demand_page_count++;
                if (g_demand_page_count <= 32 || (g_demand_page_count & 0xFF) == 0) {
                    fprintf(stderr, "[DEMAND] Page at 0x%08X (fault=0x%08X, count=%u)\n",
                            (uint32_t)(uintptr_t)p, (uint32_t)fault_addr, g_demand_page_count);
                }
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            /* If all strategies failed, fall through to crash handler */
            fprintf(stderr, "[DEMAND] FAILED at 0x%08X (err=%lu)\n",
                    (uint32_t)fault_addr, GetLastError());
        }
    }

    /* Log ALL exceptions to stderr (even non-fatal ones) for debugging */
    fprintf(stderr, "\n!!! VEH: exception 0x%08lX at 0x%p !!!\n",
        code, (void*)ep->ExceptionRecord->ExceptionAddress);
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        fprintf(stderr, "    %s addr=0x%p, g_esp=0x%08X, total_calls=%u\n",
            ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
            (void*)ep->ExceptionRecord->ExceptionInformation[1],
            g_esp, g_total_calls);
    }
    if (code == 0xC0000374 /* STATUS_HEAP_CORRUPTION */) {
        extern uint32_t g_last_heapalloc_heap, g_last_heapalloc_size, g_last_heapalloc_ret;
        extern uint32_t g_last_heapfree_ptr, g_heapop_count;
        fprintf(stderr, "    HEAP CORRUPTION: heapop_count=%u\n", g_heapop_count);
        fprintf(stderr, "    last HeapAlloc: heap=0x%08X size=0x%08X ret=0x%08X\n",
                g_last_heapalloc_heap, g_last_heapalloc_size, g_last_heapalloc_ret);
        fprintf(stderr, "    last HeapFree: ptr=0x%08X\n", g_last_heapfree_ptr);
        fprintf(stderr, "    g_esp=0x%08X, total_calls=%u, total_icalls=%u\n",
                g_esp, g_total_calls, g_total_icalls);
        /* Dump trace ring */
        fprintf(stderr, "    Last 16 trace ring entries:\n");
        for (int i = 16; i > 0; i--) {
            uint32_t idx = (g_trace_ring_idx - i) & (TRACE_RING_SIZE-1);
            fprintf(stderr, "      [-%d] %s", i, g_trace_ring[idx]);
        }
    }
    fflush(stderr);

    /* Only handle fatal exceptions (skip C++ exceptions, breakpoints, etc.) */
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION &&
        code != EXCEPTION_IN_PAGE_ERROR &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED &&
        code != 0xC0000374 /* STATUS_HEAP_CORRUPTION */) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* Write crash dump using raw Win32 API only - no CRT at all */
    HANDLE h = CreateFileA("D:\\recomp\\pc\\xwa\\xwa_crash.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[256];

        snprintf(buf, sizeof(buf), "=== CRASH: Exception 0x%08X ===\r\n"
            "  Faulting IP: 0x%p\r\n", code, (void*)ep->ExceptionRecord->ExceptionAddress);
        wf(h, buf);

        if (ep->ExceptionRecord->NumberParameters >= 2) {
            snprintf(buf, sizeof(buf), "  %s at 0x%p\r\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "WRITE" : "READ",
                (void*)ep->ExceptionRecord->ExceptionInformation[1]);
            wf(h, buf);
        }

        snprintf(buf, sizeof(buf),
            "\r\nEAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
            "Stack usage: %u bytes (initial=0x%08X)\r\n"
            "Call depth: %u (max: %u)\r\n"
            "Total calls: %u, icalls: %u\r\n",
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
            g_esp_initial - g_esp, g_esp_initial,
            g_call_depth, g_call_depth_max,
            g_total_calls, g_total_icalls);
        wf(h, buf);

        /* Dump simulated stack */
        wf(h, "\r\n=== Stack ===\r\n");
        for (int i = -4; i < 16; i++) {
            uint32_t addr = g_esp + i * 4;
            snprintf(buf, sizeof(buf), "  [ESP%+d] 0x%08X: 0x%08X\r\n", i*4, addr, MEM32(addr));
            wf(h, buf);
        }

        /* Dump trace ring */
        wf(h, "\r\n=== Trace Ring ===\r\n");
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                wf(h, buf);
            }
        }

        /* Dump ICALL trace */
        wf(h, "\r\n=== ICALL Trace ===\r\n");
        for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
            uint32_t idx = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx]) {
                snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", i, g_icall_trace[idx]);
                wf(h, buf);
            }
        }
        snprintf(buf, sizeof(buf), "Total indirect calls: %u\r\n", g_icall_count);
        wf(h, buf);

        CloseHandle(h);
    }

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

/* SafeDisc-encrypted function stubs
 * These addresses (in .text 0x5A0000-0x5A8FFF) contain encrypted code from
 * SafeDisc copy protection. The Steam version doesn't decrypt them.
 * They're called from CRT __initterm during C++ static initialization.
 * Safe to stub as no-ops since we don't need SafeDisc initialization. */
static void stub_safedisc_nop(void) {
    /* Clean return: pop return address */
    g_esp += 4;
}

/* Stub for __sbh_heap_init - returns 1 (success) without initializing SBH */
static void stub_sbh_heap_init(void) {
    g_eax = 1;  /* return TRUE (success) */
    g_esp += 4;  /* pop return address */
}

/* Stub for __sbh_find_block - always returns 0 (not found).
 * Since SBH is disabled (threshold=0), no allocations go through SBH,
 * so no blocks should ever be found. This prevents the real function
 * from traversing uninitialized SBH header list at 0x60BBF8.
 * Signature: int __sbh_find_block(void* ptr, HEADER** pHeader, REGION** pRegion)
 * cdecl, 3 args (12 bytes), caller cleans stack. */
static void stub_sbh_find_block(void) {
    g_eax = 0;  /* not found */
    g_esp += 4;  /* pop return address */
}

/* sub_0057E560: Pre-main-loop init callback.
 * Called via function pointer at 0xA1C071 before entering the game loop.
 * Initializes sound/music subsystems and loads font resources.
 * Original code: 0x0057E560-0x0057E59E */
static void manual_sub_0057E560(void) {
    extern void sub_0053F800(void);
    extern void sub_0053F5C0(void);
    extern void sub_0055BB90(void);
    extern void sub_0053F5B0(void);
    extern void sub_0053F970(void);
    extern void sub_00556B20(void);
    #define esp g_esp

    RECOMP_CALL(sub_0053F800);
    PUSH32(esp, 0);
    RECOMP_CALL(sub_0053F5C0);
    esp += 4;
    RECOMP_CALL(sub_0055BB90);
    RECOMP_CALL(sub_0053F5B0);
    RECOMP_CALL(sub_0053F970);
    PUSH32(esp, 0xAu);
    RECOMP_CALL(sub_00556B20);
    esp += 4;
    PUSH32(esp, 0xCu);
    RECOMP_CALL(sub_00556B20);
    esp += 4;
    PUSH32(esp, 0xFu);
    RECOMP_CALL(sub_00556B20);
    esp += 4;
    g_eax = 0;
    esp += 4;  /* pop return address */

    #undef esp
}

/* sub_0057E4F0: Per-frame update callback.
 * Called every game loop iteration from sub_0053E760.
 * Handles sound mixing, display flip, and frame timing.
 * Original code: 0x0057E4F0-0x0057E557 */
static void manual_sub_0057E4F0(void) {
    extern void sub_0053F010(void);
    extern void sub_0055BC20(void);
    extern void sub_0053F5D0(void);
    extern void sub_00541810(void);
    extern void sub_0053EF80(void);
    #define esp g_esp

    RECOMP_CALL(sub_0053F010);
    PUSH32(esp, 0);
    PUSH32(esp, 0x00601C9Cu);
    RECOMP_CALL(sub_0055BC20);
    g_eax = MEM32(0x9F4B40);
    esp += 8;
    if (g_eax != 0) goto frame_skip;
    PUSH32(esp, 0);
    PUSH32(esp, 0x00601C94u);
    RECOMP_CALL(sub_0055BC20);
    g_eax = MEM32(0x9F4B40);
    esp += 8;
    if (g_eax != 0) goto frame_skip;
    PUSH32(esp, 0);
    PUSH32(esp, 0x00601C88u);
    RECOMP_CALL(sub_0055BC20);
    esp += 8;
frame_skip:
    RECOMP_CALL(sub_0053F5D0);
    PUSH32(esp, 0x00584F30u);
    PUSH32(esp, 0x00584F50u);
    RECOMP_CALL(sub_00541810);
    esp += 8;
    RECOMP_CALL(sub_0053EF80);
    MEM32(0x9F60D4) = g_eax;
    g_eax = 0;
    esp += 4;  /* pop return address */

    #undef esp
}

/* sub_00584F30: Outer init callback.
 * Calls sound init, game init callback, and display init.
 * Original code: 0x00584F30-0x00584F41 */
static void manual_sub_00584F30(void) {
    extern void sub_005580D0(void);
    extern void sub_00528A50(void);
    extern void sub_0055D720(void);
    #define esp g_esp
    RECOMP_CALL(sub_005580D0);
    RECOMP_CALL(sub_00528A50);
    RECOMP_CALL(sub_0055D720);
    g_eax = 0;
    esp += 4;
    #undef esp
}

/* sub_00584F50: Outer frame callback.
 * Calls sound update, then recurses with inner callbacks.
 * Original code: 0x00584F50-0x00584F72 */
static void manual_sub_00584F50(void) {
    extern void sub_00558100(void);
    extern void sub_00541810(void);
    #define esp g_esp
    g_eax = MEM32(0xABD1E4);
    PUSH32(esp, g_eax);
    RECOMP_CALL(sub_00558100);
    esp += 4;
    PUSH32(esp, 0x00539760u);
    PUSH32(esp, 0x005397D0u);
    RECOMP_CALL(sub_00541810);
    esp += 8;
    g_eax = 0;
    esp += 4;
    #undef esp
}

/* sub_00539760: Inner cleanup callback.
 * Frees music/sound resources and closes resource files.
 * Original code: 0x00539760-0x005397C3 */
static void manual_sub_00539760(void) {
    extern void sub_00558BE0(void);
    extern void sub_00564D10(void);
    extern void sub_0055DD40(void);
    extern void sub_0055DCE0(void);
    extern void sub_0055D480(void);
    extern void sub_005387A0(void);
    #define esp g_esp
    RECOMP_CALL(sub_00558BE0);
    PUSH32(esp, 0x00602BB4u);
    RECOMP_CALL(sub_00564D10);
    esp += 4;
    RECOMP_CALL(sub_0055DD40);
    RECOMP_CALL(sub_0055DCE0);
    g_eax = MEM32(0x9F4B98);
    if (g_eax != 0) {
        PUSH32(esp, g_eax);
        RECOMP_CALL(sub_0055D480);
        esp += 4;
        MEM32(0x9F4B98) = 0;
    }
    g_eax = MEM32(0x9F4B24);
    if (g_eax != 0) {
        PUSH32(esp, g_eax);
        RECOMP_CALL(sub_0055D480);
        esp += 4;
        MEM32(0x9F4B24) = 0;
    }
    PUSH32(esp, 0x00602BA8u);
    RECOMP_CALL(sub_005387A0);
    esp += 4;
    g_eax = 0;
    esp += 4;
    #undef esp
}

/* sub_005397D0: Main game tick function.
 * Handles input, game state updates, rendering for one frame.
 * TODO: Properly implement this large function (~300 bytes).
 * For now, stub it to return 0 (skip game logic), but present
 * a frame so the D3D11 window stays visible. */
static void manual_sub_005397D0(void) {
    /* Game tick is stubbed - rendering is driven by PeekMessage idle present.
     * When this function is properly implemented, it will call BeginScene,
     * Execute (with execute buffers), EndScene, and Flip. */
    g_eax = 0;
    g_esp += 4;  /* pop return address */
}

/* Stub for sub_00556B20 (font/resource loader) - returns 1 (success).
 * The real function tries to load .abp font files (which don't exist),
 * falls back to GDI rendering on a DD surface, and fails during the
 * complex pixel readback pipeline. Stubbing lets us get past DD init.
 * cdecl, 1 arg (caller cleans), returns 1 in eax. */
static void stub_font_loader(void) {
    uint32_t fontIdx = MEM32(g_esp + 4);
    fprintf(stderr, "[STUB] sub_00556B20(fontIdx=%u) -> returning 1 (success)\n", fontIdx);
    g_eax = 1;
    g_esp += 4;  /* pop return address */
}

/* Tracing helper: log when specific functions are entered */
static void trace_winmain_entry(void) {
    fprintf(stderr, "[TRACE] WinMain (sub_0050A4A0) entered\n");
    fflush(stderr);
    /* Tail to real function */
    extern void sub_0050A4A0(void);
    sub_0050A4A0();
}

/* Stub for calls through uninitialized function pointers (NULL/0).
 * Returns 0 in eax, pops return address from simulated stack. */
static void stub_null_funcptr(void) {
    g_eax = 0;
    g_esp += 4;  /* pop return address */
}

/* _initstdio (0x59CC80) - CRT$XI initializer for FILE stream table.
 * SafeDisc-encrypted in original binary; reimplemented from VC6 CRT source.
 * The generated code for this function body exists as unreachable labels
 * L_0059CC8A-L_0059CD3A inside sub_0059CC10, but the entry prologue at
 * 0x59CC80-0x59CC89 was encrypted and never lifted.
 *
 * Initializes _nstream (0xB0F960) and _piob (0xB0E948) so that CRT fopen works.
 */
static void manual_initstdio(void) {
    extern void sub_0059C9B0(void);  /* _calloc_crt */
    extern void sub_0059CF10(void);  /* _amsg_exit */

    /* Use 'esp' as a local alias that the RECOMP_CALL macro expects.
     * RECOMP_CALL expands to PUSH32(esp, ...) so esp must resolve to g_esp.
     * Define esp as a macro only within this function scope. */
    #define esp g_esp

    /* This is a void(*)(void) callback from __initterm; pop return address */
    esp += 4;

    /* Read _nstream; if 0, default to 0x200; if < 0x14, minimum 0x14 */
    uint32_t nstream = MEM32(0xB0F960);
    if (nstream == 0) {
        nstream = 0x200;  /* default: 512 streams */
    } else if ((int32_t)nstream < 0x14) {
        nstream = 0x14;   /* minimum: 20 streams */
    }
    MEM32(0xB0F960) = nstream;

    /* calloc(_nstream, 4) via _calloc_crt */
    PUSH32(esp, 4);           /* element size */
    PUSH32(esp, nstream);     /* count */
    RECOMP_CALL(sub_0059C9B0);
    esp += 8;
    uint32_t piob = g_eax;
    MEM32(0xB0E948) = piob;

    /* If allocation failed, retry with minimum 20 */
    if (piob == 0) {
        MEM32(0xB0F960) = 0x14;
        PUSH32(esp, 4);
        PUSH32(esp, 0x14u);
        RECOMP_CALL(sub_0059C9B0);
        esp += 8;
        piob = g_eax;
        MEM32(0xB0E948) = piob;

        if (piob == 0) {
            /* Fatal: _amsg_exit(0x1a) */
            PUSH32(esp, 0x1Au);
            RECOMP_CALL(sub_0059CF10);
            esp += 4;
            piob = MEM32(0xB0E948);
        }
    }

    /* Initialize _piob entries pointing to static FILE structs at 0x60AF10.
     * Each FILE struct is 0x20 bytes. Range: 0x60AF10 to 0x60B190. */
    {
        uint32_t offset = 0;
        uint32_t file_addr = 0x60AF10u;
        while (file_addr < 0x60B190u) {
            MEM32(piob + offset) = file_addr;
            file_addr += 0x20;
            offset += 4;
            piob = MEM32(0xB0E948);  /* re-read in case of aliasing */
        }
    }

    /* Initialize _file fields for pre-allocated IOB entries (stdin/stdout/stderr).
     * For each index, look up the OS handle from __pioinfo table.
     * If handle is -1 or 0, set _file = -1 in the FILE struct. */
    {
        uint32_t idx = 0;
        uint32_t edx = 0x60AF20u;
        while (edx < 0x60AF80u) {
            uint32_t bucket = (uint32_t)((int32_t)idx >> 5);
            uint32_t slot = idx & 0x1F;
            uint32_t pioinfo_ptr = MEM32(bucket * 4 + 0xB0E840);
            uint32_t handle = MEM32(pioinfo_ptr + (slot + slot * 8) * 4);
            if (handle == 0xFFFFFFFF || handle == 0) {
                MEM32(edx) = 0xFFFFFFFF;
            }
            edx += 0x20;
            idx += 1;
        }
    }

    #undef esp

    fprintf(stderr, "[MANUAL] _initstdio: _nstream=%u, _piob=0x%08X\n",
            MEM32(0xB0F960), MEM32(0xB0E948));
    fflush(stderr);
}

/* Stub for DirectInput internal dispatch table entries (sub_0049A490).
 * These are COM method implementations stored as function pointers at
 * 0x6937D4-0x693838. They are mid-function labels within sub_0049A490
 * that the dispatch table doesn't know about. All return DD_OK (0)
 * and pop the return address (stdcall with 'this' ptr + variable args).
 * Most take 1-3 args; we pop conservatively and let the caller handle
 * the rest via the known ecx-based dispatch pattern. */
static void stub_dinput_nop(void) {
    g_eax = 0;
    g_esp += 4;  /* pop return address */
}

/* ============================================================
 * WndProc Bridge
 *
 * Windows calls the WndProc at the address stored in the WNDCLASS
 * structure. The game stores 0x0053E650 which is a mid-function
 * label inside sub_0053E340 (the actual WndProc). Since our .text
 * pages are data-only (not executable), we need a real native
 * stdcall function that bridges to the recompiled WndProc.
 *
 * We write our bridge function's address into the WNDCLASS at the
 * point where the game stores the WndProc pointer. But actually,
 * the better approach: override the address 0x0053E650 in the manual
 * override table, AND write a real native WndProc bridge.
 *
 * The game's WndProc (sub_0053E340) is stdcall with 4 args:
 *   LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM)
 * It pops ebx, ebp, esi, edi, processes the message, and returns
 * via ret 0x10 (pops 4 args + 16 bytes from stack).
 * ============================================================ */
extern void sub_0053E340(void);

static LRESULT CALLBACK native_wndproc_bridge(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static uint32_t wndproc_count = 0;
    wndproc_count++;
    if (wndproc_count <= 30 || (wndproc_count % 5000 == 0)) {
        fprintf(stderr, "[WND] WndProc #%u: msg=0x%04X wParam=0x%X lParam=0x%X esp=0x%08X\n",
                wndproc_count, msg, (uint32_t)wParam, (uint32_t)lParam, g_esp);
        fflush(stderr);
    }

    /* Save callee-saved globals - WndProc is re-entrant from native Windows
     * callbacks and must not corrupt the caller's register state */
    uint32_t saved_esp = g_esp;
    uint32_t saved_ebx = g_ebx;
    uint32_t saved_esi = g_esi;
    uint32_t saved_edi = g_edi;

    /* Push args right-to-left on simulated stack (stdcall convention) */
    PUSH32(g_esp, (uint32_t)lParam);
    PUSH32(g_esp, (uint32_t)wParam);
    PUSH32(g_esp, (uint32_t)msg);
    PUSH32(g_esp, (uint32_t)(uintptr_t)hwnd);
    PUSH32(g_esp, 0xDEAD0000u);  /* return address (will be consumed by ret 0x10) */

    g_call_depth++;
    if (g_call_depth > g_call_depth_max) g_call_depth_max = g_call_depth;
    sub_0053E340();
    g_call_depth--;

    /* Restore callee-saved globals */
    g_esp = saved_esp;
    g_ebx = saved_ebx;
    g_esi = saved_esi;
    g_edi = saved_edi;

    return (LRESULT)g_eax;
}

/* Stub that stores the native WndProc bridge address instead of 0x0053E650.
 * When the game stores the WndProc address into the WNDCLASS, it uses the
 * instruction at 0x0053EB47: mov [esp+0x18], 0x53E650. We intercept the
 * ICALL/address to write our bridge address instead.
 *
 * BUT: since the address 0x0053E650 is a constant embedded in the code,
 * we patch the .text data at 0x0053E650 to contain a thunk. Actually,
 * the simplest approach: patch the memory at the location where the game
 * stores this constant in the WNDCLASS structure. That happens at the
 * instruction at 0x0053EB47. We'll patch the constant there after .text
 * is loaded. OR: we can just patch the .text word at the operand location.
 *
 * Even simpler: add 0x0053E650 as a manual override that acts as the
 * WndProc entry point. When called via ITAIL/ICALL it would work. But
 * Windows calls it as a real function pointer, not through our dispatch.
 *
 * The real fix: patch the DWORD at 0x0053E648 (the mov operand for the
 * instruction at 0x0053EB47) OR write the native bridge address into
 * the WNDCLASS after the game sets it up. BUT the WNDCLASS is on the
 * stack, allocated dynamically.
 *
 * Cleanest approach: patch the .text data at the instruction that stores
 * the WndProc address. The instruction at 0x0053EB47 is:
 *   C7 44 24 18 50 E6 53 00  (mov [esp+0x18], 0x0053E650)
 * The immediate operand 0x0053E650 is at file/VA offset 0x0053EB4B.
 * We overwrite it with our native bridge address. */

/* Manual override table */
static recomp_dispatch_entry_t g_manual_overrides[] = {
    { 0x00000000, stub_null_funcptr },  /* NULL function pointer calls */
    { 0x005A0750, stub_safedisc_nop },
    { 0x005A0EC0, stub_safedisc_nop },
    { 0x005A1100, stub_safedisc_nop },
    { 0x005A13B0, stub_safedisc_nop },
    /* SafeDisc-encrypted CRT functions called during __initterm.
     * These are void(*)(void) callbacks; safe to stub as no-ops. */
    { 0x0059A5F0, stub_safedisc_nop },
    { 0x0059C150, stub_safedisc_nop },
    { 0x0059CC80, manual_initstdio },
    /* CRT atexit callback (called during exit cleanup via _initterm).
     * Address 0x59CD40 is in .text but not in dispatch table. */
    { 0x0059CD40, stub_safedisc_nop },
    /* DirectInput internal dispatch table entries (sub_0049A490).
     * These are mid-function label addresses stored in the DI vtable
     * at 0x6937D4-0x693838 for joystick/keyboard device handling. */
    { 0x0049A630, stub_dinput_nop },
    { 0x0049A670, stub_dinput_nop },
    { 0x0049A6B0, stub_dinput_nop },
    { 0x0049A6F0, stub_dinput_nop },
    { 0x0049A730, stub_dinput_nop },
    { 0x0049A770, stub_dinput_nop },
    { 0x0049A7C0, stub_dinput_nop },
    { 0x0049A7D0, stub_dinput_nop },
    { 0x0049A800, stub_dinput_nop },
    { 0x0049A830, stub_dinput_nop },
    { 0x0049A870, stub_dinput_nop },
    { 0x0049A880, stub_dinput_nop },
    { 0x0049A8A0, stub_dinput_nop },
    { 0x0049A8B0, stub_dinput_nop },
    { 0x0049A8D0, stub_dinput_nop },
    { 0x0049A8F0, stub_dinput_nop },
    { 0x0049A910, stub_dinput_nop },
    { 0x0049A920, stub_dinput_nop },
    { 0x0049A930, stub_dinput_nop },
    { 0x0049A950, stub_dinput_nop },
    { 0x0049A9A0, stub_dinput_nop },
    { 0x0049A9C0, stub_dinput_nop },
    { 0x0049A9E0, stub_dinput_nop },
    { 0x0049AA00, stub_dinput_nop },
    { 0x0049AA20, stub_dinput_nop },
    { 0x0049AA30, stub_dinput_nop },
    /* Mid-function ITAIL targets in sub_005241B0 (DirectInput init).
     * These are cleanup/exit paths jumped to on error conditions.
     * The function has a large stack frame; these labels restore it. */
    { 0x005252BC, stub_null_funcptr },
    { 0x005252C5, stub_null_funcptr },
    /* Stub __sbh_heap_init (0x5A3560) - SBH is disabled but this func
     * still allocates 4MB of virtual memory. Return 1 (success). */
    { 0x005A3560, stub_sbh_heap_init },
    /* Stub __sbh_find_block (0x5A3800) - always returns 0 (not found).
     * Prevents traversal of uninitialized SBH header linked list. */
    { 0x005A3800, stub_sbh_find_block },
    /* Pre-main-loop init callback - missed by code generator */
    { 0x0057E560, manual_sub_0057E560 },
    /* Per-frame update callback - missed by code generator */
    { 0x0057E4F0, manual_sub_0057E4F0 },
    /* Outer init callback (calls sub_005580D0, sub_00528A50, sub_0055D720) */
    { 0x00584F30, manual_sub_00584F30 },
    /* Outer frame callback (calls sub_00558100, then sub_00541810 with inner callbacks) */
    { 0x00584F50, manual_sub_00584F50 },
    /* Inner cleanup callback (frees music/sound resources) */
    { 0x00539760, manual_sub_00539760 },
    /* Main game tick (stubbed - returns 0) */
    { 0x005397D0, manual_sub_005397D0 },
};
static const int g_manual_override_count = 45;

recomp_func_t recomp_lookup_manual(uint32_t va) {
    for (int i = 0; i < g_manual_override_count; i++) {
        if (g_manual_overrides[i].address == va) {
            return g_manual_overrides[i].func;
        }
    }
    return NULL;
}

/* Import bridge table (populated during init) */
#define MAX_IMPORT_BRIDGES 1024
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
 * Dynamic Native Function Registry
 *
 * When the game calls GetProcAddress at runtime, it gets a real
 * DLL function address. When it later ICALLs that address, we
 * need to bridge the call (read args from simulated stack, call
 * real function, adjust g_esp). This registry maps native
 * addresses to arg counts for correct bridging.
 * ============================================================ */

/* Common Win32 function arg counts (stdcall) */
typedef struct { const char* name; int nargs; } native_func_info_t;
static const native_func_info_t g_known_native_funcs[] = {
    /* KERNEL32 */
    { "GetVersion", 0 }, { "GetVersionExA", 1 }, { "GetVersionExW", 1 },
    { "GetCurrentProcessId", 0 }, { "GetCurrentThreadId", 0 },
    { "GetCurrentProcess", 0 }, { "GetTickCount", 0 },
    { "QueryPerformanceCounter", 1 }, { "QueryPerformanceFrequency", 1 },
    { "GetSystemInfo", 1 }, { "GlobalMemoryStatus", 1 },
    { "GetModuleHandleA", 1 }, { "GetModuleHandleW", 1 },
    { "GetProcAddress", 2 }, { "LoadLibraryA", 1 }, { "LoadLibraryW", 1 },
    { "FreeLibrary", 1 },
    { "GetSystemDirectoryA", 2 }, { "GetWindowsDirectoryA", 2 },
    { "CreateFileA", 7 }, { "CreateFileW", 7 },
    { "ReadFile", 5 }, { "WriteFile", 5 },
    { "CloseHandle", 1 }, { "SetFilePointer", 4 },
    { "GetFileSize", 2 }, { "DeleteFileA", 1 },
    { "GetLastError", 0 }, { "SetLastError", 1 },
    { "Sleep", 1 }, { "GetTickCount", 0 },
    { "VirtualAlloc", 4 }, { "VirtualFree", 3 },
    { "HeapAlloc", 3 }, { "HeapFree", 3 },
    { "HeapCreate", 3 }, { "HeapDestroy", 1 },
    { "InitializeCriticalSection", 1 }, { "DeleteCriticalSection", 1 },
    { "EnterCriticalSection", 1 }, { "LeaveCriticalSection", 1 },
    { "CreateMutexA", 3 }, { "ReleaseMutex", 1 },
    { "WaitForSingleObject", 2 }, { "CreateEventA", 4 },
    { "SetEvent", 1 }, { "ResetEvent", 1 },
    { "GetEnvironmentVariableA", 3 },
    { "OutputDebugStringA", 1 },
    { "InterlockedIncrement", 1 }, { "InterlockedDecrement", 1 },
    { "InterlockedExchange", 2 },
    { "TlsAlloc", 0 }, { "TlsFree", 1 },
    { "TlsGetValue", 1 }, { "TlsSetValue", 2 },
    { "GetModuleFileNameA", 3 },
    { "MultiByteToWideChar", 6 }, { "WideCharToMultiByte", 8 },
    { "lstrcpyA", 2 }, { "lstrcatA", 2 }, { "lstrlenA", 1 },
    { "GetPrivateProfileStringA", 6 }, { "GetPrivateProfileIntA", 3 },
    { "WritePrivateProfileStringA", 4 },
    /* USER32 */
    { "MessageBoxA", 4 }, { "GetDesktopWindow", 0 },
    { "ShowWindow", 2 }, { "UpdateWindow", 1 },
    { "SetWindowPos", 7 }, { "GetWindowRect", 2 },
    { "GetClientRect", 2 }, { "SetWindowTextA", 2 },
    { "GetForegroundWindow", 0 }, { "SetForegroundWindow", 1 },
    { "ShowCursor", 1 }, { "SetCursor", 1 }, { "LoadCursorA", 2 },
    { "PostQuitMessage", 1 }, { "DestroyWindow", 1 },
    { "SendMessageA", 4 }, { "PostMessageA", 4 },
    { "PeekMessageA", 5 }, { "GetMessageA", 4 },
    { "TranslateMessage", 1 }, { "DispatchMessageA", 1 },
    { "DefWindowProcA", 4 }, { "RegisterClassA", 1 },
    { "RegisterClassExA", 1 },
    { "CreateWindowExA", 12 }, { "AdjustWindowRect", 3 },
    { "GetSystemMetrics", 1 }, { "GetDC", 1 }, { "ReleaseDC", 2 },
    { "InvalidateRect", 3 }, { "MoveWindow", 6 },
    { "SetTimer", 4 }, { "KillTimer", 2 },
    { "GetKeyState", 1 }, { "GetAsyncKeyState", 1 },
    { "GetActiveWindow", 0 }, { "GetLastActivePopup", 1 },
    { "SetActiveWindow", 1 }, { "GetFocus", 0 }, { "SetFocus", 1 },
    { "EnableWindow", 2 }, { "IsWindow", 1 }, { "IsWindowVisible", 1 },
    { "GetParent", 1 }, { "SetParent", 2 },
    { "GetDlgItem", 2 }, { "SetDlgItemTextA", 3 },
    { "DialogBoxParamA", 5 }, { "EndDialog", 2 },
    { "LoadIconA", 2 }, { "LoadStringA", 4 },
    { "wsprintfA", -1 }, /* cdecl, variable args */
    { "CharUpperA", 1 }, { "CharLowerA", 1 },
    /* GDI32 */
    { "GetDeviceCaps", 2 },
    /* ADVAPI32 */
    { "RegOpenKeyExA", 5 }, { "RegCloseKey", 1 },
    { "RegQueryValueExA", 6 }, { "RegSetValueExA", 6 },
    { "RegCreateKeyExA", 9 },
    /* WINMM */
    { "timeGetTime", 0 }, { "timeBeginPeriod", 1 }, { "timeEndPeriod", 1 },
    { "joyGetNumDevs", 0 }, { "joyGetDevCapsA", 3 },
    { "joyGetPosEx", 2 },
    /* OLE32 */
    { "CoInitialize", 1 }, { "CoUninitialize", 0 },
    { "CoCreateInstance", 5 },
    /* SHELL32 */
    { "SHGetSpecialFolderPathA", 4 },
    { NULL, 0 }
};

int lookup_native_nargs(const char* name) {
    for (int i = 0; g_known_native_funcs[i].name != NULL; i++) {
        if (strcmp(g_known_native_funcs[i].name, name) == 0)
            return g_known_native_funcs[i].nargs;
    }
    return -1; /* unknown */
}

/* Dynamic native function registry */
#define MAX_NATIVE_FUNCS 128
typedef struct {
    uint32_t addr;      /* real DLL function address */
    int nargs;          /* argument count */
    char name[64];      /* function name for debugging */
} native_reg_entry_t;

static native_reg_entry_t g_native_reg[MAX_NATIVE_FUNCS];
static int g_native_reg_count = 0;

/* Register a dynamically resolved native function */
void recomp_register_native(uint32_t addr, const char* name, int nargs) {
    /* Check for duplicate */
    for (int i = 0; i < g_native_reg_count; i++) {
        if (g_native_reg[i].addr == addr) return;
    }
    if (g_native_reg_count >= MAX_NATIVE_FUNCS) {
        fprintf(stderr, "WARNING: native function registry full\n");
        return;
    }
    native_reg_entry_t* e = &g_native_reg[g_native_reg_count++];
    e->addr = addr;
    e->nargs = nargs;
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    fprintf(stderr, "[*] Registered native: %s @ 0x%08X (%d args)\n", name, addr, nargs);
}

/* Stdcall function pointer types by arg count (from imports.c) */
typedef uint32_t (__stdcall *STDFN0_t)(void);
typedef uint32_t (__stdcall *STDFN1_t)(uint32_t);
typedef uint32_t (__stdcall *STDFN2_t)(uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN3_t)(uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN4_t)(uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN5_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN6_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN7_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN8_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN9_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN10_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN11_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
typedef uint32_t (__stdcall *STDFN12_t)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

/* Call a native stdcall function with args from simulated stack */
int recomp_native_call(uint32_t va) {
    for (int i = 0; i < g_native_reg_count; i++) {
        if (g_native_reg[i].addr != va) continue;

        int n = g_native_reg[i].nargs;
        uint32_t a[12];
        for (int j = 0; j < n && j < 12; j++)
            a[j] = MEM32(g_esp + 4 + j * 4);

        /* Log MessageBoxA calls with text content */
        if (strcmp(g_native_reg[i].name, "MessageBoxA") == 0) {
            const char* text = a[1] ? (const char*)(uintptr_t)a[1] : "(null)";
            const char* caption = a[2] ? (const char*)(uintptr_t)a[2] : "(null)";
            fprintf(stderr, "[*] MessageBoxA: hwnd=0x%X text=\"%s\" caption=\"%s\" type=0x%X\n",
                    a[0], text, caption, a[3]);
        }

        uint32_t r = 0;
        void* fn = (void*)(uintptr_t)va;
        switch (n) {
            case 0:  r = ((STDFN0_t)fn)(); break;
            case 1:  r = ((STDFN1_t)fn)(a[0]); break;
            case 2:  r = ((STDFN2_t)fn)(a[0],a[1]); break;
            case 3:  r = ((STDFN3_t)fn)(a[0],a[1],a[2]); break;
            case 4:  r = ((STDFN4_t)fn)(a[0],a[1],a[2],a[3]); break;
            case 5:  r = ((STDFN5_t)fn)(a[0],a[1],a[2],a[3],a[4]); break;
            case 6:  r = ((STDFN6_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5]); break;
            case 7:  r = ((STDFN7_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6]); break;
            case 8:  r = ((STDFN8_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]); break;
            case 9:  r = ((STDFN9_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]); break;
            case 10: r = ((STDFN10_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9]); break;
            case 11: r = ((STDFN11_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10]); break;
            case 12: r = ((STDFN12_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11]); break;
            default:
                fprintf(stderr, "WARNING: native call %s has %d args (max 12)\n",
                        g_native_reg[i].name, n);
                break;
        }
        g_eax = r;
        g_esp += 4 + n * 4; /* pop return addr + args (stdcall) */
        return 1;
    }
    return 0; /* not found */
}

/* ============================================================
 * Memory Setup
 * ============================================================ */

/*
 * CRITICAL: The process heap on Windows 10/11 (32-bit) typically reserves
 * 0x400000-0xBFB000. Our game data sections (0x5A9000-0xB10000) fall within
 * that range. As the heap grows, it writes metadata into our data pages,
 * causing STATUS_HEAP_CORRUPTION (0xC0000374) non-deterministically.
 *
 * Fix: Replace the process heap with a new one at a non-conflicting address.
 * This is done by creating a new heap via HeapCreate and patching the PEB's
 * ProcessHeap field. The old heap reservation remains but is never grown into.
 */
static HANDLE g_old_process_heap = NULL;

static void relocate_process_heap(void) {
    HANDLE oldHeap = GetProcessHeap();

    /* Check if the old heap's reservation overlaps our data range */
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(oldHeap, &mbi, sizeof(mbi))) {
        uintptr_t heap_start = (uintptr_t)mbi.AllocationBase;
        /* Find the end of the reservation */
        uintptr_t heap_end = heap_start;
        uintptr_t scan = heap_start;
        while (1) {
            if (VirtualQuery((void*)scan, &mbi, sizeof(mbi)) == 0) break;
            if (mbi.AllocationBase != (void*)heap_start) break;
            heap_end = scan + mbi.RegionSize;
            scan = heap_end;
        }
        printf("[*] Process heap at %p, reservation: 0x%08X-0x%08X\n",
               oldHeap, (uint32_t)heap_start, (uint32_t)heap_end);

        /* Check for overlap with game data */
        if (heap_end <= XWA_DATA_START || heap_start >= XWA_DATA_END) {
            printf("[*] No overlap with game data - heap is safe\n");
            return; /* No conflict, no need to relocate */
        }
        printf("[!] Heap reservation OVERLAPS game data (0x%08X-0x%08X)!\n",
               XWA_DATA_START, XWA_DATA_END);
    }

    /* Create a new heap at a non-conflicting address */
    HANDLE newHeap = HeapCreate(0, 0x100000, 0);
    if (!newHeap) {
        fprintf(stderr, "ERROR: Failed to create replacement heap\n");
        return;
    }

    /* Patch PEB->ProcessHeap to point to the new heap.
     * On 32-bit Windows: TEB at fs:[0x18], PEB at TEB+0x30, ProcessHeap at PEB+0x18 */
    uint8_t* teb = (uint8_t*)NtCurrentTeb();
    uint8_t* peb = *(uint8_t**)(teb + 0x30);
    HANDLE* pProcessHeap = (HANDLE*)(peb + 0x18);

    g_old_process_heap = *pProcessHeap;
    *pProcessHeap = newHeap;

    printf("[*] Replaced process heap: old=%p new=%p\n", g_old_process_heap, newHeap);

    /* Verify it worked */
    if (GetProcessHeap() == newHeap) {
        printf("[*] Process heap relocation successful\n");
    } else {
        fprintf(stderr, "WARNING: GetProcessHeap() returned %p, expected %p\n",
                GetProcessHeap(), newHeap);
    }
}

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

    /* Relocate process heap if it conflicts with our data section */
    relocate_process_heap();

    /* Enumerate ALL heaps to find which one owns 0x400000-0xBFB000 */
    {
        HANDLE heaps[64];
        DWORD nheaps = GetProcessHeaps(64, heaps);
        printf("[*] Process has %lu heaps:\n", nheaps);
        for (DWORD i = 0; i < nheaps && i < 64; i++) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(heaps[i], &mbi, sizeof(mbi))) {
                printf("    Heap %lu: %p (alloc base %p, region 0x%lX bytes)\n",
                    i, heaps[i], mbi.AllocationBase, mbi.RegionSize);
                /* Check if this heap has a segment at 0x400000 */
                if ((uintptr_t)mbi.AllocationBase == 0x00400000 ||
                    ((uintptr_t)heaps[i] >= 0x400000 && (uintptr_t)heaps[i] < 0xBFB000)) {
                    printf("    *** THIS HEAP is in the 0x400000-0xBFB000 range! ***\n");
                }
            }
        }
    }

    /* Debug: check what's at our target addresses (scan past reservation too) */
    {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t scan = XWA_REGION_START;
        printf("[*] Memory map at target range:\n");
        while (scan < XWA_REGION_END + 0x100000) {  /* scan a bit past the region */
            if (VirtualQuery((void*)scan, &mbi, sizeof(mbi)) == 0) break;
            printf("    0x%08X-0x%08X: State=0x%lX Type=0x%lX Alloc=0x%p\n",
                   (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                   mbi.State, mbi.Type, mbi.AllocationBase);
            scan += mbi.RegionSize;
            if (mbi.RegionSize == 0) break;
        }
    }

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

    /* Try 2: Commit pages within existing reservation (data section).
     * The old heap reservation at 0x400000-0xBFB000 is still present
     * (we can't free it) but the process heap has been relocated,
     * so the heap won't grow into our data pages anymore. */
    {
        void* data_try = VirtualAlloc(
            (void*)(uintptr_t)XWA_DATA_START,
            XWA_DATA_END - XWA_DATA_START,
            MEM_COMMIT,  /* just commit, don't reserve */
            PAGE_READWRITE
        );
        if (data_try == (void*)(uintptr_t)XWA_DATA_START) {
            printf("[*] Data committed at original VA 0x%08X (within old heap reservation)\n",
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

            /* Proactively commit FREE pages from BFB000 to extended end.
             * IMPORTANT: Do NOT commit RESERVED pages - they may belong to
             * heap reservations, thread stacks, or other system structures.
             * Committing them corrupts the owning allocator's metadata. */
            {
                MEMORY_BASIC_INFORMATION mbi;
                uintptr_t scan = XWA_DATA_END;
                uint32_t committed = 0, gaps = 0, reserved_skip = 0;
                while (scan < XWA_EXTENDED_END) {
                    if (!VirtualQuery((void*)scan, &mbi, sizeof(mbi))) break;
                    if (mbi.RegionSize == 0) break;

                    if (mbi.State == MEM_FREE) {
                        SIZE_T sz = mbi.RegionSize;
                        if (scan + sz > XWA_EXTENDED_END) sz = XWA_EXTENDED_END - scan;
                        void* p = VirtualAlloc((void*)scan, sz,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                        if (p) committed += (uint32_t)sz;
                    } else if (mbi.State == MEM_RESERVE) {
                        /* Skip - belongs to another allocation (heap, etc.) */
                        reserved_skip++;
                        gaps++;
                        if (gaps <= 8) {
                            printf("    [reserved] 0x%08X-0x%08X type=0x%lX (skipped)\n",
                                (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                                mbi.Type);
                        }
                    } else if (mbi.State == MEM_COMMIT) {
                        /* Existing allocation - log it as a gap */
                        gaps++;
                        if (gaps <= 8) {
                            printf("    [gap] 0x%08X-0x%08X type=0x%lX prot=0x%lX\n",
                                (uint32_t)scan, (uint32_t)(scan + mbi.RegionSize),
                                mbi.Type, mbi.Protect);
                        }
                    }
                    scan += mbi.RegionSize;
                }
                printf("[*] Extended BSS: committed %u KB, %u gaps, %u reserved-skips (0x%08X-0x%08X)\n",
                       committed / 1024, gaps, reserved_skip, XWA_DATA_END, XWA_EXTENDED_END);
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
            /* Commit pages for the .text range so we can load embedded data
             * tables, jump tables, and string constants that recompiled code
             * references via MEM macros.  Our exe lives at 0x10000000, so the
             * 0x401000-0x5A9000 range is inside the old heap reservation but
             * may not be committed yet.  MEM_COMMIT within MEM_RESERVE is OK. */
            {
                void* text_pages = VirtualAlloc(
                    (void*)(uintptr_t)0x00401000,
                    0x5A9000 - 0x401000,     /* .text through end of gap before .rdata */
                    MEM_COMMIT, PAGE_READWRITE);
                if (text_pages) {
                    printf("[*] Committed .text data pages at 0x%p (0x%X bytes)\n",
                           text_pages, 0x5A9000 - 0x401000);
                } else {
                    fprintf(stderr, "WARNING: Failed to commit .text pages (err=%lu)\n",
                            GetLastError());
                }
            }

            /* Read .text (contains embedded data tables, jump tables, string
             * constants that the recompiled code still references via MEM macros).
             * .text: file offset 0x400, VA 0x401000, RawSize 0x1A7C00
             *
             * IMPORTANT: The Steam binary has SafeDisc encryption on large parts
             * of .text (roughly 0x599000-0x5A1000+). We try to load from a
             * decrypted binary first; fall back to the game binary. */
            {
                int text_loaded = 0;
                /* Try decrypted binary: same dir as game exe, or known paths */
                const char* dec_paths[] = {
                    "xwingalliance_decrypted.exe",
                    "../recomp/config/xwingalliance_decrypted.exe",
                    NULL
                };
                for (int i = 0; dec_paths[i]; i++) {
                    FILE* fd = fopen(dec_paths[i], "rb");
                    if (fd) {
                        fseek(fd, 0x00000400, SEEK_SET);
                        size_t n = fread((void*)ADDR(0x00401000), 1, 0x1A7C00, fd);
                        fclose(fd);
                        if (n == 0x1A7C00) {
                            printf("[*] Loaded .text from decrypted binary: %s\n", dec_paths[i]);
                            text_loaded = 1;
                            break;
                        }
                    }
                }
                if (!text_loaded) {
                    fprintf(stderr, "WARNING: Using encrypted .text from game binary"
                            " (jump tables may be garbage)\n");
                    fseek(f, 0x00000400, SEEK_SET);
                    fread((void*)ADDR(0x00401000), 1, 0x1A7C00, f);
                }
            }

            /* Read .rdata (VSize) */
            fseek(f, 0x001A8000, SEEK_SET);
            fread((void*)ADDR(0x005A9000), 1, 0x4A24, f);

            /* Read .data (RawSize only; rest is BSS, already zero from VirtualAlloc) */
            fseek(f, 0x001ACC00, SEEK_SET);
            fread((void*)ADDR(0x005AE000), 1, 0x60600, f);

            fclose(f);
            printf("[*] Loaded data sections from %s\n", data_file);

            /* Patch SafeDisc-encrypted CRT data tables in .text section.
             * These tables are used by sub_005A03B0 (_openfile/_sopen) for
             * parsing fopen mode strings ("r", "rb", "w+", etc.).
             *
             * Jump table at 0x5A050C: 10 entries mapping class index → handler VA.
             * Byte table at 0x5A0534: 74 entries mapping (char - '+') → class index.
             */
            {
                /* Jump table: class index → handler address */
                static const uint32_t jump_table[10] = {
                    0x005A049C,  /* [0] default: invalid character */
                    0x005A0427,  /* [1] '+': read+write mode */
                    0x005A043A,  /* [2] 'S': sequential access */
                    0x005A0444,  /* [3] 'R': random access */
                    0x005A044E,  /* [4] 'b': binary mode */
                    0x005A045F,  /* [5] 't': text mode */
                    0x005A0470,  /* [6] 'c': commit on flush */
                    0x005A047D,  /* [7] 'n': no commit */
                    0x005A048A,  /* [8] 'T': short-lived */
                    0x005A0494,  /* [9] 'D': temporary/delete-on-close */
                };
                memcpy((void*)ADDR(0x5A050C), jump_table, sizeof(jump_table));

                /* Byte table: (char - 0x2B) → class index (0 = default/invalid) */
                uint8_t byte_table[74];
                memset(byte_table, 0, sizeof(byte_table));
                byte_table['+' - 0x2B] = 1;  /* offset 0  */
                byte_table['D' - 0x2B] = 9;  /* offset 25 */
                byte_table['R' - 0x2B] = 3;  /* offset 39 */
                byte_table['S' - 0x2B] = 2;  /* offset 40 */
                byte_table['T' - 0x2B] = 8;  /* offset 41 */
                byte_table['b' - 0x2B] = 4;  /* offset 55 */
                byte_table['c' - 0x2B] = 6;  /* offset 56 */
                byte_table['n' - 0x2B] = 7;  /* offset 67 */
                byte_table['t' - 0x2B] = 5;  /* offset 73 */
                memcpy((void*)ADDR(0x5A0534), byte_table, sizeof(byte_table));

                printf("[*] Patched SafeDisc-encrypted CRT tables at 0x5A050C, 0x5A0534\n");
            }

            /* Patch WndProc address in sub_0053EB30's code data.
             * Instruction at 0x0053EB47: mov [esp+0x18], 0x0053E650
             * The 4-byte immediate 0x0053E650 is at VA 0x0053EB4B.
             * Replace with address of our native WndProc bridge so
             * Windows can call it directly (our .text pages aren't executable). */
            {
                extern LRESULT CALLBACK native_wndproc_bridge(HWND, UINT, WPARAM, LPARAM);
                uint32_t bridge_addr = (uint32_t)(uintptr_t)&native_wndproc_bridge;
                MEM32(0x0053EB4B) = bridge_addr;
                printf("[*] Patched WndProc: 0x0053E650 -> 0x%08X (native bridge)\n", bridge_addr);
            }
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

/* Dump ICALL trace on exit */
static void dump_trace_atexit(void) {
    /* Write trace to file using raw Win32 API (reliable even in exit context) */
    HANDLE h = CreateFileA("D:\\recomp\\pc\\xwa\\xwa_atexit.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[256];
        DWORD written;
        int len = snprintf(buf, sizeof(buf),
            "=== ATEXIT TRACE DUMP ===\r\n"
            "Total calls: %u, icalls: %u, depth: %u (max: %u)\r\n"
            "trace_ring_idx: %u\r\n"
            "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n\r\n",
            g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
            g_trace_ring_idx,
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi);
        WriteFile(h, buf, len, &written, NULL);

        len = snprintf(buf, sizeof(buf), "=== Trace Ring ===\r\n");
        WriteFile(h, buf, len, &written, NULL);
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                WriteFile(h, buf, len, &written, NULL);
            }
        }

        len = snprintf(buf, sizeof(buf), "\r\n=== ICALL Trace ===\r\n");
        WriteFile(h, buf, len, &written, NULL);
        for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
            uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx2]) {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", i, g_icall_trace[idx2]);
                WriteFile(h, buf, len, &written, NULL);
            }
        }
        CloseHandle(h);
    }

    fprintf(stderr, "\n=== EXIT TRACE DUMP ===\n");
    fprintf(stderr, "Total ICALLs: %u, call depth: %u (max %u)\n",
            g_icall_count, g_call_depth, g_call_depth_max);
    fprintf(stderr, "ICALL trace (last %d):\n", ICALL_TRACE_SIZE);
    for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
        int idx = (g_icall_trace_idx + i) & (ICALL_TRACE_SIZE - 1);
        if (g_icall_trace[idx])
            fprintf(stderr, "  [%2d] 0x%08X\n", i, g_icall_trace[idx]);
    }
    fprintf(stderr, "ESP: 0x%08X (initial: 0x%08X)\n", g_esp, g_esp_initial);
    fflush(stderr);
}

/* Watchdog thread: dumps trace to file using raw Win32 API, then terminates */
static DWORD WINAPI watchdog_thread(LPVOID param) {
    DWORD timeout_ms = (DWORD)(uintptr_t)param;
    Sleep(timeout_ms);

    /* Use raw Win32 CreateFile to avoid CRT locking issues */
    HANDLE hFile = CreateFileA("D:\\recomp\\pc\\xwa\\xwa_watchdog.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[512];
        DWORD written;
        int len;

        len = snprintf(buf, sizeof(buf),
            "=== Watchdog dump after %u ms ===\r\n"
            "Total calls: %u, total icalls: %u, call_depth: %u (max: %u)\r\n"
            "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
            "trace_ring_idx=%u\r\n\r\n",
            timeout_ms,
            g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
            g_trace_ring_idx);
        WriteFile(hFile, buf, len, &written, NULL);

        /* Dump trace ring */
        len = snprintf(buf, sizeof(buf), "=== Trace Ring (last %d) ===\r\n", TRACE_RING_SIZE);
        WriteFile(hFile, buf, len, &written, NULL);
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                WriteFile(hFile, buf, len, &written, NULL);
            }
        }

        /* Dump ICALL trace */
        len = snprintf(buf, sizeof(buf), "\r\n=== ICALL Trace (last %d) ===\r\n", ICALL_TRACE_SIZE);
        WriteFile(hFile, buf, len, &written, NULL);
        for (int i = 0; i < ICALL_TRACE_SIZE; i++) {
            uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + i) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx2]) {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", i, g_icall_trace[idx2]);
                WriteFile(hFile, buf, len, &written, NULL);
            }
        }
        len = snprintf(buf, sizeof(buf), "Total indirect calls: %u\r\n", g_icall_count);
        WriteFile(hFile, buf, len, &written, NULL);

        CloseHandle(hFile);
    }

    /* TerminateProcess bypasses loader lock, unlike ExitProcess */
    TerminateProcess(GetCurrentProcess(), 42);
    return 0;
}

/* Forward declaration of the recompiled game entry points */
extern void sub_0050A4A0(void);  /* WinMain */
extern void sub_0059CD60(void);  /* CRT startup (calls WinMain internally) */

/* Import bridge registration (generated by gen_bridges.py) */
extern void register_import_bridges(void);

/* ============================================================
 * NtTerminateProcess Inline Hook
 *
 * Catches ALL process termination paths:
 *  - Our ExitProcess bridge (via TerminateProcess -> NtTerminateProcess)
 *  - Real ExitProcess calls from DLLs
 *  - Heap corruption handler (RtlReportCriticalFailure -> NtTerminateProcess)
 *  - Any other termination path
 *
 * Dumps the native callstack + recomp trace ring to a file.
 * ============================================================ */

typedef long NTSTATUS_T;
typedef NTSTATUS_T (NTAPI *PFN_NtTerminateProcess)(HANDLE, NTSTATUS_T);
static PFN_NtTerminateProcess g_real_NtTerminateProcess = NULL;
static uint8_t g_nttp_orig_bytes[16];
static volatile LONG g_terminate_hook_entered = 0;

/* Flag set by our ExitProcess bridge so hook knows it's a "known" exit */
volatile int g_exit_via_bridge = 0;

static void NTAPI hook_NtTerminateProcess(HANDLE hProcess, NTSTATUS_T exitStatus) {
    /* Signal on stderr FIRST (before any file I/O) */
    fprintf(stderr, "\n!!! NtTerminateProcess HOOKED: handle=0x%X status=0x%08X bridge=%d !!!\n",
        (uint32_t)(uintptr_t)hProcess, (uint32_t)exitStatus, g_exit_via_bridge);
    fflush(stderr);

    /* Prevent re-entrancy */
    if (InterlockedExchange(&g_terminate_hook_entered, 1)) {
        /* Re-entrant: restore original and call directly */
        DWORD oldProt;
        VirtualProtect((void*)g_real_NtTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProt);
        memcpy((void*)g_real_NtTerminateProcess, g_nttp_orig_bytes, 8);
        VirtualProtect((void*)g_real_NtTerminateProcess, 16, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), (void*)g_real_NtTerminateProcess, 16);
        g_real_NtTerminateProcess(hProcess, exitStatus);
        return;
    }

    /* Capture native call stack */
    void* bt[48];
    WORD nframes = CaptureStackBackTrace(0, 48, bt, NULL);

    /* Write diagnostics to file using raw Win32 API */
    HANDLE h = CreateFileA("D:\\recomp\\pc\\xwa\\xwa_terminate.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[512];
        int len;

        len = snprintf(buf, sizeof(buf),
            "=== NtTerminateProcess Hook ===\r\n"
            "Exit status: 0x%08X (%d)\r\n"
            "Handle: 0x%08X\r\n"
            "Via bridge: %s\r\n\r\n",
            (uint32_t)exitStatus, (int)exitStatus,
            (uint32_t)(uintptr_t)hProcess,
            g_exit_via_bridge ? "YES (known exit)" : "NO (unknown/unexpected)");
        wf(h, buf);

        /* Native call stack with module resolution */
        wf(h, "=== Native Call Stack ===\r\n");
        for (int i = 0; i < nframes; i++) {
            HMODULE hMod = NULL;
            char modName[260];
            if (GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCSTR)bt[i], &hMod)) {
                GetModuleFileNameA(hMod, modName, sizeof(modName));
                /* Extract just filename */
                char* slash = strrchr(modName, '\\');
                char* name = slash ? slash + 1 : modName;
                uint32_t offset = (uint32_t)((uint8_t*)bt[i] - (uint8_t*)hMod);
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%p  %s + 0x%X\r\n",
                    i, bt[i], name, offset);
            } else {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%p  (unknown module)\r\n",
                    i, bt[i]);
            }
            wf(h, buf);
        }

        /* Recomp register state */
        len = snprintf(buf, sizeof(buf),
            "\r\n=== Recomp State ===\r\n"
            "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
            "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
            "Total calls: %u, icalls: %u, depth: %u (max: %u)\r\n"
            "trace_ring_idx: %u\r\n\r\n",
            g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
            g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
            g_trace_ring_idx);
        wf(h, buf);

        /* Trace ring */
        wf(h, "=== Trace Ring ===\r\n");
        uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE)
            ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
        for (uint32_t i = start; i < g_trace_ring_idx; i++) {
            uint32_t idx = i & (TRACE_RING_SIZE - 1);
            if (g_trace_ring[idx][0]) {
                len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                wf(h, buf);
            }
        }

        /* ICALL trace */
        wf(h, "\r\n=== ICALL Trace ===\r\n");
        for (int j = 0; j < ICALL_TRACE_SIZE; j++) {
            uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + j) & (ICALL_TRACE_SIZE - 1);
            if (g_icall_trace[idx2]) {
                len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", j, g_icall_trace[idx2]);
                wf(h, buf);
            }
        }
        len = snprintf(buf, sizeof(buf), "Total indirect calls: %u\r\n", g_icall_count);
        wf(h, buf);

        CloseHandle(h);
    }

    /* Restore original bytes and call real NtTerminateProcess */
    DWORD oldProt;
    VirtualProtect((void*)g_real_NtTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy((void*)g_real_NtTerminateProcess, g_nttp_orig_bytes, 8);
    VirtualProtect((void*)g_real_NtTerminateProcess, 16, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)g_real_NtTerminateProcess, 16);

    g_real_NtTerminateProcess(hProcess, exitStatus);
}

static void install_terminate_hook(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    g_real_NtTerminateProcess = (PFN_NtTerminateProcess)
        GetProcAddress(ntdll, "NtTerminateProcess");
    if (!g_real_NtTerminateProcess) return;

    /* Save original bytes */
    memcpy(g_nttp_orig_bytes, (void*)g_real_NtTerminateProcess, 16);

    /* Overwrite first 5 bytes with JMP rel32 to our hook */
    DWORD oldProt;
    VirtualProtect((void*)g_real_NtTerminateProcess, 16, PAGE_EXECUTE_READWRITE, &oldProt);

    uint8_t* p = (uint8_t*)g_real_NtTerminateProcess;
    p[0] = 0xE9; /* JMP rel32 */
    uint32_t target = (uint32_t)(uintptr_t)&hook_NtTerminateProcess;
    uint32_t src = (uint32_t)(uintptr_t)p + 5;
    *(uint32_t*)(p + 1) = target - src;

    VirtualProtect((void*)g_real_NtTerminateProcess, 16, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), (void*)g_real_NtTerminateProcess, 16);

    printf("[*] NtTerminateProcess hook installed at %p\n", (void*)g_real_NtTerminateProcess);
}

FILE* g_trace_file = NULL;
char g_trace_ring[TRACE_RING_SIZE][TRACE_ENTRY_SIZE] = {{0}};
uint32_t g_trace_ring_idx = 0;

int main(int argc, char* argv[]) {
    setvbuf(stderr, NULL, _IONBF, 0); /* Force unbuffered stderr */
    /* Trace ring buffer is in-memory, dumped by watchdog thread */
    printf("=== X-Wing Alliance Static Recompilation ===\n");
    printf("=== Phase 2: Recompilation Infrastructure  ===\n\n");

    /* Default path to original binary for data loading */
    const char* data_file = NULL;
    if (argc > 1) {
        data_file = argv[1];
    }

    /* Install NtTerminateProcess hook FIRST (catches all exit paths) */
    install_terminate_hook();

    /* Install VEH crash handler */
    AddVectoredExceptionHandler(1, veh_handler);

    /* Install UEF (Unhandled Exception Filter) as backup crash catcher */
    SetUnhandledExceptionFilter(veh_handler);

    printf("[*] VEH + UEF crash handler installed\n");

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
    printf("    Data:   VA 0x%08X - 0x%08X (extended to 0x%08X)\n",
           XWA_DATA_START, XWA_DATA_END, XWA_EXTENDED_END);
    printf("    Offset: %lld\n", (long long)g_mem_base);

    /* Register import bridges (maps IAT slots to bridge functions) */
    register_import_bridges();

    /* Initialize COM mock interfaces (DirectDraw, Direct3D, DirectInput, DirectSound) */
    {
        extern void com_mocks_init(void);
        com_mocks_init();
    }

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

    /* Note: DirectDraw/rendering function pointers in BSS (e.g. 0x80DB6C,
     * 0x7FFD70) are NULL until DirectX init. RECOMP_ICALL(0) handles this
     * as a no-op that returns 0 in eax. */

    printf("[*] Launching CRT startup (sub_0059CD60)...\n");
    printf("    (will call WinMain internally after CRT init)\n");
    fflush(stdout);

    /* Register trace dump for when program exits */
    atexit(dump_trace_atexit);

    /* FLS callback: called during process exit even if atexit doesn't run.
     * This catches exit paths that bypass our ExitProcess bridge. */
    {
        DWORD flsIdx = FlsAlloc(NULL);
        if (flsIdx != FLS_OUT_OF_INDEXES) {
            /* Store a sentinel value so the FLS slot is "active" */
            FlsSetValue(flsIdx, (PVOID)1);
        }
    }

    /* Register a _onexit callback (MSVC-specific, runs during _exit too) */
    _onexit((_onexit_t)dump_trace_atexit);

    /* Start watchdog timer (10 seconds) */
    CreateThread(NULL, 0, watchdog_thread, (LPVOID)10000, 0, NULL);

    /* Call the CRT entry point (WinMainCRTStartup / mainCRTStartup).
     * This handles all CRT initialization: _heap_init, _mtinit, _ioinit,
     * __initterm, then calls WinMain(GetModuleHandle(0), 0, GetCommandLineA(), SW_SHOWDEFAULT).
     * It may call ExitProcess() instead of returning. */
    fprintf(stderr, "[*] About to call sub_0059CD60 (CRT startup)...\n");
    fflush(stderr);
    PUSH32(g_esp, 0xDEAD0000u);        /* dummy return address */

    /* Wrap in SEH to catch crashes that VEH might miss */
    {
        DWORD seh_code = 0;
        __try {
            sub_0059CD60();
        } __except((seh_code = GetExceptionCode()), EXCEPTION_EXECUTE_HANDLER) {
            /* Dump trace ring on any unhandled exception */
            char buf[512];
            DWORD written;
            HANDLE h = CreateFileA("D:\\recomp\\pc\\xwa\\xwa_seh_crash.log",
                GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                int len = snprintf(buf, sizeof(buf),
                    "=== SEH CRASH: Exception 0x%08lX ===\r\n"
                    "Total calls: %u, icalls: %u, depth: %u (max: %u)\r\n"
                    "EAX=0x%08X ECX=0x%08X EDX=0x%08X EBX=0x%08X\r\n"
                    "ESP=0x%08X ESI=0x%08X EDI=0x%08X\r\n"
                    "trace_ring_idx: %u\r\n\r\n",
                    seh_code, g_total_calls, g_total_icalls, g_call_depth, g_call_depth_max,
                    g_eax, g_ecx, g_edx, g_ebx, g_esp, g_esi, g_edi,
                    g_trace_ring_idx);
                WriteFile(h, buf, len, &written, NULL);

                wf(h, "=== Trace Ring ===\r\n");
                uint32_t start = (g_trace_ring_idx >= TRACE_RING_SIZE) ? (g_trace_ring_idx - TRACE_RING_SIZE) : 0;
                for (uint32_t i = start; i < g_trace_ring_idx; i++) {
                    uint32_t idx = i & (TRACE_RING_SIZE - 1);
                    if (g_trace_ring[idx][0]) {
                        len = snprintf(buf, sizeof(buf), "  %s", g_trace_ring[idx]);
                        WriteFile(h, buf, len, &written, NULL);
                    }
                }

                wf(h, "\r\n=== ICALL Trace ===\r\n");
                for (int j = 0; j < ICALL_TRACE_SIZE; j++) {
                    uint32_t idx2 = (g_icall_trace_idx - ICALL_TRACE_SIZE + j) & (ICALL_TRACE_SIZE - 1);
                    if (g_icall_trace[idx2]) {
                        len = snprintf(buf, sizeof(buf), "  [%2d] 0x%08X\r\n", j, g_icall_trace[idx2]);
                        WriteFile(h, buf, len, &written, NULL);
                    }
                }
                CloseHandle(h);
            }
            fprintf(stderr, "\n!!! SEH CRASH: Exception 0x%08lX\n", seh_code);
            fprintf(stderr, "Total calls: %u, depth: %u, trace_idx: %u\n",
                    g_total_calls, g_call_depth, g_trace_ring_idx);
            fflush(stderr);
        }
    }

    fprintf(stderr, "[*] sub_0059CD60 returned! eax = 0x%08X\n", g_eax);
    fflush(stderr);
    printf("[*] WinMain returned (eax = 0x%08X)\n", g_eax);

    cleanup_memory();
    return 0;
}
