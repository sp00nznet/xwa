/* settings: the remaster's options and the keys for them (settings.c). */
#pragma once
#include <windows.h>

extern int g_flight_mouse, g_flight_pad, g_mods, g_hw3d;
void settings_apply_prefs(void);   /* the game's display mode in foption.cfg (cwd = game folder) */

void settings_load(void);
void settings_save(void);
void settings_menu(HWND w, int x, int y);
/* F10, F11, F12, Alt+Enter: 1 if it was one of ours. */
int  settings_key(HWND w, UINT vk, int alt);
