/*
 * flight: the joystick X-Wing insists on, from what a player has today.
 *
 * With a real joystick plugged in, it is used as it is (host.c). Otherwise
 * the virtual one the game sees is driven by, in order:
 *
 *   an Xbox pad     left stick: pitch and roll/yaw; right stick X: rudder;
 *                   A fire, B button 2, X button 3, Y button 4;
 *                   right trigger fires too
 *   the mouse       in flight (the 3D is on screen) and the window in front:
 *                   distance from the picture's centre is the stick,
 *                   left button fire, right button button 2
 *   the arrow keys  full deflection while held
 *
 * Mouse and pad each have a switch in the settings menu (F10).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <xinput.h>
#include <math.h>
#include <stdlib.h>

#include "gpu.h"
#include "settings.h"
#include "flight.h"

static int pad_axis(SHORT v, int dead) {
    int a = v < 0 ? -(int)v : v;
    if (a < dead) return 0;
    int s = (a - dead) * 32767 / (32767 - dead);
    return v < 0 ? -s : s;
}

/* -32767..32767 per axis -> the 0..65535 joyGetPosEx reports, centred */
static DWORD axis(int v) {
    if (v < -32767) v = -32767;
    if (v > 32767) v = 32767;
    return (DWORD)(v + 32768);
}

static volatile LONG g_sx, g_sy, g_sbuttons;   /* a --keys script's stick */
void flight_script(int x, int y, int buttons) {
    InterlockedExchange(&g_sx, x * 32767 / 100);
    InterlockedExchange(&g_sy, y * 32767 / 100);
    InterlockedExchange(&g_sbuttons, buttons);
}

void flight_joystick(HWND game, int scripted, JOYINFOEX* j) {
    int x = scripted ? g_sx : 0, y = scripted ? g_sy : 0, r = 0;
    DWORD buttons = scripted ? (DWORD)g_sbuttons : 0;
    if (!scripted) {
        XINPUT_STATE xs;
        if (g_flight_pad && XInputGetState(0, &xs) == ERROR_SUCCESS) {
            XINPUT_GAMEPAD* p = &xs.Gamepad;
            x = pad_axis(p->sThumbLX, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
            y = -pad_axis(p->sThumbLY, XINPUT_GAMEPAD_LEFT_THUMB_DEADZONE);
            r = pad_axis(p->sThumbRX, XINPUT_GAMEPAD_RIGHT_THUMB_DEADZONE);
            if (p->wButtons & XINPUT_GAMEPAD_A || p->bRightTrigger > 100) buttons |= JOY_BUTTON1;
            if (p->wButtons & XINPUT_GAMEPAD_B) buttons |= JOY_BUTTON2;
            if (p->wButtons & XINPUT_GAMEPAD_X) buttons |= JOY_BUTTON3;
            if (p->wButtons & XINPUT_GAMEPAD_Y) buttons |= JOY_BUTTON4;
        } else if (game && GetForegroundWindow() == game) {
            if (g_flight_mouse && gpu_in_flight()) {
                POINT c;
                GetCursorPos(&c);
                ScreenToClient(game, &c);
                gpu_to_game(&c);
                /* a quarter of the picture's height from the centre is full deflection */
                x = (c.x - 320) * 32767 / 120;
                y = (c.y - 240) * 32767 / 120;
                if (abs(x) < 1500) x = 0;
                if (abs(y) < 1500) y = 0;
                if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) buttons |= JOY_BUTTON1;
                if (GetAsyncKeyState(VK_RBUTTON) & 0x8000) buttons |= JOY_BUTTON2;
            }
            if (GetAsyncKeyState(VK_LEFT) & 0x8000) x = -32767;
            if (GetAsyncKeyState(VK_RIGHT) & 0x8000) x = 32767;
            if (GetAsyncKeyState(VK_UP) & 0x8000) y = -32767;
            if (GetAsyncKeyState(VK_DOWN) & 0x8000) y = 32767;
        }
    }
    j->dwXpos = axis(x);
    j->dwYpos = axis(y);
    j->dwRpos = axis(r);
    j->dwZpos = 0x7FFF;
    j->dwButtons = buttons;
    j->dwButtonNumber = (buttons & 1) + (buttons >> 1 & 1) + (buttons >> 2 & 1) + (buttons >> 3 & 1);
    j->dwPOV = JOY_POVCENTERED;
}
