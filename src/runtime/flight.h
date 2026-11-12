/* flight: the virtual joystick from a pad, the mouse or the arrow keys (flight.c). */
#pragma once
#include <windows.h>
#include <mmsystem.h>

void flight_joystick(HWND game, int scripted, JOYINFOEX* j);
/* --keys "N:stick:X:Y" (-100..100) and "N:fire" / "N:nofire" */
void flight_script(int x, int y, int buttons);
