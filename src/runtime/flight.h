/* flight: the virtual joystick from a pad, the mouse or the arrow keys (flight.c). */
#pragma once
#include <windows.h>
#include <mmsystem.h>

void flight_joystick(HWND game, int scripted, JOYINFOEX* j);
/* --keys "N:stick:X:Y" (-100..100) and "N:fire" / "N:nofire" */
void flight_script(int x, int y, int buttons);

/* Autopilot for test scripts: steer the scripted stick at the game's target.
 * The game supplies where its target is from the ship (flight_target_fn):
 * right, up and forward, any unit; 0 when there is no target. mode: 0 off,
 * 1 steer, 2 steer and fire when lined up. ponytail: P-control, no roll. */
typedef int (*flight_target_fn)(float* right, float* up, float* fwd);
void flight_aim(flight_target_fn f, int mode);
