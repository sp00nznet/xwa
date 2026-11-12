/* sound: counts of what the game's DirectSound does (sound.c). */
#pragma once
extern int g_sound_log;
void sound_watch(void* direct_sound);   /* after DirectSoundCreate */
void sound_report(void);                /* one line of counts */
