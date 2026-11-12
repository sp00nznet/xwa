/* music: the CD audio, played from Music\TrackNN.ogg (music.c). */
#include <windows.h>
#include <mmsystem.h>
MCIERROR music_mci(MCIDEVICEID dev, UINT msg, DWORD_PTR flags, DWORD_PTR parms);
void music_volume(DWORD v);
