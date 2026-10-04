@echo off
rem netlab RUN for XWA: the campaign mission load of tools/run_engine_flight.sh, on a Windows
rem test machine without Git Bash.  Usage: netlab_run.cmd <xwa_recomp.exe> <game dir> [knobs.cmd]
rem The game dir is the install with xwingalliance_decrypted.exe copied into it; the game needs it
rem as its working directory. Extra "set XWA_...=" lines for one experiment go in xwa_knobs.cmd in
rem the game dir (or a .cmd passed as the third argument); both are optional.
setlocal
set EXE=%~f1
cd /d "%~2" || exit /b 2
set XWA_BARRSEL=4& set XWA_NONAV=1& set XWA_AUTOPILOT=1& set XWA_PILOT=Test& set XWA_FLYDEMO=1
set XWA_DPSP=1& set XWA_DPOBJ=1& set XWA_ROGUARD=1& set XWA_NAMEGUARD=1& set XWA_STRGUARD=1
set XWA_NATIVEDRAW=1& set XWA_ALLOBJ=1& set XWA_TBLGUARD=1& set XWA_MKCTX=1& set XWA_WATCHDOG_MS=0
set XWA_RENDERFN=1& set XWA_RUNSCENE=1& set XWA_KEEP3D=1& set XWA_3DFLAG=1& set XWA_ZEROFILL=1
set XWA_FGFILL=1& set XWA_RTDUMP=25& set XWA_NOLST=1& set XWA_NATIVESCANF=1& set XWA_D3DCAPS=1
set XWA_RENDERINIT=1& set XWA_PUMPFIX=1& set XWA_WAITEXIT=1& set XWA_WAITAFTER=150
if exist xwa_knobs.cmd call xwa_knobs.cmd
if not "%~3"=="" call "%~f3"
"%EXE%" xwingalliance_decrypted.exe
