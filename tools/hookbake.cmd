@echo off
rem Build tools\hookbake.c (32-bit) into work\hookbake.exe.
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set "VS=%%i"
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul || exit /b 1
cd /d "%~dp0.."
cl /nologo /O1 /Fe:work\hookbake.exe /Fo:work\ tools\hookbake.c /link /BASE:0x60000000 /DYNAMICBASE:NO /STACK:0x40000
