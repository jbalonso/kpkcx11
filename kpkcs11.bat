@echo off

if exist i386_nt35 rmdir /s /q i386_nt35 >nul
mkdir i386_nt35

cd i386_nt35

rem if this fails because it "already exists" but is "not" already there,
rem it's probably because you're running something that is referencing
rem it (like Visual C++ ...)

mkdir kpkcs11
copy ..\src\kpkcs11.dsw kpkcs11 >nul

set o=X:\openssl-0.9.6
rem set o=H:\b\openssl-0.9.6

perl ..\src\configure.win32 --openssldir=%o%

cd ..
