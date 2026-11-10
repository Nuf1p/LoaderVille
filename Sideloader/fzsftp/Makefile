CC_X64          := x86_64-w64-mingw32-gcc
OUT_X64         := loader.dll

all:
	@ echo "[*] Building default DLL Reflective Loader..."
	@ x86_64-w64-mingw32-windres resource.rc -O coff -o resource.o
	@ $(CC_X64) SideeLoader.c resource.o -masm=intel -Wl,-e,DllMain -shared -Wl,-Bstatic -Wl,-s -w -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -Wl,-Bstatic -O0 -DWIN -o $(OUT_X64)
	@ echo "[+] Done"

clean:
	@ rm -r *.exe 
	@ rm -f *.dll 
	@ rm -f *.bin
