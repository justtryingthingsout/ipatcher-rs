dylib-path := $(shell pwd)/patchfinder64/

all:
ifeq (,$(wildcard ./patchfinder64/libpatchfinder.dylib))
	dylib
endif
	@echo Building program with cargo
	@cargo build
	@install_name_tool -change libpatchfinder.dylib $(dylib-path)/libpatchfinder.dylib target/debug/ipatcher-rs #fix for dylib being cached(?)
	@echo [*] Built iPatcher-rust, run it using 'target/debug/ipatcher-rs'
dylib:
	@echo Making dylib
	@sed -i.c -e 's/static addr_t\nbof64/addr_t bof64/' -e 's/static addr_t\nxref64/addr_t xref/' patchfinder64/patchfinder64.c
	@cd patchfinder64 && gcc -Wall -c patchfinder64.c.c
	@cd patchfinder64 && gcc -dynamiclib -undefined suppress -flat_namespace patchfinder64.c.o -o libpatchfinder.dylib
	@rm patchfinder64/patchfinder64.c.o patchfinder64/patchfinder64.c.c