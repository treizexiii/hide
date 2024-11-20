UNAME_S := $(shell uname -s)

build:
	cargo build --release

install: build
ifeq ($(UNAME_S), Linux)
	@echo "Installing on Linux"
	cp target/release/hide ~/.local/bin
else ifeq ($(OS), Windows_NT)
	@echo "Installing on Windows..."
	cp target/release/hide $(USERPROFILE)/.local/bin
endif

uninstall:
ifeq ($(UNAME_S), Linux)
	sudo rm /usr/bin/hide
else ifeq ($(OS), Windows_NT)
	rm $(USERPROFILE)/.local/bin/hide.exe
endif
