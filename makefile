
build:
	cargo build --release

install: build
	sudo cp target/release/hide /usr/bin

uninstall:
	sudo rm /usr/bin/hide
