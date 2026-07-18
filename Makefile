.PHONY: modules serve build clean package

modules:
	./script/setup-modules.sh

build:
	python3 script/catalog.py
	python3 script/normalize.py --catalog dist/catalog.json

package: modules build
	rm -rf release
	mkdir -p release
	7z a -t7z -mx=1 -v1900m \
		release/samples-$(VERSION).7z \
		dist/*
	cd release && sha256sum * > SHA256SUMS