PYTHON := python3
DIST_DIR := dist
RELEASE_DIR := release
VERSION ?= dev

.PHONY: serve build clean package

serve:
	npx serve $(DIST_DIR)

build:
	$(PYTHON) script/catalog.py
	$(PYTHON) script/normalize.py --catalog $(DIST_DIR)/catalog.json

clean:
	rm -rf $(DIST_DIR) $(RELEASE_DIR)

package: build
	rm -rf $(RELEASE_DIR)
	mkdir -p $(RELEASE_DIR)

	7z a \
		-t7z \
		-mx=1 \
		-v1900m \
		$(RELEASE_DIR)/samples-$(VERSION).7z \
		$(DIST_DIR)/*

	cd $(RELEASE_DIR) && sha256sum * > SHA256SUMS