VERSION ?=
SOURCE_DATE_EPOCH ?=

.PHONY: release container container-smoke test-race fuzz-smoke

release:
	VERSION="$(VERSION)" SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" ./scripts/release.sh

container:
	VERSION="$(VERSION)" SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" ./scripts/container-build.sh

container-smoke:
	VERSION="$(VERSION)" SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" ./scripts/container-build.sh --run

test-race:
	go test -race ./...

fuzz-smoke:
	./scripts/fuzz-smoke.sh
