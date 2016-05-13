PROJECT = github.com/chromium/hstspreload/...

.PHONY: test
test: lint
	go test -cover ${PROJECT}

.PHONY: test-verbose
test-verbose: lint
	go test -v -cover ${PROJECT}

.PHONY: build
build:
	go build ${PROJECT}

.PHONY: lint
lint:
	go vet ${PROJECT}
	golint -set_exit_status ${PROJECT}

.PHONY: pre-commit
pre-commit: lint build test

.PHONY: travis
travis: lint build test-verbose
