GO_MODULE := $(shell git config --get remote.origin.url | grep -o 'github\.com[:/][^.]*' | tr ':' '/')
CMD_NAME := $(shell basename ${GO_MODULE})
DEFAULT_APP_PORT ?= 8080

RUN ?= .*
PKG ?= ./...
.PHONY: test
test: ## Run tests in local environment
	golangci-lint run --timeout=5m $(PKG)
	go test -cover -run=$(RUN) $(PKG)

.PHONY: docker
docker: ## Build local development docker image with cached go modules, builds, and tests
	@docker build -t $(CMD_NAME):latest .

.PHONY: docker-snyk
docker-snyk: ## Run local snyk scan, SNYK_TOKEN environment variable must be set
	@docker run --rm -e SNYK_TOKEN -w /go/src/$(GO_MODULE) -v $(shell pwd):/go/src/$(GO_MODULE):delegated snyk/snyk:golang

.PHONY: docker-run
docker-run: ## Build and run the application in a local docker container
docker-run: docker
	@docker run -p $(DEFAULT_APP_PORT):$(DEFAULT_APP_PORT) \
		-v $(HOME)/.minikube/ca.crt:/test-files/ca.crt \
		-v $(PWD)/internal/server/testdata/session-secret:/etc/session-secret \
		-v $(PWD)/internal/server/testdata/client-secret:/etc/client-secret \
		$(CMD_NAME):latest \
		--cluster-ca-filepath /test-files/ca.crt \
		--session-secret-filepath /etc/session-secret \
		--kubectl-client-secret-filepath /etc/client-secret

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
