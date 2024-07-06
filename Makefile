# Variables
GO=go

.PHONY: help build test clean fmt vet lint build-images run-docker build-plugin run-local protoc graph

help:  ## Display this help message
	@echo "Help for Makefile: $(MAKEFILE_LIST) in $(dir $(abspath $(lastword $(MAKEFILE_LIST))))"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build-plugin:  ## Build plugins and copy the configuration
	@echo "Preparing local environment..."
	mkdir -p bin/plugins/azurecli/1.0.0
	@$(GO) build -o bin/plugins/azurecli/1.0.0/azurecli ./test/plugins/azurecli.go
	chmod +x bin/plugins/azurecli/1.0.0/azurecli
