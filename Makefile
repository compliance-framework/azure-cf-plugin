# Variables
GO=go

.PHONY: help build test clean fmt vet lint build-images run-docker build-plugin run-local protoc graph

help:  ## Display this help message
	@echo "Help for Makefile: $(MAKEFILE_LIST) in $(dir $(abspath $(lastword $(MAKEFILE_LIST))))"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build-image: build-plugin
	docker build .

build-plugin: go-setup  ## Build plugins and copy the configuration
	@echo "Preparing local environment..."
	@$(GO) build -o plugin main.go
	chmod +x plugin

go-setup:        ## Setup/update go environment
	go mod tidy
