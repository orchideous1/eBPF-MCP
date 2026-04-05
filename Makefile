# 编译项目
# 编译输出到 exe/ebpf-mcp
.PHONY: build
build:
	@echo "Building ebpf-mcp..."
	@mkdir -p exe
	go build -o exe/ebpf-mcp .
	@echo "Build complete: exe/ebpf-mcp"

# 运行项目（STDIO模式，默认）
.PHONY: run
run: build
	sudo -E ./exe/ebpf-mcp

# 运行项目（HTTP模式）
.PHONY: run-http
run-http: build
	sudo -E ./exe/ebpf-mcp -transport http -port 8080

# 默认对所有探针执行 go generate
# 使用方式: make generate [endpoint=<endpoint>]
generate:
ifeq ($(endpoint),)
	@echo "Generating eBPF code for all probes..."
	@find ebpf -name 'probe.go' -exec dirname {} \; | while read dir; do \
		echo "Generating in $$dir..."; \
		(cd $$dir && go generate); \
	done
else
	@echo "Generating eBPF code for endpoint: $(endpoint)"
	@find ebpf -type d -name '$(endpoint)' | while read dir; do \
		if [ -f "$$dir/probe.go" ]; then \
			echo "Generating in $$dir..."; \
			(cd $$dir && go generate); \
		else \
			echo "Warning: $$dir/probe.go not found"; \
		fi; \
	done
endif

test:
	go test ./...

test-nfs-e2e:
	sudo -E go test -count=1 ./test/integration -run TestNFSProbeLoadAndDuckDBIngestionE2E -v

test-race:
	go test -race ./...

vet:
	go vet ./...

clean-testcache:
	go clean -testcache

clean-log:
	rm -rf ./log/**

clean-result:
	rm -rf ./database/**

# clean: clean-all: clean-log clean-result

# 清理编译产物
.PHONY: clean
clean:
	@rm -rf exe/
	@go clean
	@echo "Clean complete"


