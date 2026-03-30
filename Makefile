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


