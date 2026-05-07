CONTAINER_ENGINE ?= docker

IMAGE := "ghcr.io/cilium/ebpf-builder"
VERSION := "1777990914"

CLANG ?= clang-22

FLAGS :=
# -g to enable DWARF + BTF
FLAGS += -g
# -O2 to enable optimization needed for BPF
FLAGS += -O2
# -target bpf to specify the BPF target
FLAGS += -target bpf

.PHONY: docker
docker:
	$(CONTAINER_ENGINE) run --rm -v $(shell pwd):/src -w /src $(IMAGE):$(VERSION) make all

TARGETS := \
	basic

.PHONY: all
all: $(addsuffix .o,$(TARGETS))

%.o: %.c
	$(CLANG) $(FLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o
