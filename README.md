# Stackwhere

Where is the stack usage of my BPF program coming from? 

In BPF, every byte of stack usage counts, the verifier limits us to 512 bytes of stack per BPF program or 256 bytes when combining tail calls and BPF-to-BPF functions. You cannot always tell which variables in your sources contribute to stack usage due to compiler optimizations. `stackwhere` uses DWARF debug info to get information about stack usage from the actual ELF file.

## Installation

### Release binary

1. Go to https://github.com/cilium/stackwhere/releases and find the latest stable release.
2. Download the binary for your OS and CPU architecture.
3. Unpack the .tar.gz archive and move binary to permanent directory

#### Example on Linux AMD64

```bash
wget https://github.com/cilium/stackwhere/releases/download/v0.1.0/stackwhere_0.1.0_linux_amd64.tar.gz

# Optional, verify checksum
wget https://github.com/cilium/stackwhere/releases/download/v0.1.0/stackwhere_0.1.0_checksums.txt
sha256sum -c stackwhere_0.1.0_checksums.txt --ignore-missing
# Should say: stackwhere_0.1.0_linux_amd64.tar.gz: OK

tar -xzf stackwhere_0.1.0_linux_amd64.tar.gz
sudo mv stackwhere /usr/bin/stackwhere
```

### Go install

Install the latest version by running `go install github.com/cilium/stackwhere/cmd/stackwhere@latest`.

## Usage

Stackwhere uses DWARF debug info, which requires the .o files to be created with the `-g` compiler option and to not
be stripped.

### Inspecting collections

The `list` (alias `l`) sub-command lists the peak stack usage for each program / function in the given
only a object file.

```
$ stackwhere list {path to .o}
128 bytes - my_example_program
 80 bytes - my_other_program
 20 bytes - small_function
```

### Inspecting programs

The `list` (alias `l`) sub-command lists a detailed per program listing when a program name is specified as the second
argument.

```
$ stackwhere list {path to .o} {name of program}
R10-16:
  8 - example_var1 @ /some/path/to/your/sources/bpf.c:12
R10-24:
  16 - example_var2 @ /some/path/to/your/sources/bpf.c:14
R10-40:
  8 - example_var3 @ /some/path/to/your/sources/bpf.c:20
  4 - example_var5 @ /some/path/to/your/sources/bpf.c:41
R10-48:
  8 - example_var4 @ /some/path/to/your/sources/bpf.c:21
```

This prints each offset into the stack found in the program when attributable to something found in the sources. Stack offsets are always R10 minus some fixed offset, BPF does not have push/pop instructions, so stack size is always predetermined and offsets within it assigned by the compiler. R10 is the stack frame the function.

Stack usage happens in three situations:
1. A local variable or function argument is larger than 8 bytes, and thus cannot fit in a register value.
2. All register values are full, variables or intermediate values are spilled onto the stack.
3. A pointer to a local variable or attribute is passed to a helper function or kfunc.

So local variables and function arguments of inlined functions can appear in the output, be referred to as "variables".

Multiple variables can share the same offset when their lifetimes do not overlap, so stack slots are reused by the compiler when it thinks its safely able to. Stackwhere groups variables at the same offsets together and outputs them from low offsets (the "bottom" of the stack) to high offsets ("top" top of the stack).

Spilling of unamed values, such as intermediate values of an expression does not appear in this output (at this this). Such spilled values can share stack slots with named variables and may use gaps in offsets that are shown. 

## Tips for reducing stack usage

The limiting factor for a BPF program is the **peak** memory usage, some ideas to reduce peak memory usage are:

1. Removing variables. not always possible, but a 1 byte variable can take up a whole 8 byte stack slot.
2. Shorten variable lifetimes. Use inlined functions or variable scopes to limit the lifetime of a variable. Attempt to order code such that variables can have smaller lifetimes. This promotes stack slot reuse, less variables alive a the same time, smaller peak usage.
3. Utilize non-stack memory. Avoid storing variables which can be derived from the program context. Use map values instead of copying and holding onto individual field values. Use per-CPU map values or global variables to store large values (that are not used as input to branching logic).
4. Split programs into tail calls.
5. Reduce function call depth.

Warning, some of these measures may increase verifier complexity and/or runtime performance, there are always tradeoffs.
