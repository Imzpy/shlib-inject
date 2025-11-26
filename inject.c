#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/ptrace.h>

/* ARM64 specific ptrace constant */
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define __unused __attribute__((unused))

static volatile sig_atomic_t should_exit = 0;

extern char __inj_call[];
extern char __inj_call_end[];
extern char __inj_trap[];
#define __inj_call_sz ((size_t)(__inj_call_end - __inj_call))

static bool verbose = false;

#define dprintf(fmt, ...) if (verbose) printf(fmt, ##__VA_ARGS__)

/* function calling injection code */
#if defined(__x86_64__)
	/*
	 * rax: address of a function to call
	 * rdi, rsi, rdx, rcx, r8, r9: arguments passed to a function
	 * return: rax contains the result
	 */
	__asm__(
	"__inj_call:					\n\t"
	"	call *%rax				\n\t"
	"__inj_trap:					\n\t"
	"	int3					\n\t"
	"__inj_call_end:				\n\t"
	);
#elif defined(__aarch64__)
	/*
	 * x8: address of a function to call
	 * x0-x7: arguments passed to a function
	 * return: x0 contains the result
	 */
	__asm__(
	"__inj_call:					\n\t"
	"	blr x8					\n\t"
	"__inj_trap:					\n\t"
	"	brk #0					\n\t"
	"__inj_call_end:				\n\t"
	);
#else
#error "Only x86-64 and arm64 are supported"
#endif

static void signal_handler(int /*sig*/)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	should_exit = 1;
}

static const char *signal_names[] = {
	[0] = "SIGZERO!!!",
	[SIGHUP] = "SIGHUP",
	[SIGINT] = "SIGINT",
	[SIGQUIT] = "SIGQUIT",
	[SIGILL] = "SIGILL",
	[SIGTRAP] = "SIGTRAP",
	[SIGABRT] = "SIGABRT",
	[SIGBUS] = "SIGBUS",
	[SIGFPE] = "SIGFPE",
	[SIGKILL] = "SIGKILL",
	[SIGUSR1] = "SIGUSR1",
	[SIGSEGV] = "SIGSEGV",
	[SIGUSR2] = "SIGUSR2",
	[SIGPIPE] = "SIGPIPE",
	[SIGALRM] = "SIGALRM",
	[SIGTERM] = "SIGTERM",
	[SIGSTKFLT] = "SIGSTKFLT",
	[SIGCHLD] = "SIGCHLD",
	[SIGCONT] = "SIGCONT",
	[SIGSTOP] = "SIGSTOP",
	[SIGTSTP] = "SIGTSTP",
	[SIGTTIN] = "SIGTTIN",
	[SIGTTOU] = "SIGTTOU",
	[SIGURG] = "SIGURG",
	[SIGXCPU] = "SIGXCPU",
	[SIGXFSZ] = "SIGXFSZ",
	[SIGVTALRM] = "SIGVTALRM",
	[SIGPROF] = "SIGPROF",
	[SIGWINCH] = "SIGWINCH",
	[SIGIO] = "SIGIO",
	[SIGPWR] = "SIGPWR",
	[SIGSYS] = "SIGSYS"
};

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

static const char *sig_name(int sig)
{
	static char buf[256];

	if (sig < 0 || sig >= ARRAY_SIZE(signal_names) || !signal_names[sig]) {
		snprintf(buf, sizeof(buf), "SIGNAL(%d)", sig);
		return buf;
	}

	return signal_names[sig];
}

static long find_libc_base(pid_t pid, long *out_end_addr)
{
	char maps_path[64];
	FILE *maps_file;
	char line[1024];
	long base_addr = 0;

	if (pid == -1) {
		snprintf(maps_path, sizeof(maps_path), "/proc/self/maps");
	} else {
		snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	}

	maps_file = fopen(maps_path, "r");
	if (!maps_file) {
		int err = -errno;
		fprintf(stderr, "Failed to open %s: %d\n", maps_path, err);
		return 0;
	}

	while (fgets(line, sizeof(line), maps_file)) {
		long start_addr, end_addr, offset, inode;
		char perms[16], dev[16], pathname[256];
		int parsed;

		parsed = sscanf(line, "%lx-%lx %s %lx %15s %ld %255s",
				&start_addr, &end_addr, perms, &offset, dev, &inode, pathname);
		if (parsed < 7)
			continue;

		const char *libc_pos = strstr(pathname, "libc");
		if (libc_pos &&
		    libc_pos > pathname &&
		    libc_pos[-1] == '/' &&
		    (libc_pos[4] == '.' || libc_pos[4] == '-') &&
		    strstr(pathname, ".so") /*&&
		    perms[2] == 'x'*/) {
			printf("Found libc mapping: %lx-%lx %s %s\n",
			       start_addr, end_addr, perms, pathname);

			base_addr = start_addr;
			if (out_end_addr)
				*out_end_addr = end_addr;
			break;
		}
	}

	fclose(maps_file);

	if (base_addr) {
		printf("libc base address: 0x%lx\n", base_addr);
	} else {
		printf("libc base address not found\n");
	}

	return base_addr;
}

static long find_elf_sym_info(const char *elf_path, const char *sym_name)
{
	int fd = -1;
	long result = 0;
	void *mapped = MAP_FAILED;
	size_t file_size = 0;
	struct stat st;

	fd = open(elf_path, O_RDONLY);
	if (fd < 0) {
		int err = -errno;
		fprintf(stderr, "Failed to open ELF file %s: %d\n", elf_path, err);
		return 0;
	}

	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat ELF file %s\n", elf_path);
		goto cleanup;
	}
	file_size = st.st_size;

	mapped = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapped == MAP_FAILED) {
		int err = -errno;
		fprintf(stderr, "Failed to mmap ELF file %s: %d\n", elf_path, err);
		goto cleanup;
	}

	if (file_size < sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "File too small to be valid ELF: %s\n", elf_path);
		goto cleanup;
	}

	/* Check ELF header and architecture */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mapped;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "Invalid ELF file or not 64-bit: %s\n", elf_path);
		goto cleanup;
	}

#if defined(__x86_64__)
	if (ehdr->e_machine != EM_X86_64) {
		fprintf(stderr, "ELF file is not x86_64: %s\n", elf_path);
		goto cleanup;
	}
#elif defined(__aarch64__)
	if (ehdr->e_machine != EM_AARCH64) {
		fprintf(stderr, "ELF file is not aarch64: %s\n", elf_path);
		goto cleanup;
	}
#else
#error "Unsupported architecture"
#endif

	if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > file_size) {
		fprintf(stderr, "Section headers extend beyond file size\n");
		goto cleanup;
	}

	if (ehdr->e_shstrndx >= ehdr->e_shnum) {
		fprintf(stderr, "Invalid section header string table index\n");
		goto cleanup;
	}

	Elf64_Shdr *shdrs = (Elf64_Shdr *)((char *)mapped + ehdr->e_shoff);
	Elf64_Shdr *shstrtab_shdr = &shdrs[ehdr->e_shstrndx];

	if (shstrtab_shdr->sh_offset + shstrtab_shdr->sh_size > file_size) {
		fprintf(stderr, "String table extends beyond file size\n");
		goto cleanup;
	}

	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM)
			continue;

		Elf64_Shdr *symtab_shdr = &shdrs[i];
		Elf64_Shdr *strtab_shdr = &shdrs[symtab_shdr->sh_link];

		if (symtab_shdr->sh_link >= ehdr->e_shnum ||
		    symtab_shdr->sh_offset + symtab_shdr->sh_size > file_size ||
		    strtab_shdr->sh_offset + strtab_shdr->sh_size > file_size)
			continue;

		Elf64_Sym *symtab = (Elf64_Sym *)((char *)mapped + symtab_shdr->sh_offset);
		char *strtab = (char *)mapped + strtab_shdr->sh_offset;

		size_t num_symbols = symtab_shdr->sh_size / sizeof(Elf64_Sym);
		for (size_t j = 0; j < num_symbols; j++) {
			if (symtab[j].st_name >= strtab_shdr->sh_size)
				continue;

			const char *name = &strtab[symtab[j].st_name];
			if (strcmp(name, sym_name) == 0) {
				result = symtab[j].st_value;
				printf("Found symbol %s at 0x%lx in %s\n", sym_name, result, elf_path);
				goto cleanup;
			}
		}
	}

cleanup:
	if (mapped != MAP_FAILED)
		munmap(mapped, file_size);
	if (fd >= 0)
		close(fd);
	return result;
}

static int copy_file_to_fd(const char *file_path, int dest_fd)
{
	int src_fd = -1;
	int result = -1;
	char buffer[4096];
	ssize_t bytes_read, bytes_written;

	src_fd = open(file_path, O_RDONLY);
	if (src_fd < 0) {
		int err = -errno;
		fprintf(stderr, "Failed to open source file %s: %d\n", file_path, err);
		return err;
	}

	while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
		char *write_ptr = buffer;
		ssize_t remaining = bytes_read;

		while (remaining > 0) {
			bytes_written = write(dest_fd, write_ptr, remaining);
			if (bytes_written < 0) {
				int err = -errno;
				fprintf(stderr, "Failed to write to destination fd: %d\n", err);
				goto cleanup;
			}
			write_ptr += bytes_written;
			remaining -= bytes_written;
		}
	}

	if (bytes_read < 0) {
		int err = -errno;
		fprintf(stderr, "Failed to read from source file %s: %d\n", file_path, err);
		goto cleanup;
	}

	if (fsync(dest_fd) < 0) {
		int err = -errno;
		fprintf(stderr, "Failed to fsync() destination fd: %d\n", err);
		goto cleanup;
	}
	if (lseek(dest_fd, 0, SEEK_SET) < 0) {
		int err = -errno;
		fprintf(stderr, "Failed to lseek() destination fd: %d\n", err);
		goto cleanup;
	}

	result = 0;

cleanup:
	if (src_fd >= 0)
		close(src_fd);
	return result;
}

static int remote_vm_write(int pid, const void *remote_dst, const void *local_src, size_t sz)
{
	struct iovec local, remote;

	local.iov_base = (void *)local_src;
	local.iov_len = sz;

	remote.iov_base = (void *)remote_dst;
	remote.iov_len = sz;

	if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != (ssize_t)sz) {
		int err = -errno;
		fprintf(stderr, "Failed to remote-write-vm of %zu bytes: %d\n", sz, err);
		return err;
	}

	return 0;
}

__unused
static int remote_vm_read(int pid, const void *local_dst, const void *remote_src, size_t sz)
{
	struct iovec local, remote;

	local.iov_base = (void *)local_dst;
	local.iov_len = sz;

	remote.iov_base = (void *)remote_src;
	remote.iov_len = sz;

	if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != (ssize_t)sz) {
		int err = -errno;
		fprintf(stderr, "Failed to remote-read-vm of %zu bytes: %d\n", sz, err);
		return err;
	}

	return 0;
}

static void print_regs(const struct user_regs_struct *regs, const char *pfx)
{
	if (pfx)
		printf("%s: ", pfx);

#if defined(__x86_64__)
	printf("rip=%llx rax=%llx (orig_rax=%llx) rdi=%llx rsi=%llx rdx=%llx r10=%llx r8=%llx r9=%llx rbp=%llx rsp=%llx\n",
		regs->rip, regs->rax, regs->orig_rax, regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9,
		regs->rbp, regs->rsp);
#elif defined(__aarch64__)
	printf("pc=%llx sp=%llx x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx x5=%llx x8=%llx\n",
		regs->pc, regs->sp, regs->regs[0], regs->regs[1], regs->regs[2], regs->regs[3],
		regs->regs[4], regs->regs[5], regs->regs[8]);
#else
#error "Unsupported architecture"
#endif
}

static int ptrace_get_regs(int pid, struct user_regs_struct *regs, const char *descr)
{
	struct iovec iov = {
		.iov_base = regs,
		.iov_len = sizeof(*regs),
	};

	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		int err = -errno;
		fprintf(stderr, "ptrace(PTRACE_GETREGSET, PID %d, %s) failed: %d\n", pid, descr, err);
		return err;
	}
	dprintf("PTRACE_GETREGSET(%d, %s)\n", pid, descr);
	return 0;
}

static int ptrace_set_regs(int pid, const struct user_regs_struct *regs, const char *descr)
{
	struct iovec iov = {
		.iov_base = (void *)regs,
		.iov_len = sizeof(*regs),
	};

	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		int err = -errno;
		fprintf(stderr, "ptrace(PTRACE_SETREGSET, PID %d, %s) failed: %d\n", pid, descr, err);
		return err;
	}

	dprintf("PTRACE_SETREGSET(%d, %s)\n", pid, descr);
	return 0;
}

static int ptrace_op(int pid, enum __ptrace_request op, long data, const char *descr)
{
	const char *op_name;

	switch (op) {
	case PTRACE_TRACEME: op_name = "PTRACE_TRACEME"; break;
	case PTRACE_ATTACH: op_name = "PTRACE_ATTACH"; break;
	case PTRACE_DETACH: op_name = "PTRACE_DETACH"; break;
	case PTRACE_CONT: op_name = "PTRACE_CONT"; break;
	case PTRACE_LISTEN: op_name = "PTRACE_LISTEN"; break;
	case PTRACE_SEIZE: op_name = "PTRACE_SEIZE"; break;
	case PTRACE_INTERRUPT: op_name = "PTRACE_INTERRUPT"; break;
	case PTRACE_SINGLESTEP: op_name = "PTRACE_SINGLESTEP"; break;
	case PTRACE_SYSCALL: op_name = "PTRACE_SYSCALL"; break;
	default: op_name = "???";
	}

	if (ptrace(op, pid, NULL, data) < 0) {
		int err = -errno;
		fprintf(stderr, "ptrace(%s, pid %d, %s) failed: %d\n", op_name, pid, descr, err);
		return err;
	}

	dprintf("%s(%d)\n", op_name, pid);

	return 0;
}

static int ptrace_wait_generic(int pid, int signal, bool ptrace_event, long ip, const char *descr)
{
	int status, err;

	while (true) {
		if (waitpid(pid, &status, __WALL) != pid) {
			err = -errno;
			fprintf(stderr, "waitpid(pid %d, %s) failed: %d\n", pid, descr, err);
			return err;
		}

		if (WIFEXITED(status)) {
			dprintf("WIFEXITED(pid %d)\n", pid);
			return -ENOENT;
		}

		if (WIFSTOPPED(status) &&
		   (!ptrace_event || (status >> 16) == PTRACE_EVENT_STOP) &&
		    WSTOPSIG(status) == signal) {
			/* Verify IP matches if requested (for SIGTRAP) */
			if (ip) {
				struct user_regs_struct regs;

				err = ptrace_get_regs(pid, &regs, descr);
				if (err)
					return err;

				/* Note: this IP calculation logic is SIGTRAP specific */
#if defined(__x86_64__)
				long trap_ip = regs.rip - 1;
#elif defined(__aarch64__)
				long trap_ip = regs.pc;
#else
#error "Unsupported architecture"
#endif
				if (trap_ip != ip) {
					fprintf(stderr, "UNEXPECTED IP %lx (expecting %lx) for STOPSIG=%d (%s), PASSING THROUGH BACK TO APP!\n",
					        trap_ip, ip,
					        WSTOPSIG(status), sig_name(WSTOPSIG(status)));
					goto pass_through;
				}
			}

			dprintf("STOPPED%s STOPSIG=%d (%s)\n",
				ptrace_event ? " (PTRACE_EVENT_STOP)" : "",
				WSTOPSIG(status), sig_name(WSTOPSIG(status)));
			return 0;
		}

		{
			struct user_regs_struct regs;
			siginfo_t siginfo;

			ptrace_get_regs(pid, &regs, descr);
			ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo);

#if defined(__x86_64__)
			long signal_ip = regs.rip;
#elif defined(__aarch64__)
			long signal_ip = regs.pc;
#else
#error "Unsupported architecture"
#endif
			printf("PASS-THROUGH SIGNAL %d (%s) (status %x, IP %lx, addr %p, code %d) BACK TO PID %d\n",
			       WSTOPSIG(status), sig_name(WSTOPSIG(status)), status,
			       signal_ip, siginfo.si_addr, siginfo.si_code, pid);
		}

pass_through:
		err = ptrace_op(pid, PTRACE_CONT, WSTOPSIG(status), descr);
		if (err)
			return err;
	}
}

static int ptrace_wait_stop(int pid, const char *descr)
{
	return ptrace_wait_generic(pid, SIGTRAP, true /* PTRACE_EVENT_STOP */, 0, descr);
}

static int ptrace_wait_signal(int pid, int signal, long ip, const char *descr)
{
	return ptrace_wait_generic(pid, SIGTRAP, false /* !PTRACE_EVENT_STOP */, ip, descr);
}

static int ptrace_wait_syscall(int pid, const char *descr)
{
	return ptrace_wait_generic(pid, SIGTRAP | 0x80, false /* !PTRACE_EVENT_STOP */, 0, descr);
}

/* Helper macros for register manipulation */
#define ___concat(a, b) a ## b
#define ___apply(fn, n) ___concat(fn, n)
#define ___nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#define ___narg(...) ___nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#if defined(__x86_64__)

/* function call convention */
#define ___regs_set_func_args0(_r)
#define ___regs_set_func_args1(_r, a)                (_r)->rdi = a; ___regs_set_func_args0(_r)
#define ___regs_set_func_args2(_r, a, b)             (_r)->rsi = b; ___regs_set_func_args1(_r, a)
#define ___regs_set_func_args3(_r, a, b, c)          (_r)->rdx = c; ___regs_set_func_args2(_r, a, b)
#define ___regs_set_func_args4(_r, a, b, c, d)       (_r)->rcx = d; ___regs_set_func_args3(_r, a, b, c)
#define ___regs_set_func_args5(_r, a, b, c, d, e)    (_r)->r8  = e; ___regs_set_func_args4(_r, a, b, c, d)
#define ___regs_set_func_args6(_r, a, b, c, d, e, f) (_r)->r9  = f; ___regs_set_func_args5(_r, a, b, c, d, e)

/* system call convention */
#define ___regs_set_sys_args0(_r, nr)                   (_r)->rax = nr;
#define ___regs_set_sys_args1(_r, nr, a)                (_r)->rdi = a; ___regs_set_sys_args0(_r, nr)
#define ___regs_set_sys_args2(_r, nr, a, b)             (_r)->rsi = b; ___regs_set_sys_args1(_r, nr, a)
#define ___regs_set_sys_args3(_r, nr, a, b, c)          (_r)->rdx = c; ___regs_set_sys_args2(_r, nr, a, b)
#define ___regs_set_sys_args4(_r, nr, a, b, c, d)       (_r)->r10 = d; ___regs_set_sys_args3(_r, nr, a, b, c)
#define ___regs_set_sys_args5(_r, nr, a, b, c, d, e)    (_r)->r8  = e; ___regs_set_sys_args4(_r, nr, a, b, c, d)
#define ___regs_set_sys_args6(_r, nr, a, b, c, d, e, f) (_r)->r9  = f; ___regs_set_sys_args5(_r, nr, a, b, c, d, e)

/* ensure 16-byte alignment and set up red zone (necessary on x86-64) */
#define ___regs_adjust_sp(_r) (_r)->rsp = ((_r)->rsp & ~0xFULL) - 128
#define ___regs_result(_r) (_r)->rax
#define ___regs_set_ip(_r, addr) (_r)->rip = addr
/* set __inj_call's argument (which function to call) */
#define ___regs_set_tramp_dst(_r, addr) (_r)->rax = addr

#elif defined(__aarch64__)

#define ___regs_set_func_args0(_r)
#define ___regs_set_func_args1(_r, a)                (_r)->regs[0] = a; ___regs_set_func_args0(_r)
#define ___regs_set_func_args2(_r, a, b)             (_r)->regs[1] = b; ___regs_set_func_args1(_r, a)
#define ___regs_set_func_args3(_r, a, b, c)          (_r)->regs[2] = c; ___regs_set_func_args2(_r, a, b)
#define ___regs_set_func_args4(_r, a, b, c, d)       (_r)->regs[3] = d; ___regs_set_func_args3(_r, a, b, c)
#define ___regs_set_func_args5(_r, a, b, c, d, e)    (_r)->regs[4] = e; ___regs_set_func_args4(_r, a, b, c, d)
#define ___regs_set_func_args6(_r, a, b, c, d, e, f) (_r)->regs[5] = f; ___regs_set_func_args5(_r, a, b, c, d, e)

#define ___regs_set_sys_args0(_r, nr)                   (_r)->regs[8] = nr;
#define ___regs_set_sys_args1(_r, nr, a)                (_r)->regs[0] = a; ___regs_set_sys_args0(_r, nr)
#define ___regs_set_sys_args2(_r, nr, a, b)             (_r)->regs[1] = b; ___regs_set_sys_args1(_r, nr, a)
#define ___regs_set_sys_args3(_r, nr, a, b, c)          (_r)->regs[2] = c; ___regs_set_sys_args2(_r, nr, a, b)
#define ___regs_set_sys_args4(_r, nr, a, b, c, d)       (_r)->regs[3] = d; ___regs_set_sys_args3(_r, nr, a, b, c)
#define ___regs_set_sys_args5(_r, nr, a, b, c, d, e)    (_r)->regs[4] = e; ___regs_set_sys_args4(_r, nr, a, b, c, d)
#define ___regs_set_sys_args6(_r, nr, a, b, c, d, e, f) (_r)->regs[5] = f; ___regs_set_sys_args5(_r, nr, a, b, c, d, e)

/* ensure 16-byte alignment (no need for red zone on arm64) */
#define ___regs_adjust_sp(_r) (_r)->sp = (_r)->sp & ~0xFULL
#define ___regs_result(_r) (_r)->regs[0]
#define ___regs_set_ip(_r, addr) (_r)->pc = addr
/* set __inj_call's argument (which function to call) */
#define ___regs_set_tramp_dst(_r, addr) (_r)->regs[8] = addr

#else
#error "Unsupported architecture"
#endif

#define ___regs_set_func_args(regs, args...)  ___apply(___regs_set_func_args, ___narg(args))(regs, ##args)
#define ___regs_set_sys_args(regs, nr, args...)  ___apply(___regs_set_sys_args, ___narg(args))(regs, nr, ##args)

static int ptrace_exec_syscall(int pid,
			       const struct user_regs_struct *pre_regs,
			       struct user_regs_struct *post_regs,
			       const char *descr)
{
	int err = 0;

	err = err ?: ptrace_set_regs(pid, pre_regs, descr);
	err = err ?: ptrace_op(pid, PTRACE_SYSCALL, 0, descr);
	err = err ?: ptrace_wait_syscall(pid, descr); /* syscall-enter-stop */
	err = err ?: ptrace_op(pid, PTRACE_SYSCALL, 0, descr);
	err = err ?: ptrace_wait_syscall(pid, descr); /* syscall-exit-stop */
	err = err ?: ptrace_get_regs(pid, post_regs, descr);

	return err;
}

static int ptrace_intercept(int pid, struct user_regs_struct *orig_regs, const char *descr)
{
	int err = 0;

	/*
	 * Attach to tracee
	 */
	dprintf("Seizing...\n");
	if ((err = ptrace_op(pid, PTRACE_SEIZE, PTRACE_O_TRACESYSGOOD, descr)) < 0)
		return err;

	if ((err = ptrace_op(pid, PTRACE_INTERRUPT, 0, descr)) < 0)
		goto err_detach;
	if ((err = ptrace_wait_stop(pid, descr)) < 0)
		goto err_detach;

	/*
	 * Take over next syscall
	 */
	dprintf("Resuming until syscall...\n");
	if ((err = ptrace_op(pid, PTRACE_SYSCALL, 0, descr)) < 0)
		goto err_detach;
	if ((err = ptrace_wait_syscall(pid, descr)) < 0)
		goto err_detach;
	/* backup original registers */
	if ((err = ptrace_get_regs(pid, orig_regs, descr)) < 0)
		goto err_detach;

#if defined(__x86_64__)
	orig_regs->rax = orig_regs->orig_rax;
	orig_regs->orig_rax = -1;
	/* cancel pending syscall with that orig_rax == -1 */
	if ((err = ptrace_set_regs(pid, orig_regs, descr)) < 0)
		goto err_detach;
#elif defined(__aarch64__)
	/* On ARM64 we need to cancel pending syscall with explicit NT_ARM_SYSTEM_CALL */
	int syscall_nr = -1;
	struct iovec iov = {
		.iov_base = &syscall_nr,
		.iov_len = sizeof(syscall_nr),
	};
	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov) < 0) {
		err = -errno;
		fprintf(stderr, "ptrace(PTRACE_SETREGSET, NT_ARM_SYSTEM_CALL, nr=%d, %s) failed: %d\n",
			syscall_nr, descr, err);
		goto err_detach;
	}
#else
#error "Unsupported architecture"
#endif

	/*
	 * Now that we "cancelled" original syscall proceed to
	 * syscall-exit-stop, so that all subsequent operations start from
	 * clean slate
	 */
	if ((err = ptrace_op(pid, PTRACE_SYSCALL, 0, descr)) < 0)
		goto err_detach;
	if ((err = ptrace_wait_syscall(pid, descr)) < 0)
		goto err_detach;

#if defined(__x86_64__)
	orig_regs->rip -= 2; /* adjust for syscall replay, syscall instruction is 2 bytes */
#elif defined(__aarch64__)
	orig_regs->pc -= 4; /* adjust for syscall replay, arm64 instruction is 4 bytes */
#else
#error "Unsupported architecture"
#endif

	/*
	 * Now we are in syscall-exit-stop, we can replay/restart syscall or
	 * proceed with user space code execution
	 */
	return 0;

err_detach:
	(void)ptrace_op(pid, PTRACE_DETACH, 0, descr);
	return err;
}

static int ptrace_replay(int pid, const struct user_regs_struct *orig_regs, const char *descr)
{
	int err = 0;

	err = err ?: ptrace_set_regs(pid, orig_regs, descr);
	err = err ?: ptrace_op(pid, PTRACE_SYSCALL, 0, descr);
	err = err ?: ptrace_wait_syscall(pid, descr); /* syscall-enter-stop */

	/*
	 * Don't wait for the original syscall to return. This might never
	 * happen (long sleep() or long blocking read()). Just detach
	 * from syscall-enter-stop step and let kernel complete
	 * the syscall successfully.
	 */

	int detach_err = ptrace_op(pid, PTRACE_DETACH, 0, descr);
	err = err ?: detach_err;

	return err;
}

static int ptrace_exec_user_call(int pid, long exec_mmap_addr, long func_addr,
				  struct user_regs_struct *regs, long *res,
				  const char *descr)
{
	long inj_trap_addr = exec_mmap_addr + __inj_trap - __inj_call;
	int err;

	___regs_set_ip(regs, exec_mmap_addr);
	___regs_set_tramp_dst(regs, func_addr);
	___regs_adjust_sp(regs);
	/* function arguments are set through regs already */

	if ((err = ptrace_set_regs(pid, regs, descr)) < 0)
		return err;
	if ((err = ptrace_op(pid, PTRACE_CONT, 0, descr)) < 0)
		return err;
	if ((err = ptrace_wait_signal(pid, SIGTRAP, inj_trap_addr, descr)) < 0)
		return err;
	if ((err = ptrace_get_regs(pid, regs, descr)) < 0)
		return err;

	*res = ___regs_result(regs);

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	struct sigaction sa;
	int err;

	if (argc != 2) {
		printf("Usage: %s <PID>\n", argv[0]);
		return 1;
	}

	pid = atoi(argv[1]);
	if (pid <= 0) {
		printf("Invalid PID: %s\n", argv[1]);
		return 1;
	}

	printf("Target PID: %d\n", pid);

	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction SIGINT");
		return 1;
	}

	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		perror("sigaction SIGTERM");
		return 1;
	}

	/* We need pidfd to open tracee's FD later on */
	int pid_fd = syscall(SYS_pidfd_open, pid, 0);
	if (pid_fd < 0) {
		err = -errno;
		fprintf(stderr, "pidfd_open(%d) failed: %d\n", pid, err);
		return 1;
	}

	/*
	 * Find dlopen() and dlclose() addresses 
	 */
	long libc_self_end = 0;
	long libc_self_base = find_libc_base(-1, &libc_self_end);
	long libc_tracee_base = find_libc_base(pid, NULL);
	if (libc_self_base == 0 || libc_tracee_base == 0)
		return 1;
	char libc_path[512];
	snprintf(libc_path, sizeof(libc_path), "/proc/self/map_files/%lx-%lx", libc_self_base, libc_self_end);
	long dlopen_off = find_elf_sym_info(libc_path, "dlopen");
	long dlclose_off = find_elf_sym_info(libc_path, "dlclose");
	if (dlopen_off == 0 || dlclose_off == 0)
		return 1;
	long dlopen_tracee_addr = libc_tracee_base + dlopen_off;
	long dlclose_tracee_addr = libc_tracee_base + dlclose_off;
	printf("Local libc base: 0x%lx (dlopen offset %lx, dlclose offset %lx)\n",
	       libc_self_base, dlopen_off, dlclose_off);
	printf("Remote libc base: 0x%lx (dlopen @ 0x%lx, dlclose @ 0x%lx)\n",
	       libc_tracee_base, dlopen_tracee_addr, dlclose_tracee_addr);

	/*
	 * Attach to tracee and intercept syscall
	 */
	struct user_regs_struct orig_regs, regs;

	printf("Intercepting tracee...\n");
	if (ptrace_intercept(pid, &orig_regs, "tracee-intercept") < 0)
		return 1;

	print_regs(&orig_regs, "ORIG REGS");

	/*
	 * INJECT SYSCALL: mmap(RW) for data + exec
	 */
	const long page_size = sysconf(_SC_PAGESIZE);
	const long data_mmap_sz = page_size;
	const long exec_mmap_sz = page_size;
	long data_mmap_addr = 0;
	long exec_mmap_addr = 0;

	printf("Executing mmap(data + exec)...\n");
	/* void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); */
	regs = orig_regs;
	___regs_set_sys_args(&regs, __NR_mmap,
			     0, data_mmap_sz + exec_mmap_sz,
			     PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptrace_exec_syscall(pid, &regs, &regs, "mmap-data+exec") < 0)
		return 1;

	data_mmap_addr = ___regs_result(&regs);
	if (data_mmap_addr <= 0) {
		fprintf(stderr, "mmap() inside tracee failed: %ld, bailing!\n", data_mmap_addr);
		return 1;
	}

	exec_mmap_addr = data_mmap_addr + data_mmap_sz;
	printf("mmap() returned 0x%lx (data @ %lx, exec @ %lx)\n",
	       data_mmap_addr, data_mmap_addr, exec_mmap_addr);

	/*
	 * Setup executable function call trampoline by copying inj_call()
	 * code into (soon-to-be) executable mmap()'ed memory
	 */
	err = remote_vm_write(pid, (void *)exec_mmap_addr, __inj_call, __inj_call_sz);
	if (err)
		return 1;

	/*
	 * INJECT SYSCALL: mprotect(r-x) on exec region
	 */
	printf("Executing mprotect(r-x)...\n");
	/* int mprotect(void *addr, size_t size, int prot); */
	regs = orig_regs;
	___regs_set_sys_args(&regs, __NR_mprotect,
			     exec_mmap_addr, exec_mmap_sz, PROT_EXEC | PROT_READ);

	long mprotect_ret;
	if (ptrace_exec_syscall(pid, &regs, &regs, "mprotect-rx") < 0)
		return 1;
	mprotect_ret = ___regs_result(&regs);
	if (mprotect_ret < 0) {
		fprintf(stderr, "mprotect(r-x) inside tracee failed: %ld, bailing!\n", mprotect_ret);
		return 1;
	}

	/*
	 * INJECT SYSCALL: memfd_create()
	 */
	printf("Executing memfd_create()...\n");

	char memfd_name[] = "shlib-inject";
	int memfd_remote_fd = -1;

	err = remote_vm_write(pid, (void *)data_mmap_addr, memfd_name, sizeof(memfd_name));
	if (err)
		return 1;

	/* int memfd_create(const char *name, unsigned int flags); */
	regs = orig_regs;
	___regs_set_sys_args(&regs, __NR_memfd_create, data_mmap_addr, MFD_CLOEXEC);

	if (ptrace_exec_syscall(pid, &regs, &regs, "memfd_create") < 0)
		return 1;

	memfd_remote_fd = ___regs_result(&regs);
	if (memfd_remote_fd < 0) {
		fprintf(stderr, "memfd_create() inside tracee failed: %d, bailing!\n", memfd_remote_fd);
		return 1;
	}
	printf("memfd_create() result: %d\n", memfd_remote_fd);

	/*
	 * dlopen() injection
	 */

	/* Open tracee's allocated FD for shared lib code */
	int memfd_local_fd = syscall(SYS_pidfd_getfd, pid_fd, memfd_remote_fd, 0);
	if (memfd_local_fd < 0) {
		err = -errno;
		fprintf(stderr, "pidfd_getfd(pid %d, remote_fd %d) failed: %d\n", pid, memfd_remote_fd, err);
		return 1;
	}

	/* Copy shared library to memfd */
	err = copy_file_to_fd("libinj.so", memfd_local_fd);
	if (err)
		return 1;

	/* Copy over memfd path for passing into dlopen() */
	char memfd_path[64];
	snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd_remote_fd);
	err = remote_vm_write(pid, (void *)data_mmap_addr, memfd_path, sizeof(memfd_path));
	if (err)
		return 1;

	printf("Executing dlopen() injection...\n");

	/* void *dlopen(const char *path, int flags); */
	long dlopen_handle;
	regs = orig_regs;
	___regs_set_func_args(&regs, data_mmap_addr, RTLD_LAZY);
	if (ptrace_exec_user_call(pid, exec_mmap_addr, dlopen_tracee_addr, &regs, &dlopen_handle, "dlopen") < 0)
		return 1;

	printf("dlopen() result: %lx\n", dlopen_handle);
	if (dlopen_handle == 0) {
		fprintf(stderr, "Failed to dlopen() injection library, bailing...\n");
		return 1;
	}

	/*
	 * Execute original intercepted syscall
	 */
	printf("Replaying original syscall and detaching tracee...\n");
	if (ptrace_replay(pid, &orig_regs, "replay-syscall") < 0)
		return 1;

	/* just idly wait... */
	sleep(1);

	/*
	 * Interrupt tracee again for clean up
	 */
	printf("Re-intercepting for cleanup...\n");
	if (ptrace_intercept(pid, &orig_regs, "tracee-reintercept") < 0)
		return 1;
	print_regs(&orig_regs, "ORIG REGS (2)");

	/*
	 * dlclose() injection
	 */
	printf("Executing dlclose() injection...\n");
	long dlclose_ret;
	regs = orig_regs;
	___regs_set_func_args(&regs, dlopen_handle);
	if (ptrace_exec_user_call(pid, exec_mmap_addr, dlclose_tracee_addr, &regs, &dlclose_ret, "dlclose") < 0)
		return 1;
	printf("dlclose() result: %ld\n", dlclose_ret);
	if (dlclose_ret != 0) {
		fprintf(stderr, "Failed to dlclose() injection library, bailing...\n");
		return 1;
	}

	/*
	 * INJECT SYSCALL: munmap(data + exec)
	 */
	printf("Executing munmap(data + exec)...\n");
	/* int munmap(void *addr, size_t len); */
	regs = orig_regs;
	___regs_set_sys_args(&regs, __NR_munmap, data_mmap_addr, data_mmap_sz + exec_mmap_sz);
	if (ptrace_exec_syscall(pid, &regs, &regs, "munmap-data+exec") < 0)
		return 1;
	long munmap_ret = ___regs_result(&regs);
	if (munmap_ret < 0) {
		fprintf(stderr, "munmap() inside tracee failed: %ld, bailing!\n", munmap_ret);
		return 1;
	}
	printf("munmap() result: %ld\n", munmap_ret);

	/*
	 * Replay intercepted original syscall
	 */
	printf("Replaying original syscall and detaching tracee...\n");
	if (ptrace_replay(pid, &orig_regs, "replay-syscall-final") < 0)
		return 1;

	printf("Tracee detached and running...\n");
	printf("Press Ctrl-C to exit...\n");

	while (!should_exit) {
		usleep(50000);
	}

	printf("Exited gracefully.\n");
	return 0;
}
