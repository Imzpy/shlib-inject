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

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))
#define __unused __attribute__((unused))

static volatile sig_atomic_t should_exit = 0;

extern char __inj_call;
extern char __inj_call_end;
extern char __inj_trap;
#define __inj_call_sz ((size_t)(&__inj_call_end - &__inj_call))

/* function calling injection code */
void __attribute__((naked)) inj_call(void)
{
	/* rax: address of a function to call
	 * rdi, rsi, rdx, rcx, r8, r9: arguments passed to a function
	 *
	 * For dlopen() call injection:
	 *   rax: dlopen() address (void *dlopen(const char *filename, int flags);)
	 *   rdi: address of path to shared library
	 *   rsi: set to 2 (RTLD_LAZY)
	 *
	 * For dlclose() call injection:
	 *   rax: dlclose() address (int dlclose(void *handle);)
	 *   rdi: handle to pass to dlclose
	 */
	__asm__ __volatile__ (
	"__inj_call:					\n\t"
	"	call *%rax				\n\t"
	"__inj_trap:"
	"	int3					\n\t"
	"__inj_call_end:				\n\t"
	);
}

static void signal_handler(int /*sig*/)
{
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	should_exit = 1;
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

	/* XXX: ARM64 will need updating */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mapped;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_machine != EM_X86_64) {
		fprintf(stderr, "Invalid ELF file or not x86_64: %s\n", elf_path);
		goto cleanup;
	}

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

__attribute__((unused))
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

__attribute__((unused))
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

	printf("rip=%llx rax=%llx (orig_rax=%llx) rdi=%llx rsi=%llx rdx=%llx r10=%llx r8=%llx r9=%llx rbp=%llx rsp=%llx\n",
		regs->rip, regs->rax, regs->orig_rax, regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9,
		regs->rbp, regs->rsp);
}

static int ptrace_get_regs(int pid, struct user_regs_struct *regs, const char *descr)
{
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		int err = -errno;
		fprintf(stderr, "ptrace(PTRACE_GETREGS, PID %d, %s) failed: %d\n", pid, descr, err);
		return err;
	}
	return 0;
}

static int ptrace_set_regs(int pid, const struct user_regs_struct *regs, const char *descr)
{
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		int err = -errno;
		fprintf(stderr, "ptrace(PTRACE_SETREGS, PID %d, %s) failed: %d\n", pid, descr, err);
		return err;
	}
	return 0;
}

static int ptrace_set_options(int pid, int options, const char *descr)
{
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, options) < 0) {
		int err = -errno;
		fprintf(stderr, "ptrace(PTRACE_SETOPTIONS, PID %d, opts %x, %s) failed: %d\n",
			pid, options, descr, err);
		return err;
	}
	return 0;
}

__attribute__((unused))
static int ptrace_read_insns(int pid, long rip, void *insns, size_t insn_sz, const char *descr)
{
	long word;

	for (size_t i = 0; i < insn_sz; i += sizeof(word)) {
		errno = 0;
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, rip + i, NULL)) == -1 && errno != 0) {
			int err = -errno;
			fprintf(stderr, "ptrace(PTRACE_PEEKTEXT, pid %d, off %zu, %s) failed: %d\n",
				pid, i, descr, err);
			return err;
		}
		memcpy(insns + i, &word, sizeof(word));
	}
	return 0;
}

static int ptrace_write_insns(int pid, long rip, void *insns, size_t insn_sz, const char *descr)
{
	long word;
	int err;

	for (size_t i = 0; i < insn_sz; i += sizeof(word)) {
		memcpy(&word, insns + i, sizeof(word));

		errno = 0;
		if (ptrace(PTRACE_POKETEXT, pid, rip + i, word) < 0) {
			err = -errno;
			fprintf(stderr, "ptrace(PTRACE_POKETEXT, pid %d, off %zu, %s) failed: %d\n",
				pid, i, descr, err);
			return err;
		}
	}
	return 0;
}

static int ptrace_op(int pid, enum __ptrace_request op, long data, const char *descr)
{
	if (ptrace(op, pid, NULL, data) < 0) {
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

		int err = -errno;
		fprintf(stderr, "ptrace(%s, pid %d, %s) failed: %d\n", op_name, pid, descr, err);
		return err;
	}

	return 0;
}

static int ptrace_wait(int pid, int sig, const char *descr)
{
	int status, err;
	siginfo_t siginfo;

	if (waitpid(pid, &status, WUNTRACED) != pid) {
		err = -errno;
		fprintf(stderr, "waitpid(pid %d, %s) failed: %d\n", pid, descr, err);
		return err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo) < 0) {
		err = -errno;
		fprintf(stderr, "ptrace(PTRACE_GETSIGINFO, pid %d, %s) failed: %d\n", pid, descr, err);
		return err;
	}

	/* XXX: handle this more gracefully, but this will do for now */
	if (siginfo.si_signo != sig) {
		fprintf(stderr, "ptrace_wait(%s): expected signal %d, but got signal %d, bailing!\n",
			descr, sig, siginfo.si_signo);
		return -1;
	}
	return 0;
}

static int ptrace_wait_stop(int pid, const char *descr)
{
	int status, err;

	while (true) {
		if (waitpid(pid, &status, WUNTRACED) != pid) {
			err = -errno;
			fprintf(stderr, "waitpid(pid %d, %s) failed: %d\n", pid, descr, err);
			return err;
		}

		/* this is what he hope to get */
		if (WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP && WSTOPSIG(status) == SIGTRAP)
		{
			//printf("STOPPED WITH PTRACE_EVENT_STOP STOPSIG=%d\n", WSTOPSIG(status));
			return 0;
		}

		if (WIFEXITED(status))
			return -ENOENT;
	}
}

static int ptrace_wait_signal(int pid, int signal, long ip __unused, const char *descr)
{
	int status, err;

	while (true) {
		if (waitpid(pid, &status, WUNTRACED) != pid) {
			err = -errno;
			fprintf(stderr, "waitpid(pid %d, %s) failed: %d\n", pid, descr, err);
			return err;
		}

		if (WIFEXITED(status))
			return -ENOENT;

		/* TODO: check for IP to match with PTRACE_GETSIGINFO */
		if (WIFSTOPPED(status) &&
		    WSTOPSIG(status) == signal)
			return 0;

		err = ptrace_op(pid, PTRACE_CONT, WSTOPSIG(status), "wait-signal-cont");
		if (err)
			return err;
	}
}

static int ptrace_wait_syscall(int pid, const char *descr)
{
	int status, err;

	while (true) {
		if (waitpid(pid, &status, WUNTRACED) != pid) {
			err = -errno;
			fprintf(stderr, "waitpid(pid %d, %s) failed: %d\n", pid, descr, err);
			return err;
		}

		/* this is what he hope to get */
		if (WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)))
			return 0;

		if (WIFEXITED(status))
			return -ENOENT;

		err = ptrace_op(pid, PTRACE_CONT, WSTOPSIG(status), "wait-syscall-cont");
		if (err)
			return err;
	}
}

__attribute__((unused))
static int ptrace_exec(int pid, long rip, void *insns, size_t insns_sz,
		       const struct user_regs_struct *in_regs, struct user_regs_struct *out_regs,
		       const char *descr)
{
	int err = 0;

	err = err ?: ptrace_write_insns(pid, rip, insns, insns_sz, descr);
	err = err ?: ptrace_set_regs(pid, in_regs, descr);
	err = err ?: ptrace_op(pid, PTRACE_CONT, 0, descr);
	err = err ?: ptrace_wait(pid, SIGTRAP, descr);
	if (err == 0 && out_regs)
		err = err ?: ptrace_get_regs(pid, out_regs, descr);
	return err;
}

__attribute__((unused))
static int ptrace_exec_syscall(int pid,
			       const struct user_regs_struct *pre_regs,
			       struct user_regs_struct *post_regs,
			       const char *descr)
{
	int err = 0;

	err = err ?: ptrace_set_regs(pid, pre_regs, descr);
	err = err ?: ptrace_op(pid, PTRACE_SYSCALL, 0, descr);
	err = err ?: ptrace_wait_syscall(pid, descr);
	err = err ?: ptrace_get_regs(pid, post_regs, descr);

	return err;
}

__attribute__((unused))
static int ptrace_restart_syscall(int pid,
			       const struct user_regs_struct *orig_regs,
			       const char *descr)
{
	int err = 0;

	err = err ?: ptrace_set_regs(pid, orig_regs, descr);
	err = err ?: ptrace_op(pid, PTRACE_SYSCALL, 0, descr);
	err = err ?: ptrace_wait_syscall(pid, descr);

	return err;
}

__attribute__((unused))
static int ptrace_cont_syscall(int pid, const char *descr)
{
	int err = 0;

	err = err ?: ptrace_op(pid, PTRACE_SYSCALL, 0, descr);
	err = err ?: ptrace_wait_syscall(pid, descr);

	return err;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	struct sigaction sa;
	bool fatal = false;
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
	void *(*dlopen)(const char *name, int flags);
	dlopen = (void*)libc_self_base + dlopen_off;
	dlopen("/data/users/andriin/shlib-inject/libinj.so", RTLD_LAZY);

	while (true) { printf("YAY!\n"); sleep(1); }
	*/

	int pid_fd = syscall(SYS_pidfd_open, pid, 0);
	if (pid_fd < 0) {
		err = -errno;
		fprintf(stderr, "pidfd_open(%d) failed: %d\n", pid, err);
		return 1;
	}

	printf("Seizing PID %d...\n", pid);
	if (ptrace_op(pid, PTRACE_SEIZE, 0, "tracee-seize") < 0)
		return 1;

	printf("Interrupting PID %d...\n", pid);
	if (ptrace_op(pid, PTRACE_INTERRUPT, 0, "tracee-interrupt") < 0)
		return 1;

	printf("Waiting for PID %d to be interrupted...\n", pid);
	if (ptrace_wait_stop(pid, "tracee-wait-stop") < 0)
		return 1;

	printf("Setting PTRACE_O_TRACESYSGOOD option for PID %d...\n", pid);
	if (ptrace_set_options(pid, PTRACE_O_TRACESYSGOOD, "tracee-set-opts") < 0)
		return 1;

	printf("Resuming until syscall...\n");
	if (ptrace_op(pid, PTRACE_SYSCALL, 0, "tracee-resume-until-syscall") < 0)
		return 1;

	printf("Waiting for syscall-entry...\n");
	if (ptrace_wait_syscall(pid, "wait-syscall-enter") < 0)
		return 1;

	struct user_regs_struct orig_regs, regs;
	if (ptrace_get_regs(pid, &orig_regs, "backup-regs") < 0)
		return 1;

	/* XXX: amr64 will need something else */
	orig_regs.rip -= 2; /* adjust for syscall replay, syscall instruction is 2 bytes */
	print_regs(&orig_regs, "ORIG REGS");

	/* HIJACK SYSCALL: mmap(r-xp) */
	const long page_size = sysconf(_SC_PAGESIZE);
	const long exec_mmap_sz = page_size;
	long exec_mmap_addr = 0;

	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	/* void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); */
	regs.orig_rax = __NR_mmap;
	regs.rdi = 0; /* addr */
	regs.rsi = exec_mmap_sz; /* length */
	regs.rdx = PROT_EXEC | PROT_READ; /* prot */
	regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE; /* flags */
	regs.r8 = 0; /* fd */
	regs.r9 = 0; /* offset */
	if (ptrace_exec_syscall(pid, &regs, &regs, "hijack-mmap-exec") < 0)
		return 1;
	exec_mmap_addr = regs.rax;
	if (exec_mmap_addr <= 0) {
		fprintf(stderr, "mmap(r-xp) inside tracee failed: %ld, bailing!\n", exec_mmap_addr);
		return 1;
	}
	printf("mmap(r-xp) result: 0x%lx\n", (long)exec_mmap_addr);

	printf("Restarting syscall...\n");
	if (ptrace_restart_syscall(pid, &orig_regs, "hijack-syscall-restart") < 0)
		return 1;

	/* HIJACK SYSCALL: mmap(rw-p) */
	const long data_mmap_sz = page_size;
	long data_mmap_addr = 0;

	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.orig_rax = __NR_mmap;
	regs.rdi = 0; /* addr */
	regs.rsi = data_mmap_sz; /* length */
	regs.rdx = PROT_WRITE | PROT_READ; /* prot */
	regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE; /* flags */
	regs.r8 = 0; /* fd */
	regs.r9 = 0; /* offset */
	if (ptrace_exec_syscall(pid, &regs, &regs, "hijack-mmap-data") < 0)
		return 1;
	data_mmap_addr = regs.rax;
	if (data_mmap_addr <= 0) {
		fprintf(stderr, "mmap(rw-p) inside tracee failed: %ld, bailing!\n", data_mmap_addr);
		return 1;
	}
	printf("mmap(rw-p) result: 0x%lx\n", (long)data_mmap_addr);

	printf("Restarting syscall...\n");
	if (ptrace_restart_syscall(pid, &orig_regs, "hijack-syscall-restart") < 0)
		return 1;

	/* HIJACK SYSCALL: memfd_create() */
	int memfd_remote_fd = -1;
	char memfd_name[] = "shlib-inject";

	err = remote_vm_write(pid, (void *)data_mmap_addr, memfd_name, sizeof(memfd_name));
	if (err)
		return 1;

	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	/* int memfd_create(const char *name, unsigned int flags); */
	regs.orig_rax = __NR_memfd_create;
	regs.rdi = data_mmap_addr; /* name */
	regs.rsi = MFD_CLOEXEC; /* flags */
	if (ptrace_exec_syscall(pid, &regs, &regs, "hijack-memfd_create") < 0)
		return 1;
	memfd_remote_fd = regs.rax;
	if (memfd_remote_fd < 0) {
		fprintf(stderr, "memfd_create() inside tracee failed: %d, bailing!\n", memfd_remote_fd);
		return 1;
	}
	printf("memfd_create() result: %d\n", memfd_remote_fd);

	int memfd_local_fd = syscall(SYS_pidfd_getfd, pid_fd, memfd_remote_fd, 0);
	if (memfd_local_fd < 0) {
		err = -errno;
		fprintf(stderr, "pidfd_getfd(pid %d, remote_fd %d) failed: %d\n", pid, memfd_remote_fd, err);
		return 1;
	}

	/* XXX: embed shared lib into memory */
	err = copy_file_to_fd("libinj.so", memfd_local_fd);
	if (err)
		return 1;

	/* Copy over memfd path for passing into dlopen() */
	char memfd_path[64];
	snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd_remote_fd);
	err = remote_vm_write(pid, (void *)data_mmap_addr, memfd_path, sizeof(memfd_path));
	if (err)
		return 1;

	/* Copy over inj_call() code into executable mmap() */
	if (ptrace_write_insns(pid, exec_mmap_addr, &__inj_call, __inj_call_sz, "write-inj-call"))
		return 1;

	long inj_trap_addr = exec_mmap_addr + &__inj_trap - &__inj_call;

	printf("Executing dlopen() injection...\n");
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.rip = exec_mmap_addr;
	regs.rax = dlopen_tracee_addr;
	regs.rdi = data_mmap_addr; /* name */
	regs.rsi = RTLD_LAZY; /* flags */
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	print_regs(&regs, "REGS");

	if (ptrace_set_regs(pid, &regs, "set-inj_dlopen-regs") < 0)
		return 1;
	if (ptrace_op(pid, PTRACE_CONT, 0, "run-inj_dlopen") < 0)
		return 1;
	if (ptrace_wait_signal(pid, SIGTRAP, inj_trap_addr, "wai-inj_dlopen") < 0)
		return 1;
	if (ptrace_get_regs(pid, &regs, "get_inj_dlopen-regs") < 0)
		return 1;

	long dlopen_handle = regs.rax;
	printf("dlopen() result: %lx\n", dlopen_handle);
	if (dlopen_handle == 0) {
		fprintf(stderr, "Failed to dlopen() injection library, bailing...\n");
		return 1;
	}

	printf("Restarting syscall...\n");
	if (ptrace_restart_syscall(pid, &orig_regs, "hijack-syscall-restart") < 0)
		return 1;

	/* REPLAY ORIGINAL SYSCALL */
	printf("Replaying syscall...\n");
	if (ptrace_op(pid, PTRACE_CONT, 0, "syscall-continue") < 0)
		return 1;

	sleep(1);

	/* Now, let's unwind everything back */
	printf("Interrupting PID %d...\n", pid);
	if (ptrace_op(pid, PTRACE_INTERRUPT, 0, "tracee-interrupt") < 0)
		return 1;
	printf("Waiting for PID %d to be interrupted...\n", pid);
	if (ptrace_wait_stop(pid, "tracee-wait-stop") < 0)
		return 1;
	printf("Setting PTRACE_O_TRACESYSGOOD option for PID %d...\n", pid);
	if (ptrace_set_options(pid, PTRACE_O_TRACESYSGOOD, "tracee-set-opts") < 0)
		return 1;
	printf("Resuming until syscall...\n");
	if (ptrace_op(pid, PTRACE_SYSCALL, 0, "tracee-resume-until-syscall") < 0)
		return 1;
	printf("Waiting for syscall-entry...\n");
	if (ptrace_wait_syscall(pid, "wait-syscall-enter") < 0)
		return 1;
	if (ptrace_get_regs(pid, &orig_regs, "backup-regs") < 0)
		return 1;
	orig_regs.rip -= 2; // adjust for syscall replay, syscall instruction is 2 bytes

	print_regs(&orig_regs, "ORIG REGS (2)");

	/* dlclose() doesn't work for some reason */
	goto skip_dlclose;
	
	printf("Executing dlclose() injection...\n");
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	regs.rip = exec_mmap_addr;
	regs.rax = dlclose_tracee_addr;
	regs.rdi = dlopen_handle;
	regs.rsp = (regs.rsp & ~0xFULL) - 128; /* ensure 16-byte alignment and set up red zone */

	print_regs(&regs, "REGS");

	if (ptrace_set_regs(pid, &regs, "set-inj_dlclose-regs") < 0)
		return 1;
	if (ptrace_op(pid, PTRACE_CONT, 0, "run-inj_dlclose") < 0)
		return 1;
	if (ptrace_wait_signal(pid, SIGTRAP, inj_trap_addr, "wai-inj_dlclose") < 0)
		return 1;
	if (ptrace_get_regs(pid, &regs, "get_inj_dlclose-regs") < 0)
		return 1;
	int dlclose_ret = regs.rax;
	printf("dlclose() result: %d\n", dlclose_ret);
	if (dlclose_ret < 0) {
		fprintf(stderr, "Failed to dlclose() injection library, bailing...\n");
		return 1;
	}
	printf("Restarting syscall...\n");
	if (ptrace_restart_syscall(pid, &orig_regs, "hijack-syscall-restart") < 0)
		return 1;

skip_dlclose:
	/* Inject munmap(rw-p) syscall */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	/* int munmap(void *addr, size_t len); */
	regs.orig_rax = __NR_munmap;
	regs.rdi = data_mmap_addr;
	regs.rsi = data_mmap_sz;
	if (ptrace_exec_syscall(pid, &regs, &regs, "hijack-munmap-data") < 0)
		return 1;
	long data_munmap_ret = regs.rax;
	if (data_munmap_ret < 0) {
		fprintf(stderr, "munmap(rw-p) inside tracee failed: %ld, bailing!\n", data_munmap_ret);
		return 1;
	}
	printf("munmap(rw-p) result: 0x%lx\n", data_munmap_ret);

	printf("Restarting syscall...\n");
	if (ptrace_restart_syscall(pid, &orig_regs, "hijack-syscall-restart") < 0)
		return 1;

	/* Inject munmap(r-xp) syscall */
	memcpy(&regs, &orig_regs, sizeof(orig_regs));
	/* int munmap(void *addr, size_t len); */
	regs.orig_rax = __NR_munmap;
	regs.rdi = exec_mmap_addr;
	regs.rsi = exec_mmap_sz;
	if (ptrace_exec_syscall(pid, &regs, &regs, "hijack-munmap-exec") < 0)
		return 1;
	long exec_munmap_ret = regs.rax;
	if (exec_munmap_ret < 0) {
		fprintf(stderr, "munmap(r-xp) inside tracee failed: %ld, bailing!\n", exec_munmap_ret);
		return 1;
	}
	printf("munmap(r-xp) result: 0x%lx\n", exec_munmap_ret);

	printf("Restarting syscall...\n");
	if (ptrace_restart_syscall(pid, &orig_regs, "hijack-syscall-restart") < 0)
		return 1;

	/* REPLAY ORIGINAL SYSCALL */
	printf("Replaying syscall...\n");
	if (ptrace_op(pid, PTRACE_CONT, 0, "syscall-continue") < 0)
		return 1;

	/* FROM NOW ON, we need to restore tracee on error */
	fatal = true;

	fatal = false;

	/*
	printf("Continuing tracee...\n");
	if (ptrace_op(pid, PTRACE_CONT, 0, "tracee_continue") < 0)
		return 1;
		*/

	if (fatal)
		return 1;

	printf("Tracee is running...\n");

	printf("Press Ctrl-C to exit...\n");

	while (!should_exit) {
		usleep(50000);
	}

	//int tmp; scanf("%d", &tmp);
	printf("Detaching tracee...\n");
	if (ptrace_op(pid, PTRACE_DETACH, 0, "tracee_detach") < 0)
		return 1;
	printf("Tracee detached...\n");

	printf("Exited gracefully.\n");
	return 0;
}
