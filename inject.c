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
#include <wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (y) : (x))

static volatile sig_atomic_t should_exit = 0;

extern char __inj_dlopen;
extern char __inj_dlopen_end;
#define __inj_dlopen_sz ((size_t)(&__inj_dlopen_end - &__inj_dlopen))

extern void *__libc_dlopen_mode(const char *file, int mode);

/* injection bootstrapping code */
void __attribute__((naked)) inj_dlopen(void)
{
	/*
	 * rax: dlopen() address (void *dlopen(const char *path, int flags);)
	 * rdi: will be set below to __injboot_path_buf address, containing shared libarary path
	 * rsi: set to 2 (RTLD_LAZY)
	 */
	__asm__ __volatile__ (
	"__inj_dlopen:					\n\t"
	//"	lea __inj_dlopen_path(%rip), %rdi	\n\t"
	"	call *%rax				\n\t"
	"	int3					\n\t"
	"__inj_dlopen_end:				\n\t"
	);
}

extern char __inj_syscall;
extern char __inj_syscall_end;
#define __inj_syscall_sz ((size_t)(&__inj_syscall_end - &__inj_syscall))

void __attribute__((naked)) inj_syscall(void)
{
	/*
	 * rax: syscall number
	 * rdi, rsi, rdx, r10, r8, r9: syscall args
	 */
	__asm__ __volatile__ (
	"__inj_syscall:					\n\t"
	"	syscall 				\n\t"
	"	int3					\n\t"
	"__inj_syscall_end:				\n\t"
	);
}

static void cleanup_callback()
{
	printf("\nPerforming cleanup...\n");
}

static void signal_handler(int sig)
{
	printf("\nReceived signal %d\n", sig);
	cleanup_callback();
	should_exit = 1;
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

static int ptrace_op(int pid, enum __ptrace_request op, const char *descr)
{
	if (ptrace(op, pid, NULL, NULL) < 0) {
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
	int wait_status, err;
	siginfo_t siginfo;

	if (waitpid(pid, &wait_status, WUNTRACED) != pid) {
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

static int ptrace_exec(int pid, long rip, void *insns, size_t insns_sz,
		       const struct user_regs_struct *in_regs, struct user_regs_struct *out_regs,
		       const char *descr)
{
	int err = 0;

	err = err ?: ptrace_write_insns(pid, rip, insns, insns_sz, descr);
	err = err ?: ptrace_set_regs(pid, in_regs, descr);
	err = err ?: ptrace_op(pid, PTRACE_SINGLESTEP, descr);
	err = err ?: ptrace_wait(pid, SIGTRAP, descr);
	if (err == 0 && out_regs)
		err = err ?: ptrace_get_regs(pid, out_regs, descr);
	return err;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	struct sigaction sa;
	bool fatal = false;
	long mmap_res = -1;
	long mmap_sz = 4096;

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

	printf("Attaching to PID %d...\n", pid);
	if (ptrace_op(pid, PTRACE_ATTACH, "tracee-attach") < 0)
		return 1;

	printf("Waiting for PID %d to complete attachment...\n", pid);
	if (ptrace_wait(pid, SIGSTOP, "wait-attach") < 0)
		return 1;

	size_t insn_backup_sz = 0;
	insn_backup_sz = max(insn_backup_sz, __inj_dlopen_sz);
	insn_backup_sz = max(insn_backup_sz, __inj_syscall_sz);
	insn_backup_sz = (insn_backup_sz + 7) / 8 * 8;
	char insn_backup[insn_backup_sz];

	struct user_regs_struct old_regs, regs;
	memset(&old_regs, 0, sizeof(old_regs));

	printf("Backing up original registers...\n");
	if (ptrace_get_regs(pid, &old_regs, "backup-regs") < 0)
		return 1;
	printf("Backed up original registers (RIP 0x%llx).\n", old_regs.rip);

	printf("Backing up original code at 0x%llx...\n", old_regs.rip);
	if (ptrace_read_insns(pid, old_regs.rip, insn_backup, insn_backup_sz, "backup-insns") < 0)
		return 1;

	/* FROM NOW ON, we need to restore tracee on error */
	fatal = true;

	/* Execute mmap() syscall (inside tracee):
	 * void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
	 * int munmap(void *addr, size_t length);
	 */
	printf("Executing mmap() syscall...\n");
	memcpy(&regs, &old_regs, sizeof(old_regs));
	regs.rax = __NR_mmap;
	regs.rdi = 0; /* addr */
	regs.rsi = mmap_sz; /* length */
	regs.rdx = PROT_WRITE | PROT_READ; /* prot */
	regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE; /* flags */
	regs.r8 = 0; /* fd */
	regs.r9 = 0; /* offset */
	if (ptrace_exec(pid, old_regs.rip, &__inj_syscall, __inj_syscall_sz, &regs, &regs, "call-mmap") < 0)
		goto restore_tracee;

	mmap_res = regs.rax;
	if (mmap_res < 0) {
		fprintf(stderr, "mmap() inside tracee failed: %ld, bailing!\n", mmap_res);
		goto restore_tracee;
	}
	printf("mmap result: 0x%lx\n", (long)mmap_res);

	//regs.rip = 0x0000; /* address of copied injboot() */ 
	//regs.rax = 0x0000; /* address of dlopen */
	//regs.rsi = 2;

	fatal = false;

restore_tracee:
	if (ptrace_set_regs(pid, &old_regs, "restore_regs") < 0)
		return 1;
	printf("Restored original registers...\n");

	if (ptrace_write_insns(pid, old_regs.rip, insn_backup, insn_backup_sz, "restore_insns") < 0)
		return 1;
	printf("Restored original insn at 0x%llx...\n", old_regs.rip);

	printf("Continuing tracee...\n");
	if (ptrace_op(pid, PTRACE_CONT, "tracee_continue") < 0)
		return 1;

	if (fatal)
		return 1;

	printf("Tracee is running...\n");

	printf("Press Ctrl-C to exit...\n");

	while (!should_exit) {
		usleep(50000);
	}

	printf("Detaching tracee...\n");
	if (ptrace_op(pid, PTRACE_DETACH, "tracee_detach") < 0)
		return 1;
	printf("Tracee detached...\n");

	printf("Exited gracefully.\n");
	return 0;
}
