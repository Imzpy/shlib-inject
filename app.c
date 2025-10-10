#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <elf.h>
#include "app_lib.h"

/*
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
		    strstr(pathname, ".so") {
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
*/
int main() {
	int cnt = 0;

	/*
	long libc_self_end = 0;
	long libc_self_base = find_libc_base(-1, &libc_self_end);
	if (libc_self_base == 0)
		return 1;
	char libc_path[512];
	snprintf(libc_path, sizeof(libc_path), "/proc/self/map_files/%lx-%lx", libc_self_base, libc_self_end);
	long dlopen_off = find_elf_sym_info(libc_path, "__libc_dlopen_mode");
	if (dlopen_off == 0)
		return 1;
	printf("Local libc base: 0x%lx (__libc_dlopen_mode offset %lx)\n",
	       libc_self_base, dlopen_off);

	void *(*dlopen)(const char *name, int flags);
	dlopen = (void*)libc_self_base + dlopen_off;
	dlopen("/data/users/andriin/shlib-inject/libinj.so", RTLD_LAZY);
	       */

	//void *res = dlopen("./libinj.so", RTLD_LAZY);
	//printf("DLOPEN RES %lx\n", (long)res);

	while (1) {
		char buf[256];

		snprintf(buf, sizeof(buf), "Hello from app (%d)!\n", ++cnt);
		fancy_print(buf);
		sleep(1);
	}

	return 0;
}
