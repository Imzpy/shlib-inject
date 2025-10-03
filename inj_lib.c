#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>

static void (*original_fancy_print)(const char *str) = NULL;

__attribute__((constructor))
void init_libinj()
{
    printf("libinj.so: Constructor called - library loaded\n");
}

__attribute__((destructor))
void cleanup_libinj()
{
    printf("libinj.so: Destructor called - library unloaded\n");
}

void fancy_print(const char *str)
{
	if (!original_fancy_print) {
		original_fancy_print = dlsym(RTLD_NEXT, "fancy_print");
		if (original_fancy_print)
			printf("libinj.so: Found original fancy_print at %p\n", (void*)original_fancy_print);
		else
			printf("libinj.so: Could not find original fancy_print\n");
	}

	printf("!!!!!!---");

	if (original_fancy_print && str) {
		size_t len = strlen(str);

		if (len > 0 && str[len - 1] == '\n') {
			char *temp_str = strdup(str);

			temp_str[len - 1] = '\0';
			original_fancy_print(temp_str);

			free(temp_str);
		} else {
			original_fancy_print(str);
		}
	} else if (original_fancy_print) {
		original_fancy_print(str);
	} else {
		printf("FALLBACK(%s)", str ?: "(null)");
	}

	printf("---!!!!!!\n");
}
