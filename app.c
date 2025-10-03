#include <stdio.h>
#include <unistd.h>
#include "app_lib.h"

int main() {
	int cnt = 0;

	while (1) {
		char buf[256];

		snprintf(buf, sizeof(buf), "Hello from app (%d)!\n", ++cnt);
		fancy_print(buf);
		sleep(1);
	}

	return 0;
}
