#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void dump_domain(const char *dir)
{
	char path[PATH_MAX], buf[256];
	unsigned long long val;

	snprintf(path, sizeof(path), "%s/name", dir);
	FILE *fp = fopen(path, "r");
	if (!fp)
		return;
	if (!fgets(buf, sizeof(buf), fp)) {
		fclose(fp);
		return;
	}
	fclose(fp);
	buf[strcspn(buf, "\r\n")] = '\0';

	printf("%s (%s)\n", dir, buf);

	snprintf(path, sizeof(path), "%s/energy_uj", dir);
	if ((fp = fopen(path, "r")) && fscanf(fp, "%llu", &val) == 1)
		printf("  energy_uj=%llu\n", val);
	if (fp)
		fclose(fp);

	snprintf(path, sizeof(path), "%s/power_uw", dir);
	if ((fp = fopen(path, "r")) && fscanf(fp, "%llu", &val) == 1)
		printf("  power_uw=%llu\n", val);
	if (fp)
		fclose(fp);
}

int main(void)
{
	if (chdir("/sys/class/powercap") != 0) {
		perror("chdir powercap");
		return 1;
	}

	for (int i = 0; i < 32; i++) {
		char dir[64];
		snprintf(dir, sizeof(dir), "intel-rapl:%d", i);
		if (access(dir, R_OK) != 0)
			continue;
		dump_domain(dir);
		for (int j = 0; j < 32; j++) {
			char sub[96];
			snprintf(sub, sizeof(sub), "%s:%d", dir, j);
			if (access(sub, R_OK) != 0)
				continue;
			dump_domain(sub);
		}
	}
	return 0;
}
