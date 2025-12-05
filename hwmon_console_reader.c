#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

static void dump_hwmon(const char *dir)
{
    char path[PATH_MAX], buf[256];
    FILE *fp;

    snprintf(path, sizeof(path), "%s/name", dir);
    fp = fopen(path, "r");
    if (!fp)
        return;

    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return;
    }
    fclose(fp);
    buf[strcspn(buf, "\r\n")] = '\0';

    printf("%s (%s)\n", dir, buf);

    DIR *d = opendir(dir);
    if (!d)
        return;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *fname = de->d_name;

        if (fname[0] == '.' && (fname[1] == '\0' ||
                                (fname[1] == '.' && fname[2] == '\0')))
            continue;

        if (strncmp(fname, "temp", 4) == 0 && strstr(fname, "_input")) {
            int id = -1;
            if (sscanf(fname, "temp%d_input", &id) != 1)
                continue;

            char label_path[PATH_MAX];
            char input_path[PATH_MAX];
            char label[256] = {0};
            long long val = 0;

            snprintf(label_path, sizeof(label_path), "%s/temp%d_label", dir, id);
            snprintf(input_path, sizeof(input_path), "%s/temp%d_input", dir, id);

            fp = fopen(label_path, "r");
            if (fp) {
                if (fgets(label, sizeof(label), fp))
                    label[strcspn(label, "\r\n")] = '\0';
                fclose(fp);
            } else {
                snprintf(label, sizeof(label), "temp%d", id);
            }

            fp = fopen(input_path, "r");
            if (fp && fscanf(fp, "%lld", &val) == 1) {
                double celsius = val / 1000.0;
                printf("  %s: %.1f °C\n", label, celsius);
            }
            if (fp)
                fclose(fp);
        }

        if (strncmp(fname, "fan", 3) == 0 && strstr(fname, "_input")) {
            int id = -1;
            if (sscanf(fname, "fan%d_input", &id) != 1)
                continue;

            char label_path[PATH_MAX];
            char input_path[PATH_MAX];
            char label[256] = {0};
            long long val = 0;

            snprintf(label_path, sizeof(label_path), "%s/fan%d_label", dir, id);
            snprintf(input_path, sizeof(input_path), "%s/fan%d_input", dir, id);

            fp = fopen(label_path, "r");
            if (fp) {
                if (fgets(label, sizeof(label), fp))
                    label[strcspn(label, "\r\n")] = '\0';
                fclose(fp);
            } else {
                snprintf(label, sizeof(label), "fan%d", id);
            }

            fp = fopen(input_path, "r");
            if (fp && fscanf(fp, "%lld", &val) == 1) {
                printf("  %s: %lld RPM\n", label, val);
            }
            if (fp)
                fclose(fp);
        }

        if (strncmp(fname, "power", 5) == 0 && strstr(fname, "_input")) {
            int id = -1;
            if (sscanf(fname, "power%d_input", &id) != 1)
                continue;

            char label_path[PATH_MAX];
            char input_path[PATH_MAX];
            char label[256] = {0};
            long long val = 0;

            snprintf(label_path, sizeof(label_path), "%s/power%d_label", dir, id);
            snprintf(input_path, sizeof(input_path), "%s/power%d_input", dir, id);

            fp = fopen(label_path, "r");
            if (fp) {
                if (fgets(label, sizeof(label), fp))
                    label[strcspn(label, "\r\n")] = '\0';
                fclose(fp);
            } else {
                snprintf(label, sizeof(label), "power%d", id);
            }

            fp = fopen(input_path, "r");
            if (fp && fscanf(fp, "%lld", &val) == 1) {
                double watts = val / 1000000.0;
                printf("  %s: %.3f W\n", label, watts);
            }
            if (fp)
                fclose(fp);
        }
    }

    closedir(d);
}

int main(void)
{
    if (chdir("/sys/class/hwmon") != 0) {
        perror("chdir hwmon");
        return 1;
    }

    for (int i = 0; i < 64; i++) {
        char dir[64];
        snprintf(dir, sizeof(dir), "hwmon%d", i);
        if (access(dir, R_OK) != 0)
            continue;
        dump_hwmon(dir);
    }

    return 0;
}