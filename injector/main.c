#include "injector.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROCESS_NAME "./PwnAdventure3-Linux-Shipping"

static pid_t findProcessIdByName(const char* processName) {
    DIR* dir;
    struct dirent* entry;
    int pid;

    dir = opendir("/proc");
    if (dir == NULL) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            pid = atoi(entry->d_name);
            if (pid > 0) {
                char cmdPath[255];
                FILE* cmdFile;
                char cmdLine[255];

                snprintf(cmdPath, sizeof(cmdPath), "/proc/%d/cmdline", pid);
                cmdFile = fopen(cmdPath, "r");
                if (cmdFile) {
                    if (fgets(cmdLine, sizeof(cmdLine), cmdFile) != NULL) {
                        // Remove trailing newline character
                        cmdLine[strcspn(cmdLine, "\n")] = '\0';

                        // Compare process name with the requested name
                        if (strcmp(processName, cmdLine) == 0) {
                            fclose(cmdFile);
                            closedir(dir);
                            return pid;
                        }
                    }
                    fclose(cmdFile);
                }
            }
        }
    }

    closedir(dir);
    return -1;
}
int main()
{
	injector_pid_t pid = -1;
	injector_t *injector;
	void *handle;

	pid = findProcessIdByName(PROCESS_NAME);
	if (pid == -1) {
		fprintf(stderr, "[-] Could not find the pid of %s !\n", PROCESS_NAME);
		return -1;
	}
	printf("[+] Found the pid number %d of %s !\n", pid, PROCESS_NAME);
	if (injector_attach(&injector, pid) != 0)
	{
		printf("[-] ATTACH ERROR: %s\n", injector_error());
        return -1;
	}
	printf("[+] Successfully attached to pid %d !\n", pid);
	if (injector_inject(injector, "libGameLogic.so", &handle) != 0) {
        printf("[-] INJECT ERROR: %s\n", injector_error());
		return -1;
    }
	printf("[+] Shared library successfully injected to pid %d !\n", pid);
	
	injector_detach(injector);
}
