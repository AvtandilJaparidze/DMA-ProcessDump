#include <stdio.h>
#include <unistd.h>
#include <string>
#include <thread>

#include "memory.h"

std::string GetArgFromCommandLine(int argc, char *argv[], const char* ArgName)
{
	for (int i = 0; i < argc; i++)
	{
		if (std::strcmp(argv[i], ArgName) == 0)
		{
			return std::string(argv[i + 1]);
		}
	}

	return std::string();
}

int main(int argc, char *argv[])
{
	if (geteuid() != 0)
	{
		printf("Error: %s is not running as root\n", argv[0]);
		return 0;
	}

	const std::string ProcessName = GetArgFromCommandLine(argc, argv, "-p");
	const std::string SocketPath = GetArgFromCommandLine(argc, argv, "-s");

	if (ProcessName.empty() || SocketPath.empty())
	{
		printf("invalid arguments provided.\n");
		return EXIT_FAILURE;
	}

	char line[10];
	FILE* cmd = popen("pidof /usr/bin/qemu-system-x86_64 -s", "r");

	fgets(line, 10, cmd);
	pid_t qemuPid = strtoul(line, NULL, 10);

	if (qemuPid == 0)
	{
		printf("failed to find qemu process.\n");
		return EXIT_FAILURE;
	}

	const std::string commandLine = "qemu://hugepage-pid=" + std::to_string(qemuPid) + ",qmp=" + SocketPath;

	LPCSTR argss[] = {(LPCSTR)"", (LPCSTR)"-device", (LPCSTR)commandLine.c_str()};
	int argcc = 3;
	hVMM = VMMDLL_Initialize(argcc, argss);

	VMMDLL_InitializePlugins(hVMM);

	std::this_thread::sleep_for(std::chrono::seconds(2));

	printf("MemProcFS initialized\n");

	Memory memory = Memory();
	memory.OpenProcess(ProcessName.c_str());
	memory.DumpProcess();

	return EXIT_SUCCESS;
}