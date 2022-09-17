#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

int main() {
	printf("[*] Waiting for any key...\n");
	system("pause");

	MessageBoxW(NULL, L"Normal Message!", L"Alert", MB_OK);
	return 0;
}