#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main() {
	printf("[*] Waiting for any key...\n");
	system("pause");

	MessageBoxW(NULL, L"Normal Message!", L"Alert", MB_OK);
	return 0;
}
