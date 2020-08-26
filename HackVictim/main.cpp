#include <Windows.h>
#include <stdio.h>
#include "resource.h"

BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
VOID CenterDialog(HWND hDlg);
VOID SetNewImageBase(LPVOID pImageBuffer, DWORD dwNewImageBase);
void MemoryInject(DWORD dwPID);
DWORD FileToMemory(LPCSTR lpszFile, LPVOID *pFileBuffer);
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID *pImageBuffer);
BOOL EnableDebugPrivilege();
void RepairIAT(LPVOID pImageBuffer);
BOOL WriteSharedMemory(LPVOID pData, DWORD dwDataSize, const char*lpName);
BOOL ReadSharedMemory(LPVOID *pBuffer, const char *lpName);



// ���α�ʾMessageBoxA, CreateFileA, OpenProcess �ļ���״̬����3λ���ζ�Ӧ���������Ƿ����Զ�̵���
BYTE g_bOrderState[6] = {0};


int main()
{	
	EnableDebugPrivilege();	
	HINSTANCE hInstance = GetModuleHandle(NULL);
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);
	return 0;
}

// �Ի��򴰿ڹ���
BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{			
			CenterDialog(hDlg);  			
			return TRUE;
		}
	case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
			case IDC_BUTTON_INJECT:
				{
					HWND hEdit = GetDlgItem(hDlg, IDC_EDIT_PID);
					char szPID[6] = {0};
					GetWindowTextA(hEdit, szPID, 6);
					DWORD dwPID = 0;
					sscanf(szPID,"%d", &dwPID);
					MemoryInject(dwPID);					
					return TRUE;
				}
			case IDC_BUTTON_MONITOR_MSGBOX:
				{		
					HWND hBtn = GetDlgItem(hDlg,IDC_BUTTON_MONITOR_MSGBOX);
					if (g_bOrderState[0] == TRUE) SetWindowText(hBtn,"�������");					
					else SetWindowText(hBtn,"������");
					g_bOrderState[0] = !g_bOrderState[0];
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");
					return TRUE;
				}
			case IDC_BUTTON_MONITOR_CREATEFILE:
				{
					HWND hBtn = GetDlgItem(hDlg,IDC_BUTTON_MONITOR_CREATEFILE);
					if (g_bOrderState[1] == TRUE) SetWindowText(hBtn,"�������");					
					else SetWindowText(hBtn,"������");
					g_bOrderState[1] = !g_bOrderState[1];
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");
					return TRUE;
				}
			case IDC_BUTTON_MONITOR_ADD:
				{
					HWND hBtn = GetDlgItem(hDlg,IDC_BUTTON_MONITOR_ADD);
					if (g_bOrderState[2] == TRUE) SetWindowText(hBtn,"�������");					
					else SetWindowText(hBtn,"������");
					g_bOrderState[2] = !g_bOrderState[2];
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");
					return TRUE;
				}
			case IDC_BUTTON_CALL_MSGBOX:
				{
					g_bOrderState[3] = 1;
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");					
					g_bOrderState[3] = 0;					
					return TRUE;
				}
			case IDC_BUTTON_CALL_CREATEFILE:
				{
					g_bOrderState[4] = 1;
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");					
					g_bOrderState[4] = 0;
					return TRUE;
				}
			case IDC_BUTTON_CALL_ADD:
				{
					g_bOrderState[5] = 1;
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");					
					g_bOrderState[5] = 0;
					return TRUE;
				}
				
			}
			return TRUE;
		}
		
	case WM_CLOSE:
		{
			EndDialog(hDlg, 0);
			return TRUE;
		}
			
	}
	return FALSE;
}

VOID CenterDialog(HWND hDlg)
{
	HWND hwndOwner = NULL;
	RECT rcOwner, rcDlg, rc;			
	// Get the owner window and dialog box rectangles. 			
	if ((hwndOwner = GetParent(hDlg)) == NULL) 
	{
		hwndOwner = GetDesktopWindow(); 
	}			
	GetWindowRect(hwndOwner, &rcOwner); 
	GetWindowRect(hDlg, &rcDlg); 
	CopyRect(&rc, &rcOwner); 
	
	// Offset the owner and dialog box rectangles so that right and bottom 
	// values represent the width and height, and then offset the owner again 
	// to discard space taken up by the dialog box. 
	
	OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
	OffsetRect(&rc, -rc.left, -rc.top); 
	OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 
	
	// The new position is the sum of half the remaining space and the owner's 
	// original position. 
	
	SetWindowPos(hDlg, 
		HWND_TOP, 
		rcOwner.left + (rc.right / 2), 
		rcOwner.top + (rc.bottom / 2), 
		0, 0,          // Ignores size arguments. 
		SWP_NOSIZE); 
}

// �ڴ�ע��
void MemoryInject(DWORD dwPID)
{
	// ��ȡDLL������
	LPVOID pDllFileBuffer = NULL, pDllImageBuffer = NULL;
	DWORD dwFileBufferSize = FileToMemory("HackVictimDll.dll",&pDllFileBuffer);
	DWORD dwSizeOfImage = FileBufferToImageBuffer(pDllFileBuffer, &pDllImageBuffer);	
	//LPVOID pImageBuffer = pDllImageBuffer;	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));	
	// ����Ϸ���������ڴ�
	printf("����id: %d\n", dwPID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPID);
	LPVOID pRemoteImageBase = VirtualAllocEx(hProcess,NULL,dwSizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if (NULL == pRemoteImageBase)
	{
		printf("����Ϸ���������ڴ�ʧ�ܣ�������: %d\n", GetLastError());
		return;
	}
	// �޸�IAT
	RepairIAT(pDllImageBuffer);
	// �޸��ض�λ��д�뵽��Ϸ����
	SetNewImageBase(pDllImageBuffer, (DWORD)pRemoteImageBase);
	WriteProcessMemory(hProcess,pRemoteImageBase,pDllImageBuffer,dwSizeOfImage,NULL);	
	
	// ������ں�����ַ
	HMODULE hDll = LoadLibraryA("HackVictimDll.dll");
	DWORD dwInjectEntry = (DWORD)GetProcAddress(hDll, "_InjectEntry@4");
	if (dwInjectEntry == NULL)
	{
		printf("��ȡ������ַʧ�ܣ�������: %d\n", GetLastError());
	}
	DWORD dwProcOffset = dwInjectEntry - (DWORD)hDll + (DWORD)pRemoteImageBase;
 	printf("��ǰ��ַ�ռ�DLL��ַ: 0x%X\n", (DWORD)hDll);
// 	printf("��ǰ��ַ�ռ���ں�����ַ: 0x%X\n", dwInjectEntry);
 	printf("Զ�̵�ַ�ռ�DLL��ַ: 0x%X\n", (DWORD)pRemoteImageBase);
// 	printf("Զ����ں�����ַ: 0x%X\n", dwProcOffset);

	DWORD dwPRemoteImageBase = (DWORD)pRemoteImageBase;
	WriteSharedMemory(&dwPRemoteImageBase, sizeof(DWORD),"hackvictimimagebase"); // ������ע���DLL�Լ��Ļ�ַ	
	
	// ����Զ���̣߳�ִ����ڴ���	
	CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)dwProcOffset,NULL,NULL,NULL);
	printf("����Զ���̳߳ɹ�\n");
	
}

// �޸� ImageBase ���޸��ض�λ��
// �ڴ澵��汾
VOID SetNewImageBase(LPVOID pImageBuffer, DWORD dwNewImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + \
		pOptionHeader->DataDirectory[5].VirtualAddress);
	DWORD dwImageBaseDelta = dwNewImageBase - pOptionHeader->ImageBase; // �¾�ImageBase �Ĳ�ֵ	
	
	// �ض�λ��� VirtualAddress + ��12λƫ�� = RVA
	// RVA + ImageBase ����ڴ���洢��һ����ָ�롱
	// Ҫ�޸ĵ��������ָ�롱��ֵ��Ҫ�������ָ�롱��������ImageBase�Ĳ�ֵ
	while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock)
	{
		size_t n = (pRelocationTable->SizeOfBlock - 8) / 2; // ������Ҫ�޸ĵĵ�ַ��������4λ==0011��Ҫ�޸ģ�
		PWORD pOffset = (PWORD)((DWORD)pRelocationTable + 8); // 2�ֽ�ƫ�Ƶ�����
		for (size_t i = 0; i < n; i++)
		{
			// ��4λ����0011����Ҫ�ض�λ
			if ((pOffset[i] & 0xF000) == 0x3000)
			{
				// ������Ҫ�ض�λ�����ݵ�RVA��ַ
				DWORD dwRva = pRelocationTable->VirtualAddress + (pOffset[i] & 0x0FFF);				
				// �����ھ����еĵ�ַ
				PDWORD pData = (PDWORD)((DWORD)pImageBuffer + dwRva);
				// �ض�λ��������д���ĵ�ַ				
				*pData += dwImageBaseDelta;
			}
		}		
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	// �޸� ImageBase
	pOptionHeader->ImageBase = dwNewImageBase;
}

// ��ȡ�ļ����ڴ��У����ض�ȡ���ֽ�������ȡʧ�ܷ���0
DWORD FileToMemory(LPCSTR lpszFile, LPVOID *pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL)
	{
		//printf("���ļ�ʧ��\n");
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	*pFileBuffer = malloc(dwFileSize);
	if (*pFileBuffer == NULL)
	{
		//printf("�����ڴ�ʧ��\n");
		fclose(pFile);
		return 0;
	}
	DWORD dwRead = fread(*pFileBuffer, 1, dwFileSize, pFile);
	fclose(pFile);
	if (dwRead != dwFileSize)
	{
		free(*pFileBuffer);
		return 0;
	}
	return dwRead;
}

// �� FileBuffer ����� ImageBuffer ��д�뵽�µĻ�����
// ���� ImageBuffer �Ĵ�С��ʧ�ܷ���0
DWORD FileBufferToImageBuffer(LPVOID pFileBuffer, LPVOID *pImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (*pImageBuffer == NULL)
	{
		printf("�����ڴ�ʧ��\n");
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	// ����DOSͷ+PEͷ+��ѡPEͷ+�ڱ�+�ļ�����
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	// �����ڱ��������н�
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(*pImageBuffer) + pSectionHeader[i].VirtualAddress), \
			(LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), \
			pSectionHeader[i].SizeOfRawData);
	}
	return pOptionHeader->SizeOfImage;
}

// ��Ȩ����������ΪDEBUGȨ��
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

// ����һ��imagebuffer���޸�����IAT��
void RepairIAT(LPVOID pImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	// 	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pFileBuffer + \
	// 		RvaToFoa(pFileBuffer, pOptionHeader->DataDirectory[1].VirtualAddress));
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageBuffer + \
		pOptionHeader->DataDirectory[1].VirtualAddress);
	
	// �ϸ���˵Ӧ���� sizeof(IMAGE_IMPORT_DESCRIPTOR) ���ֽ�Ϊ0��ʾ����
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		// ��ӡģ����
		//printf("%s\n", (LPCSTR)(pImportTable->Name + (DWORD)pImageBuffer));
		// ��ȡģ����
		HMODULE hModule = LoadLibraryA((LPCSTR)(pImportTable->Name + (DWORD)pImageBuffer));
		if (NULL == hModule)
		{
			printf("��ȡģ����ʧ�ܣ�ģ����: %s\n",(LPCSTR)(pImportTable->Name + (DWORD)pImageBuffer));
		}
		// �޸�IAT��
		//printf("--------------FirstThunkRVA:%x--------------\n", pImportTable->FirstThunk);		
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pImageBuffer + \
			pImportTable->FirstThunk);
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 ��һ��4�ֽ�����
			// ������λ��1����ô��ȥ���λ���ǵ������
			// ������λ��0����ô���ֵ��RVA ָ�� IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{
				//printf("����ŵ��� Ordinal:%04x\n", (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				DWORD dwProcAddress = (DWORD)GetProcAddress(hModule,MAKEINTRESOURCE((*((PDWORD)pThunkData) & 0x7FFFFFFF)));				
				*((PDWORD)pThunkData) = dwProcAddress;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(*((PDWORD)pThunkData) + \
					(DWORD)pImageBuffer);
				
				//printf("�����ֵ��� Hint:%04x Name:%s\n", pIBN->Hint, pIBN->Name);
				DWORD dwProcAddress = (DWORD)GetProcAddress(hModule,(LPCSTR)pIBN->Name);
				*((PDWORD)pThunkData) = dwProcAddress;
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));		
	}	
}

BOOL WriteSharedMemory(LPVOID pData, DWORD dwDataSize, const char*lpName)
{
	//����FileMapping����
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		printf("�����ļ�ӳ��ʧ��\n");
		return FALSE;
	}
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		printf("�ڴ�ӳ��ʧ��\n");
		return FALSE;
	}
	//д������
	memset((char*)hMapView,0,0x1000);
	memcpy((char*)hMapView,pData,dwDataSize);
	return TRUE;
}

BOOL ReadSharedMemory(LPVOID *pBuffer, const char *lpName)
{
	//����FileMapping����
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		printf("�����ڴ�ʧ��\n");
		return FALSE;
	} 
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		printf("�ڴ�ӳ��ʧ��\n");
		return FALSE;
	}
	//��ȡ����
	*pBuffer = malloc(0x1000);	
	memcpy(*pBuffer,hMapView,0x1000);
	
	return TRUE;
}