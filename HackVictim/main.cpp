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



// 依次表示MessageBoxA, CreateFileA, OpenProcess 的监视状态，后3位依次对应三个函数是否进行远程调用
BYTE g_bOrderState[6] = {0};


int main()
{	
	EnableDebugPrivilege();	
	HINSTANCE hInstance = GetModuleHandle(NULL);
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);
	return 0;
}

// 对话框窗口过程
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
					if (g_bOrderState[0] == TRUE) SetWindowText(hBtn,"开启监控");					
					else SetWindowText(hBtn,"解除监控");
					g_bOrderState[0] = !g_bOrderState[0];
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");
					return TRUE;
				}
			case IDC_BUTTON_MONITOR_CREATEFILE:
				{
					HWND hBtn = GetDlgItem(hDlg,IDC_BUTTON_MONITOR_CREATEFILE);
					if (g_bOrderState[1] == TRUE) SetWindowText(hBtn,"开启监控");					
					else SetWindowText(hBtn,"解除监控");
					g_bOrderState[1] = !g_bOrderState[1];
					WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");
					return TRUE;
				}
			case IDC_BUTTON_MONITOR_ADD:
				{
					HWND hBtn = GetDlgItem(hDlg,IDC_BUTTON_MONITOR_ADD);
					if (g_bOrderState[2] == TRUE) SetWindowText(hBtn,"开启监控");					
					else SetWindowText(hBtn,"解除监控");
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

// 内存注入
void MemoryInject(DWORD dwPID)
{
	// 读取DLL并拉伸
	LPVOID pDllFileBuffer = NULL, pDllImageBuffer = NULL;
	DWORD dwFileBufferSize = FileToMemory("HackVictimDll.dll",&pDllFileBuffer);
	DWORD dwSizeOfImage = FileBufferToImageBuffer(pDllFileBuffer, &pDllImageBuffer);	
	//LPVOID pImageBuffer = pDllImageBuffer;	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllImageBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));	
	// 在游戏进程申请内存
	printf("进程id: %d\n", dwPID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPID);
	LPVOID pRemoteImageBase = VirtualAllocEx(hProcess,NULL,dwSizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if (NULL == pRemoteImageBase)
	{
		printf("在游戏进程申请内存失败，错误码: %d\n", GetLastError());
		return;
	}
	// 修复IAT
	RepairIAT(pDllImageBuffer);
	// 修复重定位表，写入到游戏进程
	SetNewImageBase(pDllImageBuffer, (DWORD)pRemoteImageBase);
	WriteProcessMemory(hProcess,pRemoteImageBase,pDllImageBuffer,dwSizeOfImage,NULL);	
	
	// 计算入口函数地址
	HMODULE hDll = LoadLibraryA("HackVictimDll.dll");
	DWORD dwInjectEntry = (DWORD)GetProcAddress(hDll, "_InjectEntry@4");
	if (dwInjectEntry == NULL)
	{
		printf("获取函数地址失败，错误码: %d\n", GetLastError());
	}
	DWORD dwProcOffset = dwInjectEntry - (DWORD)hDll + (DWORD)pRemoteImageBase;
 	printf("当前地址空间DLL基址: 0x%X\n", (DWORD)hDll);
// 	printf("当前地址空间入口函数地址: 0x%X\n", dwInjectEntry);
 	printf("远程地址空间DLL基址: 0x%X\n", (DWORD)pRemoteImageBase);
// 	printf("远程入口函数地址: 0x%X\n", dwProcOffset);

	DWORD dwPRemoteImageBase = (DWORD)pRemoteImageBase;
	WriteSharedMemory(&dwPRemoteImageBase, sizeof(DWORD),"hackvictimimagebase"); // 告诉已注入的DLL自己的基址	
	
	// 创建远程线程，执行入口代码	
	CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)dwProcOffset,NULL,NULL,NULL);
	printf("创建远程线程成功\n");
	
}

// 修改 ImageBase 并修复重定位表
// 内存镜像版本
VOID SetNewImageBase(LPVOID pImageBuffer, DWORD dwNewImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	
	PIMAGE_BASE_RELOCATION pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pImageBuffer + \
		pOptionHeader->DataDirectory[5].VirtualAddress);
	DWORD dwImageBaseDelta = dwNewImageBase - pOptionHeader->ImageBase; // 新旧ImageBase 的差值	
	
	// 重定位表的 VirtualAddress + 低12位偏移 = RVA
	// RVA + ImageBase 这个内存里存储了一个“指针”
	// 要修改的是这个“指针”的值，要让这个“指针”加上两个ImageBase的差值
	while (pRelocationTable->VirtualAddress || pRelocationTable->SizeOfBlock)
	{
		size_t n = (pRelocationTable->SizeOfBlock - 8) / 2; // 可能需要修改的地址数量（高4位==0011才要修改）
		PWORD pOffset = (PWORD)((DWORD)pRelocationTable + 8); // 2字节偏移的数组
		for (size_t i = 0; i < n; i++)
		{
			// 高4位等于0011才需要重定位
			if ((pOffset[i] & 0xF000) == 0x3000)
			{
				// 计算需要重定位的数据的RVA地址
				DWORD dwRva = pRelocationTable->VirtualAddress + (pOffset[i] & 0x0FFF);				
				// 计算在镜像中的地址
				PDWORD pData = (PDWORD)((DWORD)pImageBuffer + dwRva);
				// 重定位，即修正写死的地址				
				*pData += dwImageBaseDelta;
			}
		}		
		pRelocationTable = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationTable + pRelocationTable->SizeOfBlock);
	}
	// 修改 ImageBase
	pOptionHeader->ImageBase = dwNewImageBase;
}

// 读取文件到内存中，返回读取的字节数；读取失败返回0
DWORD FileToMemory(LPCSTR lpszFile, LPVOID *pFileBuffer)
{
	FILE *pFile = NULL;
	DWORD dwFileSize = 0;
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL)
	{
		//printf("打开文件失败\n");
		return 0;
	}
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	*pFileBuffer = malloc(dwFileSize);
	if (*pFileBuffer == NULL)
	{
		//printf("分配内存失败\n");
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

// 将 FileBuffer 拉伸成 ImageBuffer 并写入到新的缓冲区
// 返回 ImageBuffer 的大小；失败返回0
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
		printf("分配内存失败\n");
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	// 复制DOS头+PE头+可选PE头+节表+文件对齐
	memcpy(*pImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	// 遍历节表，复制所有节
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((LPVOID)((DWORD)(*pImageBuffer) + pSectionHeader[i].VirtualAddress), \
			(LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData), \
			pSectionHeader[i].SizeOfRawData);
	}
	return pOptionHeader->SizeOfImage;
}

// 提权函数：提升为DEBUG权限
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

// 传入一个imagebuffer，修复它的IAT表
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
	
	// 严格来说应该是 sizeof(IMAGE_IMPORT_DESCRIPTOR) 个字节为0表示结束
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		// 打印模块名
		//printf("%s\n", (LPCSTR)(pImportTable->Name + (DWORD)pImageBuffer));
		// 获取模块句柄
		HMODULE hModule = LoadLibraryA((LPCSTR)(pImportTable->Name + (DWORD)pImageBuffer));
		if (NULL == hModule)
		{
			printf("获取模块句柄失败，模块名: %s\n",(LPCSTR)(pImportTable->Name + (DWORD)pImageBuffer));
		}
		// 修复IAT表
		//printf("--------------FirstThunkRVA:%x--------------\n", pImportTable->FirstThunk);		
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pImageBuffer + \
			pImportTable->FirstThunk);
		while (*((PDWORD)pThunkData) != 0)
		{
			// IMAGE_THUNK_DATA32 是一个4字节数据
			// 如果最高位是1，那么除去最高位就是导出序号
			// 如果最高位是0，那么这个值是RVA 指向 IMAGE_IMPORT_BY_NAME
			if ((*((PDWORD)pThunkData) & 0x80000000) == 0x80000000)
			{
				//printf("按序号导入 Ordinal:%04x\n", (*((PDWORD)pThunkData) & 0x7FFFFFFF));
				DWORD dwProcAddress = (DWORD)GetProcAddress(hModule,MAKEINTRESOURCE((*((PDWORD)pThunkData) & 0x7FFFFFFF)));				
				*((PDWORD)pThunkData) = dwProcAddress;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(*((PDWORD)pThunkData) + \
					(DWORD)pImageBuffer);
				
				//printf("按名字导入 Hint:%04x Name:%s\n", pIBN->Hint, pIBN->Name);
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
	//创建FileMapping对象
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		printf("创建文件映像失败\n");
		return FALSE;
	}
	//将FileMapping对象映射到自己的进程
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		printf("内存映射失败\n");
		return FALSE;
	}
	//写入数据
	memset((char*)hMapView,0,0x1000);
	memcpy((char*)hMapView,pData,dwDataSize);
	return TRUE;
}

BOOL ReadSharedMemory(LPVOID *pBuffer, const char *lpName)
{
	//创建FileMapping对象
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		printf("共享内存失败\n");
		return FALSE;
	} 
	//将FileMapping对象映射到自己的进程
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		printf("内存映射失败\n");
		return FALSE;
	}
	//读取数据
	*pBuffer = malloc(0x1000);	
	memcpy(*pBuffer,hMapView,0x1000);
	
	return TRUE;
}