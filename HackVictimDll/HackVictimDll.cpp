// HackVictimDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

// 因为我采用内存注入的方式将DLL注入到目标进程，这样做的问题就是IAT表没有修复
// 除了user32.dll的函数，其他函数一般都用不了，需要手动LoadLibrary+GetProcAddress

// 进程通信共享内存的副本，表示控制程序下达的指令
// 前三位分别是3个函数的监视状态，后3位分别是三个函数的远程调用状态
BYTE g_bOrderState[6] = {0};
LPVOID g_pImageBuffer = NULL; // 注入DLL的基址
HANDLE g_hStdout; // 新控制台的输出句柄
DWORD g_ret; // HOOK函数内跳转到原函数的地址
BYTE g_bOriginCode[64]; // 原始代码，卸载HOOK时用到
DWORD g_dwOriginCodeSize; // 原始代码的大小
CONTEXT g_context; // 保存寄存器状态
char g_szLogBuffer[1000]; // 输出用的缓冲区，因为裸函数内不方便创建数组
int g_num1, g_num2; // Add函数挂钩子时，在裸函数内将参数赋给这两个变量


extern "C" __declspec(dllexport) DWORD WINAPI InjectEntry(LPVOID param);
BOOL WriteSharedMemory(LPVOID pData, DWORD dwDataSize, const char*lpName);
BOOL ReadSharedMemory(LPVOID *pBuffer, const char *lpName);
void Log(LPCSTR text);
void SetIATHook(LPVOID pOldFuncAddr, LPVOID pNewFuncAddr);
int WINAPI MyMessageBoxA(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType);
void UnsetIATHook(LPVOID pOldFuncAddr, LPVOID pNewFuncAddr);
HANDLE WINAPI MyCreateFileA(  LPCSTR lpFileName,DWORD dwDesiredAccess,
					DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes
					,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile);
void SetInlineHook(DWORD originalCodeAddr, DWORD originalSize, DWORD newCodeAddr);
void UnsetInlineHook(DWORD originalCodeAddr);
void MyAdd();



BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{

    return TRUE;
}



typedef int (*PFNSPRINTF)( char *, const char *,...);
typedef void* (*PFNMALLOC)(size_t);
typedef void (*PFNFREE)(void*);
typedef void* (*PFNMEMSET)(void*,int,size_t);
typedef void* (*PFNMEMCPY)(void*,void*,size_t);
typedef size_t (*PFNSTRLEN)(const char *);


PFNSPRINTF _sprintf;
PFNMALLOC _malloc;
PFNFREE _free;
PFNMEMSET _memset;
PFNMEMCPY _memcpy;
PFNSTRLEN _strlen;

// 通过远程线程调用该函数
// 循环接收控制程序的指令
extern "C" __declspec(dllexport) DWORD WINAPI InjectEntry(LPVOID param)
{
	// 手动加载要用到的函数
	HMODULE hModule = LoadLibraryA("MSVCRT.dll");	
	_sprintf = (PFNSPRINTF)GetProcAddress(hModule, "sprintf");
	_malloc = (PFNMALLOC)GetProcAddress(hModule, "malloc");
	_free = (PFNFREE)GetProcAddress(hModule, "free");
	_memset = (PFNMEMSET)GetProcAddress(hModule, "memset");
	_memcpy = (PFNMEMCPY)GetProcAddress(hModule, "memcpy");
	_strlen = (PFNSTRLEN)GetProcAddress(hModule, "strlen");

	// 申请控制台
 	AllocConsole();
	g_hStdout = CreateFileA("CONOUT$",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
	//SetStdHandle(STD_OUTPUT_HANDLE,hStdout);
	Log("申请控制台成功\n");
	
	// 获取自身基址，并做简单的检查
	LPVOID pBuffer = NULL;
	ReadSharedMemory(&pBuffer, "hackvictimimagebase");	
	g_pImageBuffer = (LPVOID)*(PDWORD)pBuffer;	
	if (((PBYTE)g_pImageBuffer)[0] != 'M' || ((PBYTE)g_pImageBuffer)[1] != 'Z' )
	{
		Log("获取基址无效\n");
		return 1;
	}	
	
	Log("开始接收指令...\n");
	LPVOID pData = NULL;
	BYTE bOldState[6];
	while (1)
	{		
		if (ReadSharedMemory(&pData, "hackvictim") == FALSE || pData == NULL)
		{
			//MessageBoxA(NULL,"读取共享内存失败","ERROR",MB_OK);
			Log("读取共享内存失败\n");
			break;
		}
		_memcpy(bOldState,g_bOrderState,6);
		_memcpy(g_bOrderState,pData,6);
		// debug
//  		char szBuffer[100]={0};
//  		_sprintf(szBuffer,"%d%d%d%d%d%d",g_bOrderState[0],g_bOrderState[1],g_bOrderState[2],g_bOrderState[3],g_bOrderState[4],g_bOrderState[5]);
		// 监视
		if (bOldState[0] != g_bOrderState[0])
		{
			if (g_bOrderState[0] == 1) 
			{				
				SetIATHook(MessageBoxA,MyMessageBoxA);
				Log("MessageBoxA Hook!\n");
			}
			else 
			{
				SetIATHook(MyMessageBoxA,MessageBoxA);
				Log("MessageBoxA UnHook!\n");
			}
		}
		if (bOldState[1] != g_bOrderState[1])
		{
			if (g_bOrderState[1] == 1) 
			{				
				SetIATHook(CreateFileA,MyCreateFileA);
				Log("CreateFileA Hook!\n");
			}
			else 
			{
				SetIATHook(MyCreateFileA,CreateFileA);
				Log("CreateFileA UnHook!\n");
			}
		}
		if (bOldState[2] != g_bOrderState[2])
		{
			// 		004011D0 55                   push        ebp
			// 		004011D1 8B EC                mov         ebp,esp
			// 		004011D3 83 EC 40             sub         esp,40h
			if (g_bOrderState[2] == 1) 
			{				
				SetInlineHook(0x004011D0,6,(DWORD)MyAdd);				
				Log("Add Hook!\n");
			}
			else 
			{
				UnsetInlineHook(0x004011D0);
				Log("Add UnHook!\n");
			}
		}
		// 远程调用
		if (g_bOrderState[3] == 1)
		{
			MessageBoxA(0,"远程调用MessageBoxA","Hacked!",MB_OK);
		}
		if (g_bOrderState[4] == 1)
		{
			HANDLE hFile = CreateFileA("victim1.exe",GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,NULL,NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				MessageBoxA(0,"读取文件失败","",MB_OK);
			}
			else
			{
				char szOutput[100] = {0};
				_sprintf(szOutput, "自身文件大小: %d 字节", GetFileSize(hFile, NULL));
				MessageBoxA(0,szOutput,"",MB_OK);
			}
			CloseHandle(hFile);
		}
		if (g_bOrderState[5] == 1)
		{
			typedef int (*PFNADD)(int,int);
			PFNADD pAdd = (PFNADD)0x004011D0; // 原Add的地址
			pAdd(11111111,88888888);
		}
		
		
		
		g_bOrderState[3] = g_bOrderState[4] = g_bOrderState[5] = 0;
		WriteSharedMemory(g_bOrderState,sizeof(g_bOrderState),"hackvictim");
// 		Log(strcat(szBuffer,"\n"));
		if (pData) _free(pData);
		Sleep(1000);
	}
	return 0;
}

BOOL WriteSharedMemory(LPVOID pData, DWORD dwDataSize, const char*lpName)
{	
	//创建FileMapping对象
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		Log("创建文件映像失败\n");
		return FALSE;
	}	
	//将FileMapping对象映射到自己的进程
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		Log("内存映射失败\n");
		return FALSE;
	}	
	//写入数据
	_memset((char*)hMapView,0,0x1000);
	_memcpy((char*)hMapView,pData,dwDataSize);	
	return TRUE;
}

BOOL ReadSharedMemory(LPVOID *pBuffer, const char *lpName)
{	
	//创建FileMapping对象
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		Log("创建共享内存失败\n");
		//MessageBoxA(0,"共享内存失败\n","",MB_OK);
		return FALSE;
	} 	
	//将FileMapping对象映射到自己的进程
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		char szOut[100] = {0};
		_sprintf(szOut,"内存映射失败: %d\n",GetLastError());
		//Log("内存映射失败\n");
		Log(szOut);
		
		return FALSE;
	}
	//读取数据	
 	*pBuffer = _malloc(0x1000);	
	if (*pBuffer == NULL)
	{		
		//MessageBoxA(0,"malloc失败\n","",MB_OK);
		Log("malloc失败\n");
		return FALSE;
	}	
 	_memcpy(*pBuffer,hMapView,0x1000);
	
	return TRUE;
}

void Log(LPCSTR text)
{
	WriteFile(g_hStdout,text,_strlen(text),0,0);
}

// 修改IAT表，让指定的函数指向新的函数
void SetIATHook(LPVOID pOldFuncAddr, LPVOID pNewFuncAddr)
{
	// 遍历IAT，找到匹配的函数，修改成新的地址
	LPVOID pImageBuffer = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(pDosHeader->e_lfanew + (DWORD)pDosHeader + 4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSectionHeader = \
		(PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);	
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImageBuffer + \
		pOptionHeader->DataDirectory[1].VirtualAddress);
	while (pImportTable->OriginalFirstThunk || pImportTable->FirstThunk)
	{
		PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((DWORD)pImageBuffer + \
			pImportTable->FirstThunk);
		while (*((PDWORD)pThunkData) != 0)
		{
			if (*(PDWORD)pThunkData == (DWORD)pOldFuncAddr)
			{
				*(PDWORD)pThunkData = (DWORD)pNewFuncAddr;
				return;
			}
			pThunkData++;
		}
		pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImportTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));		
	}	
}

// 卸载IAT HOOK
void UnsetIATHook(LPVOID pOldFuncAddr, LPVOID pNewFuncAddr)
{
	SetIATHook(pNewFuncAddr, pOldFuncAddr); // 反过来而已
}

// 被监控的MessageBox
int WINAPI MyMessageBoxA(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType)
{
	typedef int (WINAPI *PFNMESSAGEBOX)(HWND,LPCTSTR,LPCTSTR,UINT);	
	PFNMESSAGEBOX pFnMessageBox = (PFNMESSAGEBOX)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
	char szOutput[1000] = {0};
	_sprintf(szOutput,"MessageBoxA(%X, %s, %s, %X)\n", hWnd, lpText, lpCaption, uType);
	Log(szOutput);
	return pFnMessageBox(hWnd,lpText,lpCaption,uType);
}

// 被监控的CreateFileA
HANDLE WINAPI MyCreateFileA(  LPCSTR lpFileName,DWORD dwDesiredAccess,
					DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes
					,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)
{
	typedef HANDLE (WINAPI *PFNCREATEFILEA)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
	PFNCREATEFILEA pFnCreateFileA = (PFNCREATEFILEA)GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateFileA");
	char szOutput[1000] = {0};
	_sprintf(szOutput,"CreateFileA(%s, %X, %X, %X, %X, %X, %X)\n",lpFileName,dwDesiredAccess,dwShareMode,
		lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
	Log(szOutput);
	return pFnCreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
}



// 被监控的Add
void __declspec(naked)MyAdd()
{	
	// 获取关心的寄存器状态
	__asm
	{
		mov g_context.Esp,esp
		mov g_context.Eax,eax
		mov g_context.Ecx,ecx
		mov g_context.Edx,edx
		mov g_context.Ebx,ebx
	}	
	// 保存8个常用寄存器和标志寄存器
	__asm
	{
		pushad
		pushfd
	}
	
	// 我的代码，注意堆栈平衡	
	__asm
	{		
		mov eax,g_context.Esp
		mov ecx,[eax+0x4]
		mov g_num1,ecx
		mov eax,g_context.Esp
		mov ecx,[eax+0x8]
		mov g_num2,ecx
		
	}
	
	_sprintf(g_szLogBuffer, "Add(%d, %d)\n", g_num1,g_num2);
	Log(g_szLogBuffer);


	
	// 恢复寄存器，执行被替换的代码，然后返回
	// 		004011D0 55                   push        ebp
	// 		004011D1 8B EC                mov         ebp,esp
	// 		004011D3 83 EC 40             sub         esp,40h
	__asm
	{
		popfd
		popad
		push ebp
		mov ebp,esp
		sub esp,40h
		jmp g_ret
	}	
}

// 设置HOOK的函数
void SetInlineHook(DWORD originalCodeAddr, DWORD originalSize, DWORD newCodeAddr)
{
	if (originalCodeAddr==0||originalSize<5||newCodeAddr==0)
	{
		Log("参数错误\n");
		return;
	}
	// 设置内存写权限
	DWORD dwOldProtectFlag;
	BOOL bRet = VirtualProtectEx(GetCurrentProcess(),(LPVOID)originalCodeAddr,originalSize,
		PAGE_EXECUTE_READWRITE,&dwOldProtectFlag);
	if (!bRet)
	{
		Log("修改内存属性失败\n");
		return;
	}
	// 存储原始硬编码，卸载的时候要把原始代码贴回去	
	_memcpy(g_bOriginCode,(LPVOID)originalCodeAddr,originalSize);
	g_dwOriginCodeSize = originalSize;
	// 计算E9 JMP后面的4字节 = 要跳转的地址 - JMP的下一条指令的地址
	DWORD dwJmpCode = newCodeAddr - (originalCodeAddr + 5);
	// 将要替换的代码区域全部初始化为NOP
	_memset((LPVOID)originalCodeAddr,0x90,originalSize);
	// HOOK
	*(PBYTE)originalCodeAddr = 0xE9; // JMP
	*PDWORD(originalCodeAddr+1) = dwJmpCode;
	// 设置返回地址
	g_ret = originalCodeAddr + originalSize;
	// 恢复内存属性
	VirtualProtectEx(GetCurrentProcess(),(LPVOID)originalCodeAddr,originalSize,dwOldProtectFlag,NULL);
}

// 卸载HOOK的函数
void UnsetInlineHook(DWORD originalCodeAddr)
{
	VirtualProtectEx(GetCurrentProcess(),(LPVOID)originalCodeAddr,g_dwOriginCodeSize,PAGE_EXECUTE_READWRITE,NULL);
	_memcpy((LPVOID)originalCodeAddr,g_bOriginCode,g_dwOriginCodeSize);
}