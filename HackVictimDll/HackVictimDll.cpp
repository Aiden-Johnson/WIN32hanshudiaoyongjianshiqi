// HackVictimDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

// ��Ϊ�Ҳ����ڴ�ע��ķ�ʽ��DLLע�뵽Ŀ����̣����������������IAT��û���޸�
// ����user32.dll�ĺ�������������һ�㶼�ò��ˣ���Ҫ�ֶ�LoadLibrary+GetProcAddress

// ����ͨ�Ź����ڴ�ĸ�������ʾ���Ƴ����´��ָ��
// ǰ��λ�ֱ���3�������ļ���״̬����3λ�ֱ�������������Զ�̵���״̬
BYTE g_bOrderState[6] = {0};
LPVOID g_pImageBuffer = NULL; // ע��DLL�Ļ�ַ
HANDLE g_hStdout; // �¿���̨��������
DWORD g_ret; // HOOK��������ת��ԭ�����ĵ�ַ
BYTE g_bOriginCode[64]; // ԭʼ���룬ж��HOOKʱ�õ�
DWORD g_dwOriginCodeSize; // ԭʼ����Ĵ�С
CONTEXT g_context; // ����Ĵ���״̬
char g_szLogBuffer[1000]; // ����õĻ���������Ϊ�㺯���ڲ����㴴������
int g_num1, g_num2; // Add�����ҹ���ʱ�����㺯���ڽ�������������������


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

// ͨ��Զ���̵߳��øú���
// ѭ�����տ��Ƴ����ָ��
extern "C" __declspec(dllexport) DWORD WINAPI InjectEntry(LPVOID param)
{
	// �ֶ�����Ҫ�õ��ĺ���
	HMODULE hModule = LoadLibraryA("MSVCRT.dll");	
	_sprintf = (PFNSPRINTF)GetProcAddress(hModule, "sprintf");
	_malloc = (PFNMALLOC)GetProcAddress(hModule, "malloc");
	_free = (PFNFREE)GetProcAddress(hModule, "free");
	_memset = (PFNMEMSET)GetProcAddress(hModule, "memset");
	_memcpy = (PFNMEMCPY)GetProcAddress(hModule, "memcpy");
	_strlen = (PFNSTRLEN)GetProcAddress(hModule, "strlen");

	// �������̨
 	AllocConsole();
	g_hStdout = CreateFileA("CONOUT$",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_EXISTING,0,0);
	//SetStdHandle(STD_OUTPUT_HANDLE,hStdout);
	Log("�������̨�ɹ�\n");
	
	// ��ȡ�����ַ�������򵥵ļ��
	LPVOID pBuffer = NULL;
	ReadSharedMemory(&pBuffer, "hackvictimimagebase");	
	g_pImageBuffer = (LPVOID)*(PDWORD)pBuffer;	
	if (((PBYTE)g_pImageBuffer)[0] != 'M' || ((PBYTE)g_pImageBuffer)[1] != 'Z' )
	{
		Log("��ȡ��ַ��Ч\n");
		return 1;
	}	
	
	Log("��ʼ����ָ��...\n");
	LPVOID pData = NULL;
	BYTE bOldState[6];
	while (1)
	{		
		if (ReadSharedMemory(&pData, "hackvictim") == FALSE || pData == NULL)
		{
			//MessageBoxA(NULL,"��ȡ�����ڴ�ʧ��","ERROR",MB_OK);
			Log("��ȡ�����ڴ�ʧ��\n");
			break;
		}
		_memcpy(bOldState,g_bOrderState,6);
		_memcpy(g_bOrderState,pData,6);
		// debug
//  		char szBuffer[100]={0};
//  		_sprintf(szBuffer,"%d%d%d%d%d%d",g_bOrderState[0],g_bOrderState[1],g_bOrderState[2],g_bOrderState[3],g_bOrderState[4],g_bOrderState[5]);
		// ����
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
		// Զ�̵���
		if (g_bOrderState[3] == 1)
		{
			MessageBoxA(0,"Զ�̵���MessageBoxA","Hacked!",MB_OK);
		}
		if (g_bOrderState[4] == 1)
		{
			HANDLE hFile = CreateFileA("victim1.exe",GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,NULL,NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				MessageBoxA(0,"��ȡ�ļ�ʧ��","",MB_OK);
			}
			else
			{
				char szOutput[100] = {0};
				_sprintf(szOutput, "�����ļ���С: %d �ֽ�", GetFileSize(hFile, NULL));
				MessageBoxA(0,szOutput,"",MB_OK);
			}
			CloseHandle(hFile);
		}
		if (g_bOrderState[5] == 1)
		{
			typedef int (*PFNADD)(int,int);
			PFNADD pAdd = (PFNADD)0x004011D0; // ԭAdd�ĵ�ַ
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
	//����FileMapping����
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		Log("�����ļ�ӳ��ʧ��\n");
		return FALSE;
	}	
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		Log("�ڴ�ӳ��ʧ��\n");
		return FALSE;
	}	
	//д������
	_memset((char*)hMapView,0,0x1000);
	_memcpy((char*)hMapView,pData,dwDataSize);	
	return TRUE;
}

BOOL ReadSharedMemory(LPVOID *pBuffer, const char *lpName)
{	
	//����FileMapping����
	HANDLE hMapObject = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE,0,0x1000,lpName);
	if (NULL == hMapObject)
	{
		Log("���������ڴ�ʧ��\n");
		//MessageBoxA(0,"�����ڴ�ʧ��\n","",MB_OK);
		return FALSE;
	} 	
	//��FileMapping����ӳ�䵽�Լ��Ľ���
	HANDLE hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
	if (NULL == hMapView)
	{
		char szOut[100] = {0};
		_sprintf(szOut,"�ڴ�ӳ��ʧ��: %d\n",GetLastError());
		//Log("�ڴ�ӳ��ʧ��\n");
		Log(szOut);
		
		return FALSE;
	}
	//��ȡ����	
 	*pBuffer = _malloc(0x1000);	
	if (*pBuffer == NULL)
	{		
		//MessageBoxA(0,"mallocʧ��\n","",MB_OK);
		Log("mallocʧ��\n");
		return FALSE;
	}	
 	_memcpy(*pBuffer,hMapView,0x1000);
	
	return TRUE;
}

void Log(LPCSTR text)
{
	WriteFile(g_hStdout,text,_strlen(text),0,0);
}

// �޸�IAT����ָ���ĺ���ָ���µĺ���
void SetIATHook(LPVOID pOldFuncAddr, LPVOID pNewFuncAddr)
{
	// ����IAT���ҵ�ƥ��ĺ������޸ĳ��µĵ�ַ
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

// ж��IAT HOOK
void UnsetIATHook(LPVOID pOldFuncAddr, LPVOID pNewFuncAddr)
{
	SetIATHook(pNewFuncAddr, pOldFuncAddr); // ����������
}

// ����ص�MessageBox
int WINAPI MyMessageBoxA(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType)
{
	typedef int (WINAPI *PFNMESSAGEBOX)(HWND,LPCTSTR,LPCTSTR,UINT);	
	PFNMESSAGEBOX pFnMessageBox = (PFNMESSAGEBOX)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
	char szOutput[1000] = {0};
	_sprintf(szOutput,"MessageBoxA(%X, %s, %s, %X)\n", hWnd, lpText, lpCaption, uType);
	Log(szOutput);
	return pFnMessageBox(hWnd,lpText,lpCaption,uType);
}

// ����ص�CreateFileA
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



// ����ص�Add
void __declspec(naked)MyAdd()
{	
	// ��ȡ���ĵļĴ���״̬
	__asm
	{
		mov g_context.Esp,esp
		mov g_context.Eax,eax
		mov g_context.Ecx,ecx
		mov g_context.Edx,edx
		mov g_context.Ebx,ebx
	}	
	// ����8�����üĴ����ͱ�־�Ĵ���
	__asm
	{
		pushad
		pushfd
	}
	
	// �ҵĴ��룬ע���ջƽ��	
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


	
	// �ָ��Ĵ�����ִ�б��滻�Ĵ��룬Ȼ�󷵻�
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

// ����HOOK�ĺ���
void SetInlineHook(DWORD originalCodeAddr, DWORD originalSize, DWORD newCodeAddr)
{
	if (originalCodeAddr==0||originalSize<5||newCodeAddr==0)
	{
		Log("��������\n");
		return;
	}
	// �����ڴ�дȨ��
	DWORD dwOldProtectFlag;
	BOOL bRet = VirtualProtectEx(GetCurrentProcess(),(LPVOID)originalCodeAddr,originalSize,
		PAGE_EXECUTE_READWRITE,&dwOldProtectFlag);
	if (!bRet)
	{
		Log("�޸��ڴ�����ʧ��\n");
		return;
	}
	// �洢ԭʼӲ���룬ж�ص�ʱ��Ҫ��ԭʼ��������ȥ	
	_memcpy(g_bOriginCode,(LPVOID)originalCodeAddr,originalSize);
	g_dwOriginCodeSize = originalSize;
	// ����E9 JMP�����4�ֽ� = Ҫ��ת�ĵ�ַ - JMP����һ��ָ��ĵ�ַ
	DWORD dwJmpCode = newCodeAddr - (originalCodeAddr + 5);
	// ��Ҫ�滻�Ĵ�������ȫ����ʼ��ΪNOP
	_memset((LPVOID)originalCodeAddr,0x90,originalSize);
	// HOOK
	*(PBYTE)originalCodeAddr = 0xE9; // JMP
	*PDWORD(originalCodeAddr+1) = dwJmpCode;
	// ���÷��ص�ַ
	g_ret = originalCodeAddr + originalSize;
	// �ָ��ڴ�����
	VirtualProtectEx(GetCurrentProcess(),(LPVOID)originalCodeAddr,originalSize,dwOldProtectFlag,NULL);
}

// ж��HOOK�ĺ���
void UnsetInlineHook(DWORD originalCodeAddr)
{
	VirtualProtectEx(GetCurrentProcess(),(LPVOID)originalCodeAddr,g_dwOriginCodeSize,PAGE_EXECUTE_READWRITE,NULL);
	_memcpy((LPVOID)originalCodeAddr,g_bOriginCode,g_dwOriginCodeSize);
}