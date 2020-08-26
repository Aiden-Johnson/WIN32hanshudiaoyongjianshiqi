// Victim1.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include "resource.h"

BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
VOID CenterDialog(HWND hDlg);
int Add(int n1, int n2);
int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogProc);
	return 0;
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

// 对话框窗口过程
BOOL CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{		
			CenterDialog(hDlg);		
			HWND hFileName = GetDlgItem(hDlg,IDC_EDIT_FILENAME);
			SetWindowTextA(hFileName,"c:\\program32\\notepad.exe");
			HWND hPID = GetDlgItem(hDlg,IDC_EDIT_PID);
			char szPID[100] = {0};
			sprintf(szPID,"%d",GetCurrentProcessId());
			SetWindowTextA(hPID,szPID);

			return TRUE;
		}
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_MSGBOX_CREATE:
			{
				char szTitle[100] = {0};
				char szText[100] = {0};
				HWND hTitle = GetDlgItem(hDlg,IDC_EDIT_MSGBOX_TITLE);
				HWND hText = GetDlgItem(hDlg,IDC_EDIT_MSGBOX_TEXT);
				GetWindowTextA(hTitle,szTitle,100);
				GetWindowTextA(hText,szText,100);
				MessageBoxA(hDlg, szText,szTitle, MB_OK);
				return TRUE;
			}
		case IDC_BUTTON_CREATEFILE:
			{
				HWND hEdit = GetDlgItem(hDlg,IDC_EDIT_FILENAME);
				char szFileName[MAX_PATH] = {0};
				GetWindowTextA(hEdit,szFileName,MAX_PATH);
				HANDLE hFile = CreateFileA(szFileName,GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,NULL,NULL);
				if (hFile == INVALID_HANDLE_VALUE)
				{
					MessageBoxA(hDlg,"读取文件失败","",MB_OK);
				}
				else
				{
					char szOutput[100] = {0};
					sprintf(szOutput, "文件大小: %d 字节", GetFileSize(hFile, NULL));
					MessageBoxA(hDlg,szOutput,"",MB_OK);
				}
				CloseHandle(hFile);
				return TRUE;
			}
		case IDC_BUTTON_OPENPROCESS:
			{
				HWND hEdit = GetDlgItem(hDlg,IDC_EDIT_PID);
				char szPid[10] = {0};
				GetWindowTextA(hEdit,szPid,10);
				DWORD dwPID = 0;
				sscanf(szPid, "%d", &dwPID);
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPID);
				if (hProcess == NULL)
				{
					MessageBoxA(hDlg,"打开进程失败","",MB_OK);
				}
				else
				{
					MessageBoxA(hDlg,"打开进程成功","",MB_OK);
				}
				CloseHandle(hProcess);
				return TRUE;
			}
		case IDC_BUTTON_ADD:
			{
				HWND hEdit1 = GetDlgItem(hDlg,IDC_EDIT_NUM1);
				HWND hEdit2 = GetDlgItem(hDlg,IDC_EDIT_NUM2);
				HWND hEdit3 = GetDlgItem(hDlg,IDC_STATIC_RESULT);
				char szNum1[10] = {0};
				char szNum2[10] = {0};
				char szNum3[10] = {0};
				GetWindowTextA(hEdit1,szNum1,10);
				GetWindowTextA(hEdit2,szNum2,10);
				int n1 = 0, n2 = 0;
				sscanf(szNum1,"%d", &n1);
				sscanf(szNum2,"%d", &n2);				
				int res = Add(n1,n2);
				sprintf(szNum3,"%d",res);
				SetWindowTextA(hEdit3,szNum3);
				return TRUE;
			}
		}
		return TRUE;
		case WM_CLOSE:
			EndDialog(hDlg, 0);
			return TRUE;
	}
	return FALSE;
}

int Add(int n1, int n2)
{
	return n1 + n2;
}