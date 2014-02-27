#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <WinSock2.h>
#include <Windows.h>
#include <Shlwapi.h>
#include <CommCtrl.h>
#include <process.h>
#include "libssh/libssh.h"


#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>

DWORD WINAPI start(LPVOID pointer);
unsigned int ReadToVector(const TCHAR* file_name, std::vector<std::string>* list);
bool InitBrute();
DWORD GetOpenName(HINSTANCE hInstance, TCHAR* outbuf, const TCHAR* filter, const TCHAR* title);
void EnableControls(bool Enable);
int DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
bool IsConnected(SOCKET s, fd_set *rd, fd_set *wr, fd_set *ex);
void AddInfo(const std::string& text, unsigned int tid);
void AddFile(const std::string& text);
bool CheckSSH(const std::string& ip, const std::string& login, const std::string& password);
