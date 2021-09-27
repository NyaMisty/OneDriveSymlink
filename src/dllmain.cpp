#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include "definitions.h"

#include <Windows.h>
#include <intrin.h>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>
#include <detours/detours.h>
#include <string>
#include <time.h>
#include <set>
#include <vector>
#include <fstream>
#include <thread>
#include <map>
#include <cassert>
#include <tchar.h>
#include <locale>
#include <codecvt>
#include "MINT.h"
#include "win_handle.h"
#include "dbg.h"

decltype(&ReadDirectoryChangesW) pReadDirectoryChangesW;
decltype(&CreateIoCompletionPort) pCreateIoCompletionPort;


inline std::wstring to_wide_string(const std::string& input)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(input);
}

std::string get_handle_path(HANDLE hDirectory, BOOL ignore_error = FALSE) {
	char pathbuf[0x1000] = { 0 };
	DWORD ret = GetFinalPathNameByHandleA(hDirectory, pathbuf, sizeof(pathbuf), FILE_NAME_NORMALIZED);
	if (!ignore_error) {
		wassert(ret != 0);
	}
	else {
		if (ret == 0) {
			//dbg("Warning: get_handle_path error %d for handle %d", GetLastError(), hDirectory);
		}
	}
	std::string _path = pathbuf;
	return _path;
}


struct OverlapSymlinkContext {
	std::string path;
	std::string relaPath;
	std::vector<char> retBuffer;
	DWORD notifyFlags;
	scoped_win_handle h;
	scoped_win_handle hOvlEvt;
	OVERLAPPED ovl;

	OverlapSymlinkContext() {
		h = std::make_shared<scoped_win_handle_unique>();
		hOvlEvt = std::make_shared<scoped_win_handle_unique>();
	}

	~OverlapSymlinkContext() {
		
	}

	OverlapSymlinkContext(std::string path, std::string relaPath) : OverlapSymlinkContext() {
		this->path = path;
		this->relaPath = relaPath;
		this->notifyFlags = notifyFlags;
		ovl.hEvent = CreateEvent(NULL, FALSE, 0, NULL);
		hOvlEvt->reset(ovl.hEvent);
		wassert(*hOvlEvt != NULL);
		h->reset(CreateFileA(path.c_str(),
			FILE_LIST_DIRECTORY,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
			NULL));
		wassert(*h != NULL);
	}

	BOOL readChangeStart(DWORD notifyFlags, DWORD bufferLen) {
		retBuffer.resize(bufferLen);
		this->notifyFlags = notifyFlags;

		
		BOOL success = pReadDirectoryChangesW(
			h->get(), retBuffer.data(), (DWORD)retBuffer.size(), TRUE, notifyFlags, // 11f
			NULL, &ovl, NULL);
		return success;
	}

	BOOL readChangeStop() {
		return CancelIoEx(h->get(), &ovl);
	}
};

struct SymlinkGroup {
	std::string rootPath;
	time_t last_updated;
	std::map<std::string, OverlapSymlinkContext> contexts;

	SymlinkGroup() : last_updated(0) {}

	std::vector<char> getChanges(DWORD nBufferLength, LPDWORD status) {
		BOOL bRet = TRUE;
		auto symlinks = contexts;
		std::map<std::string, OverlapSymlinkContext > retBufferMap;
		std::vector<HANDLE> hEvents;
		std::vector<std::string> keys;
		hEvents.reserve(symlinks.size());
		dbg("Starting readChange...");
		for (auto& it : symlinks) {
			bRet = it.second.readChangeStart(
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY,
				nBufferLength / 2
			);
			wassert(bRet);
			hEvents.push_back(it.second.ovl.hEvent);
			keys.push_back(it.first);
		}

		dbg("Waiting for all change notifications...");
		DWORD result = WaitForMultipleObjects((DWORD)hEvents.size(), hEvents.data(), FALSE, INFINITE);
		dbg("WaitForMultipleObjects GetLastError() = %d, stopping all ReadChanges", GetLastError());
		for (auto& it : symlinks) {
			it.second.readChangeStop();
		}
		std::vector<char> outBuffer;
		outBuffer.resize(nBufferLength);
		if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + hEvents.size()) {
			int index = result - WAIT_OBJECT_0;
			DWORD bytes_transferred;
			auto& c = symlinks[keys[index]];
			dbg("Changes hit to %d: %s", index, c.path.c_str());
			bRet = GetOverlappedResult(c.h->get(), &c.ovl, &bytes_transferred, FALSE);
			wassert(bRet);
			dbg("Overlapped result bytes_transferred = %d", bytes_transferred);

			FILE_NOTIFY_INFORMATION* event = (FILE_NOTIFY_INFORMATION*)c.retBuffer.data();
			FILE_NOTIFY_INFORMATION* outevent = (FILE_NOTIFY_INFORMATION*)outBuffer.data();

			size_t bytesOut = 0;
			for (;;) {
				DWORD name_len = event->FileNameLength / sizeof(wchar_t);

				memcpy(outevent, event, sizeof(FILE_NOTIFY_INFORMATION));
				wcscpy(outevent->FileName, to_wide_string(c.relaPath).c_str());
				wcscat(outevent->FileName, event->FileName);
				dbg("Rewriting changing notification: %S", outevent->FileName);
				size_t new_name_len = wcslen(outevent->FileName);
				outevent->FileNameLength = (DWORD)new_name_len * 2;
				bytesOut += (char*)&outevent->FileName - (char*)outevent + outevent->FileNameLength;
				outevent->NextEntryOffset = (DWORD)bytesOut;

				// Are there more events to handle?
				if (event->NextEntryOffset) {
					*((uint8_t**)&event) += event->NextEntryOffset;
					*((uint8_t**)&outevent) += outevent->NextEntryOffset;
				}
				else {
					outevent->NextEntryOffset = 0;
					break;
				}
			}

			outBuffer.resize(bytesOut);
			return outBuffer;
		}
		else {
			*status = result;
			return {};
		}
	}
};


std::map<std::string, SymlinkGroup> handleContexts;
std::map<HANDLE, FILE_COMPLETION_INFORMATION> onedriveIocp;


void updateSymlinkList(HANDLE hDirectory) {
	std::string _path = get_handle_path(hDirectory);
	if (handleContexts.contains(_path)) {
		if (time(NULL) - handleContexts[_path].last_updated < 30) {
			return;
		}
		dbg("Symlink List too old, re-construsting...");
	}
	else {
		dbg("Symlink List not exists, construsting...");
		handleContexts[_path] = SymlinkGroup();
	}
	handleContexts[_path].last_updated = time(NULL);

	auto& symlinks = handleContexts[_path].contexts;
	symlinks.clear();
	symlinks[_path] = std::move(OverlapSymlinkContext(_path, ""));

	std::ifstream file(_path + "\\symlinks.ini");
	if (file.is_open()) {
		std::string line;
		while (std::getline(file, line)) {
			// using printf() in all tests for consistency
			dbg("Got line %s", line.c_str());
			std::string prefix = "OD\\";
			if (!line.compare(0, prefix.size(), prefix)) {
				auto curRela = line.substr(3);
				std::string curAbsl = _path;
				curAbsl += "\\" + curRela;
				dbg("Add path %s to list", curAbsl.c_str());
				symlinks[curAbsl] = std::move(OverlapSymlinkContext(curAbsl, curRela + "\\"));
			}
		}
		file.close();
	}
}

HANDLE hook_CreateIoCompletionPort(
	HANDLE    FileHandle,
	HANDLE    ExistingCompletionPort,
	ULONG_PTR CompletionKey,
	DWORD     NumberOfConcurrentThreads
) {
	HANDLE hRet = pCreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads);
	if (!hRet) return hRet;

	if (FileHandle == (HANDLE)-1) return hRet;

	OBJECT_TYPE_INFORMATION oti[2] = { 0 };
	DWORD retLen = 0;
	NTSTATUS ret = NtQueryObject(FileHandle, ObjectTypeInformation, &oti, sizeof(oti), &retLen);
	assert(ret == NO_ERROR);
	UNICODE_STRING strFile = { 0 };
	RtlInitUnicodeString(&strFile, L"File");
	if (RtlEqualUnicodeString(&oti[0].TypeName, &strFile, FALSE)) {
		if (get_handle_path(FileHandle, TRUE).ends_with("OneDrive")) {
			onedriveIocp[FileHandle] = { hRet, (PVOID)CompletionKey };
		}
	}
	return hRet;
}

BOOL hook_ReadDirectoryChangesW(
	HANDLE                          hDirectory,
	LPVOID                          lpBuffer,
	DWORD                           nBufferLength,
	BOOL                            bWatchSubtree,
	DWORD                           dwNotifyFilter,
	LPDWORD                         lpBytesReturned,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	dbg("Entered hook_ReadDirectoryChangesW!");
	BOOL bRet = TRUE;
	dbg("Updating symlinkList!");
	updateSymlinkList(hDirectory);
	
	std::string _path = get_handle_path(hDirectory);
	dbg("handlePath: %s", _path.c_str());

	auto handler = [=](BOOL isIOCP) {
		DWORD handleStatus = 0;
		auto retBuffer = handleContexts[_path].getChanges(nBufferLength, &handleStatus);
		memcpy(lpBuffer, retBuffer.data(), retBuffer.size());
		if (isIOCP && handleStatus == 0) {
			if (onedriveIocp.contains(hDirectory)) {
				BOOL ret = PostQueuedCompletionStatus(onedriveIocp[hDirectory].Port, (DWORD)retBuffer.size(), (ULONG_PTR)onedriveIocp[hDirectory].Key, NULL);
				dbg("PostQueuedCompletionStatus ret: %d", ret);
			}

			return TRUE;
		}
		else {
			return FALSE;
		}
	};

	if (!lpOverlapped) {
		return handler(FALSE);
	}

	std::thread(handler, TRUE).detach();
	return TRUE;
}

bool hook() {
	*(void**)&pCreateIoCompletionPort = GetProcAddress(LoadLibraryA("kernel32"), "CreateIoCompletionPort");
	*(void **)&pReadDirectoryChangesW = GetProcAddress(LoadLibraryA("kernel32"), "ReadDirectoryChangesW");
	LONG ret = 0;
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	ret = DetourUpdateThread(GetCurrentThread());
	ret = DetourAttach(&(LPVOID&)pReadDirectoryChangesW, hook_ReadDirectoryChangesW);
	ret = DetourAttach(&(LPVOID&)pCreateIoCompletionPort, hook_CreateIoCompletionPort);
	ret = DetourTransactionCommit();
	return ret == NO_ERROR;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
		return TRUE;
	
	OutputDebugStringA("OneDriveSymLink Loaded!");
	
	char filePath[0x1000] = { 0 };
	GetModuleFileNameA(hModule, filePath, sizeof(filePath));
	//RootPath = filePath;

	if (!hook()) {
		OutputDebugStringA("OneDriveSymLink Hook Failed!");
		return FALSE;
	}
	OutputDebugStringA("AppraiserHijack Hook Success!");
	return TRUE;
}