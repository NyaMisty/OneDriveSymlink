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
#include "dbg.h"
#include "win_handle.h"
#include "LRUCache.hpp"

decltype(&ReadDirectoryChangesW) pReadDirectoryChangesW;
decltype(&ReadDirectoryChangesExW) pReadDirectoryChangesExW;
decltype(&CreateIoCompletionPort) pCreateIoCompletionPort;
decltype(&CancelIoEx) pCancelIoEx;


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
	READ_DIRECTORY_NOTIFY_INFORMATION_CLASS notifyClass;
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

	BOOL readChangeStart(DWORD notifyFlags, DWORD bufferLen, READ_DIRECTORY_NOTIFY_INFORMATION_CLASS notifyClass) {
		retBuffer.resize(bufferLen);
		this->notifyFlags = notifyFlags;
		this->notifyClass = notifyClass;
		
		BOOL success = FALSE;
		if (notifyClass != (READ_DIRECTORY_NOTIFY_INFORMATION_CLASS)-1) {
			success = pReadDirectoryChangesExW(
				h->get(), retBuffer.data(), (DWORD)retBuffer.size(), TRUE, notifyFlags, // 11f
				NULL, &ovl, NULL, notifyClass);
		}
		else {
			success = pReadDirectoryChangesW(
				h->get(), retBuffer.data(), (DWORD)retBuffer.size(), TRUE, notifyFlags, // 11f
				NULL, &ovl, NULL);
		}
		
		return success;
	}

	BOOL readChangeStop() {
		return CancelIoEx(h->get(), &ovl);
	}
};

template<typename T>
size_t rewriteRDC(OverlapSymlinkContext &c, void *eventBuf, void *outEventBuf) {
	T* event = (T*)eventBuf;
	T* outevent = (T*)outEventBuf;

	size_t bytesOut = 0;
	for (;;) {
		DWORD name_len = event->FileNameLength / sizeof(wchar_t);

		memcpy(outevent, event, sizeof(T));
		wcscpy(outevent->FileName, to_wide_string(c.relaPath).c_str());
		wcscat(outevent->FileName, std::wstring(event->FileName, (size_t)event->FileNameLength / 2).c_str());
		dbg("Got changing notification: %S, action: %d", event->FileName, outevent->Action);
		dbg("Rewriting changing notification: %S -> %S, action: %d", event->FileName, outevent->FileName, outevent->Action);
		size_t new_name_len = wcslen(outevent->FileName);
		outevent->FileNameLength = (DWORD)new_name_len * 2;
		size_t curSize = (char*)&outevent->FileName - (char*)outevent + outevent->FileNameLength + 2;
		outevent->NextEntryOffset = (DWORD)curSize;
		outevent->NextEntryOffset += (8 - outevent->NextEntryOffset % 8); // round to aligned
		bytesOut += outevent->NextEntryOffset;

		dbg("Entry finished, next offset %d vs %d", event->NextEntryOffset, outevent->NextEntryOffset);
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
	return bytesOut;
}

class SymlinkGroup {
public:
	std::string rootPath;
	time_t last_updated;
	std::map<std::string, OverlapSymlinkContext> contexts;

	SymlinkGroup() : last_updated(0) {}

	std::vector<char> getChanges(DWORD nBufferLength, DWORD dwNotifyFilter, READ_DIRECTORY_NOTIFY_INFORMATION_CLASS notifyClass, LPDWORD status) {
		BOOL bRet = TRUE;
		auto symlinks = contexts;
		std::map<std::string, OverlapSymlinkContext > retBufferMap;
		std::vector<HANDLE> hEvents;
		std::vector<std::string> keys;
		hEvents.reserve(symlinks.size());
		dbg("Starting readChange...");
		for (auto& it : symlinks) {
			bRet = it.second.readChangeStart(
				//FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SECURITY,
				dwNotifyFilter,
				nBufferLength / 2,
				notifyClass
			);
			if (!bRet) {
				int err = GetLastError();
				dbg("Cannot readChangeStart: GetLastError() = %d", err);
				*status = -1;
				wassert(bRet);
				return {};
			}
			hEvents.push_back(it.second.ovl.hEvent);
			keys.push_back(it.first);
		}
		*status = 0;
		dbg("Waiting for all change notifications...");

		DWORD result = -1;
		while (true) {
			result = WaitForMultipleObjects((DWORD)hEvents.size(), hEvents.data(), FALSE, 1000);
			if (result == WAIT_TIMEOUT) {
				continue;
			}
			break;
		}
		
		dbg("WaitForMultipleObjects GetLastError() = %d, stopping all ReadChanges", GetLastError());
		std::vector<char> outBuffer;
		outBuffer.resize(nBufferLength);
		if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + hEvents.size()) {
			int index = result - WAIT_OBJECT_0;
			DWORD bytes_transferred;
			auto& c = symlinks[keys[index]];
			dbg("Changes hit to %d: %s", index, c.path.c_str());
			bRet = GetOverlappedResult(c.h->get(), &c.ovl, &bytes_transferred, FALSE);
			if (!bRet) {
				int err = GetLastError();
				dbg("Cannot GetOverlappedResult: GetLastError() = %d", err);
				*status = -1;
				wassert(bRet);
				return {};
			}
			dbg("Overlapped result bytes_transferred = %d", bytes_transferred);
			
			size_t bytesOut = 0;
			switch (notifyClass) {
			case ReadDirectoryNotifyFullInformation:
				bytesOut = rewriteRDC<FILE_NOTIFY_FULL_INFORMATION>(c, c.retBuffer.data(), outBuffer.data());
				break;
			case ReadDirectoryNotifyExtendedInformation:
				bytesOut = rewriteRDC<FILE_NOTIFY_EXTENDED_INFORMATION>(c, c.retBuffer.data(), outBuffer.data());
				break;
			case ReadDirectoryNotifyInformation:
			case -1:
				bytesOut = rewriteRDC<FILE_NOTIFY_INFORMATION>(c, c.retBuffer.data(), outBuffer.data());
				break;
			default:
				dbg("Unsupported notify class: %d", notifyClass);
				break;
			}
			dbg("Overlapped result output bytes = %d", bytesOut);
			assert(bytesOut <= nBufferLength);
			outBuffer.resize(bytesOut);
			return outBuffer;
		}
		else {
			*status = result;
			return {};
		}
	}
};

// can't use global one because OneDrive now uses 2 threads for changes listening
//std::map<std::string, SymlinkGroup> handleContexts;
lru::Cache<HANDLE, FILE_COMPLETION_INFORMATION> onedriveIocp;
lru::Cache<HANDLE, LPOVERLAPPED> onedriveOverlapped;

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::shared_ptr<SymlinkGroup> getSymlinkGroup(HANDLE hDirectory) {
	std::string _path = get_handle_path(hDirectory);
	std::string _symlinkConf = _path + "\\symlinks.ini";
	// it's now meaningless to cache it globally because we are more powerful
	//if (handleContexts.contains(_path)) {
	//	if (time(NULL) - handleContexts[_path].last_updated < 30) {
	//		return TRUE;
	//	}
	//	dbg("Symlink List too old, re-construsting...");
	//}
	//else {
	//	if (!FileExists(_symlinkConf.c_str())) {
	//		dbg("path %s has no symlink.ini, returning!", _symlinkConf.c_str());
	//		return FALSE;
	//	}
	//	dbg("Symlink List not exists, construsting...");
	//	
	//	handleContexts[_path] = SymlinkGroup();
	//}
	//handleContexts[_path].last_updated = time(NULL);

	//auto& symlinks = handleContexts[_path].contexts;
	dbg("Reading symlink group from file %s", _symlinkConf.c_str());
	auto ret = std::make_shared<SymlinkGroup>();
	auto& symlinks = ret->contexts;
	symlinks.clear();
	symlinks[_path] = std::move(OverlapSymlinkContext(_path, ""));

	std::ifstream file(_symlinkConf);
	if (file.is_open()) {
		std::string line;
		while (std::getline(file, line)) {
			// using printf() in all tests for consistency
			dbg("Got line %s", line.c_str());
			std::string prefix = "OD\\";
			if (!line.compare(0, prefix.size(), prefix)) {
				auto curRela = line.substr(3);
				std::string curAbsl = _path + "\\" + curRela;

				HANDLE hFile = CreateFileA(
					curAbsl.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
					NULL, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
					NULL);
				curAbsl = get_handle_path(hFile);
				CloseHandle(hFile);
				
				dbg("Add path %s to list", curAbsl.c_str());
				symlinks[curAbsl] = std::move(OverlapSymlinkContext(curAbsl, curRela + "\\"));
			}
		}
		file.close();
	}
	else {
		ret.reset();
	}
	return ret;
}

HANDLE WINAPI hook_CreateIoCompletionPort(
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
		auto handlePath = get_handle_path(FileHandle, TRUE);
		dbg("Got CreateIoCompletionPort for %s (handle=%d) with key %p", handlePath.c_str(), FileHandle, CompletionKey);
		if (handlePath.ends_with("OneDrive")) {
			onedriveIocp.insert(FileHandle, { hRet, (PVOID)CompletionKey });
		}
	}
	return hRet;
}


BOOL WINAPI hook_CancelIoEx(
	HANDLE hFile,
	LPOVERLAPPED lpOverlapped
) {
	onedriveIocp.remove(hFile);
	return pCancelIoEx(hFile, lpOverlapped);
}

BOOL handle_ReadDirectoryChanges(
	HANDLE                          hDirectory,
	LPVOID                          lpBuffer,
	DWORD                           nBufferLength,
	BOOL                            bWatchSubtree,
	DWORD                           dwNotifyFilter,
	LPDWORD                         lpBytesReturned,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	READ_DIRECTORY_NOTIFY_INFORMATION_CLASS ReadDirectoryNotifyInformationClass
) {
	BOOL bRet = TRUE;

	auto callOriginal = [=]() {
		if (ReadDirectoryNotifyInformationClass != (READ_DIRECTORY_NOTIFY_INFORMATION_CLASS)-1) {
			return pReadDirectoryChangesExW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass);
		}
		else {
			return pReadDirectoryChangesW(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine);
		}
	};

	//if (lpOverlapped && (!onedriveIocp.contains(hDirectory) || onedriveIocp[hDirectory].Key == (PVOID)8)) {
	//	dbg("skipping iocp key 8!");
	//	return callOriginal();
	//}
	
	dbg("Entered handle_ReadDirectoryChanges, hDir=%d lpBuffer=%p nBufferLen=0x%x filter=0x%x class=%d", hDirectory, lpBuffer, nBufferLength, dwNotifyFilter, ReadDirectoryNotifyInformationClass);
	if (lpOverlapped->hEvent) {
		dbg("does not support lpOverlapped->hEvent");
		return callOriginal();
	}
	
	//dbg("Updating symlinkList!");

	// bRet = !updateSymlinkList(hDirectory);
	auto group = std::move(getSymlinkGroup(hDirectory));

	if (!group) return callOriginal();

	std::string _path = get_handle_path(hDirectory);
	dbg("handlePath: %s", _path.c_str());

	auto handler = [=](BOOL isIOCP) {
		DWORD handleStatus = 0;
		//auto retBuffer = handleContexts[_path].getChanges(nBufferLength, ReadDirectoryNotifyInformationClass, &handleStatus);
		auto retBuffer = group->getChanges(nBufferLength, dwNotifyFilter, ReadDirectoryNotifyInformationClass, &handleStatus);
		if (isIOCP) {
			//DWORD dwBytesTransferred = 0;
			//BOOL overlappedStatus = GetOverlappedResult(hDirectory, lpOverlapped, &dwBytesTransferred, FALSE);
			//if (!overlappedStatus && GetLastError() == ERROR_OPERATION_ABORTED) {
			//	dbg("Cannot post result: overlapped operation was cancelled");
			//	return FALSE;
			//}

			if (handleStatus == 0 && onedriveIocp.contains(hDirectory)) {
				if (lpOverlapped->hEvent)
					SetEvent(lpOverlapped->hEvent);
				if (nBufferLength < retBuffer.size()) {
					dbg("Cannot post result: overlapped buffer too small %d < %d", nBufferLength, retBuffer.size());
					return FALSE;
				}
				memcpy(lpBuffer, retBuffer.data(), retBuffer.size());
				auto iocpPort = onedriveIocp[hDirectory].Port;
				auto iocpKey = (ULONG_PTR)onedriveIocp[hDirectory].Key;
				BOOL ret = PostQueuedCompletionStatus(iocpPort, (DWORD)retBuffer.size(), iocpKey, NULL);
				dbg("PostQueuedCompletionStatus port=%d key=%d lpBuffer=%p size=0x%x ret: %d", iocpPort, iocpKey, lpBuffer, retBuffer.size(), ret);
			}
			else {
				dbg("can't find corresponding IOCP Port!");
				CancelIoEx(hDirectory, lpOverlapped);
			}
			return TRUE;
		}
		else {
			memcpy(lpBuffer, retBuffer.data(), retBuffer.size());
			return FALSE;
		}
	};

	if (!lpOverlapped) {
		return handler(FALSE);
	}

	//callOriginal();
	std::thread(handler, TRUE).detach();
	return TRUE;
}

BOOL WINAPI hook_ReadDirectoryChangesW(
	HANDLE                          hDirectory,
	LPVOID                          lpBuffer,
	DWORD                           nBufferLength,
	BOOL                            bWatchSubtree,
	DWORD                           dwNotifyFilter,
	LPDWORD                         lpBytesReturned,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	return handle_ReadDirectoryChanges(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, (READ_DIRECTORY_NOTIFY_INFORMATION_CLASS)-1);
}

BOOL WINAPI hook_ReadDirectoryChangesExW(
	HANDLE                          hDirectory,
	LPVOID                          lpBuffer,
	DWORD                           nBufferLength,
	BOOL                            bWatchSubtree,
	DWORD                           dwNotifyFilter,
	LPDWORD                         lpBytesReturned,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	READ_DIRECTORY_NOTIFY_INFORMATION_CLASS ReadDirectoryNotifyInformationClass
) {
	return handle_ReadDirectoryChanges(hDirectory, lpBuffer, nBufferLength, bWatchSubtree, dwNotifyFilter, lpBytesReturned, lpOverlapped, lpCompletionRoutine, ReadDirectoryNotifyInformationClass);
}

bool hook() {
	pReadDirectoryChangesW = hook_ReadDirectoryChangesW; // type check
	*(void **)&pReadDirectoryChangesW = GetProcAddress(LoadLibraryA("kernelbase"), "ReadDirectoryChangesW");
	dbg("got pReadDirectoryChangesW: %p", pReadDirectoryChangesW);
	pReadDirectoryChangesExW = hook_ReadDirectoryChangesExW;
	*(void**)&pReadDirectoryChangesExW = GetProcAddress(LoadLibraryA("kernelbase"), "ReadDirectoryChangesExW");
	dbg("got pReadDirectoryChangesExW: %p", pReadDirectoryChangesExW);
	pCreateIoCompletionPort = hook_CreateIoCompletionPort;
	*(void**)&pCreateIoCompletionPort = GetProcAddress(LoadLibraryA("kernelbase"), "CreateIoCompletionPort");
	dbg("got pCreateIoCompletionPort: %p", pCreateIoCompletionPort);
	pCancelIoEx = hook_CancelIoEx;
	*(void**)&pCancelIoEx = GetProcAddress(LoadLibraryA("kernelbase"), "CancelIoEx");
	dbg("got pCancelIoEx: %p", pCancelIoEx);
	
	LONG ret = 0;
	DetourRestoreAfterWith();
	DetourSetIgnoreTooSmall(TRUE);
	DetourTransactionBegin();
	ret = DetourUpdateThread(GetCurrentThread());
	dbg("got DetourUpdateThread: %d", ret);
	ret = DetourAttach(&(LPVOID&)pReadDirectoryChangesW, hook_ReadDirectoryChangesW);
	dbg("got DetourAttach1: %d", ret);
	ret = DetourAttach(&(LPVOID&)pReadDirectoryChangesExW, hook_ReadDirectoryChangesExW);
	dbg("got DetourAttach2: %d", ret);
	ret = DetourAttach(&(LPVOID&)pCreateIoCompletionPort, hook_CreateIoCompletionPort);
	dbg("got DetourAttach3: %d", ret);
	ret = DetourAttach(&(LPVOID&)pCancelIoEx, hook_CancelIoEx);
	dbg("got DetourAttach4: %d", ret);
	ret = DetourTransactionCommit();
	dbg("got DetourTransactionCommit: %d", ret);
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
	OutputDebugStringA("OneDriveSymLink Hook Success!");
	return TRUE;
}