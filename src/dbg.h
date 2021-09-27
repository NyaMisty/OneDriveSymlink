#define dbg(format, ...) ShowDebugBase(TEXT("FUNC: %s()  MSG: ") TEXT(format), TEXT(__FUNCTION__), ##__VA_ARGS__)

inline void ShowDebugBase(const TCHAR* format, ...)
{
	va_list args;
	SYSTEMTIME time;
	TCHAR tempBuf[1920];
	TCHAR msgBuf[2048];

	GetLocalTime(&time);

	va_start(args, format);
	_vstprintf_s(tempBuf, format, args);
	_stprintf_s(msgBuf, TEXT("***DEBUG***  TIME: %02d:%02d:%02d.%03d  %s\n"), time.wHour, time.wMinute, time.wSecond, time.wMilliseconds, tempBuf);

	OutputDebugString(msgBuf);
	va_end(args);
}


#define wassert(exp) \
	if (!(exp)) {\
		dbg("wassert: before GetLastError(): %d", GetLastError());\
	}\
	assert(exp);