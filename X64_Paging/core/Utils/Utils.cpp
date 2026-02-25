#include <ntifs.h>
#include <stdarg.h>
#include <ntddk.h>
#include <intrin.h>
#include <sdk.h>

#ifdef _DEBUG
void Log::print(const char* text, ...)
{
    va_list(args);
    va_start(args, text);
    vDbgPrintExWithPrefix("Dbg -> ", 0, 0, text, args);
    va_end(args);
}
void Log::Prodprint(const char*, ...) {} // Leer im Debug

#else // RELEASE
void Log::print(const char*, ...) {} // Leer im Release
void Log::Prodprint(const char* text, ...)
{
    va_list(args);
    va_start(args, text);
    vDbgPrintExWithPrefix("Prod -> ", 0, 0, text, args);
    va_end(args);
}
#endif