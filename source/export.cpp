#include "export.hpp"

#include "core/core.hpp"
#include "hooking/input-hook.hpp"
#include "invoker/invoker.hpp"

#define DLL_EXPORT __declspec(dllexport)

DLL_EXPORT void keyboardHandlerRegister(KeyboardHandler handler)
{
    rh2::hooking::input::AddCallback(handler);
}

DLL_EXPORT void keyboardHandlerUnregister(KeyboardHandler handler)
{
    rh2::hooking::input::RemoveCallback(handler);
}

DLL_EXPORT void scriptWait(DWORD time)
{
    rh2::ScriptWait(std::chrono::milliseconds(time));
}

DLL_EXPORT void scriptRegister(HMODULE module, void (*LP_SCRIPT_MAIN)())
{
    rh2::ScriptRegister(module, rh2::Script(LP_SCRIPT_MAIN));
}

DLL_EXPORT void scriptRegisterAdditionalThread(HMODULE module, void (*LP_SCRIPT_MAIN)())
{
    scriptRegister(module, LP_SCRIPT_MAIN);
}

DLL_EXPORT void scriptUnregister(HMODULE module)
{
    rh2::ScriptUnregister(module);
}

DLL_EXPORT void nativeInit(uint64_t hash)
{
    rh2::Invoker::NativeInit(hash);
}

DLL_EXPORT void nativePush64(uint64_t val)
{
    rh2::Invoker::NativePush(val);
}

DLL_EXPORT PUINT64 nativeCall()
{
    return reinterpret_cast<PUINT64>(rh2::Invoker::NativeCall());
}

DLL_EXPORT UINT64* getGlobalPtr(int globalId)
{
    return rh2::GetGlobalPtr(globalId);
}

DLL_EXPORT int worldGetAllVehicles(int* arr, int arrSize)
{
    return 0;
}
DLL_EXPORT int worldGetAllPeds(int* arr, int arrSize)
{
    return 0;
}
DLL_EXPORT int worldGetAllObjects(int* arr, int arrSize)
{
    return 0;
}
DLL_EXPORT int worldGetAllPickups(int* arr, int arrSize)
{
    return 0;
}

DLL_EXPORT BYTE* getScriptHandleBaseAddress(int handle)
{
    return 0;
}

enum eGameVersion : int
{
    VER_AUTO,

    VER_SIZE,
    VER_UNK = -1
};

DLL_EXPORT eGameVersion getGameVersion()
{
    return VER_AUTO;
}
