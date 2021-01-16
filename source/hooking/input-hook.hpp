#pragma once

#include <cstdint>
#include <Windows.h>

namespace rh2::hooking::input
{
    using KeyboardCallback = void (*)(DWORD key, WORD repeats, BYTE scanCode, BOOL isExtended, BOOL isWithAlt, BOOL wasDownBefore, BOOL isUpNow);

    bool InitializeHook();

    bool RemoveHook();

    void AddCallback(KeyboardCallback callback);

    void RemoveCallback(KeyboardCallback callback);
} // namespace rh2::hooking::input