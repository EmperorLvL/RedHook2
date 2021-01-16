#pragma once

#include "../util/fiber.hpp"
#include "../memory/memory-location.hpp"
#include "../scripting/script.hpp"
#include "../rage/scrProgram.hpp"
#include "../types.hpp"

#include <chrono>

namespace rh2
{
    bool Init(hMod module);

    void Unload();

    Fiber GetGameFiber();

    MemoryLocation GetPatchVectorResults();

    MemoryLocation Get_s_CommandHash();

    MemoryLocation Get_rage__scrThread__GetCmdFromHash();

    void ScriptRegister(hMod module, const class Script& script);

    void ScriptUnregister(hMod module);

    void ScriptWait(const std::chrono::high_resolution_clock::duration& duration);

    static UINT64* GetGlobalPtr(int index)
    {
        if (!rage::scrProgram::sm_Globals)
            return nullptr;

        auto global_address = &rage::scrProgram::sm_Globals[index >> 18 & 0x3F][index & 0x3FFFF];

        if (global_address == nullptr)
            return nullptr;

        return global_address;
    }
} // namespace rh2
