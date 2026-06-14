#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <string>

namespace
{
DWORD parseSleepMs(int argc, char *argv[])
{
    // Dedicated test helper:
    // keep the process alive long enough for bless-start/get/cleanup smoke tests
    // without introducing any self-registration or protocol logic.
    DWORD sleepMs = 30000;
    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--sleep-ms" && i + 1 < argc)
        {
            try
            {
                const unsigned long parsed = std::stoul(argv[++i]);
                if (parsed > 0)
                {
                    sleepMs = static_cast<DWORD>(parsed);
                }
            }
            catch (...)
            {
                return sleepMs;
            }
        }
    }
    return sleepMs;
}
} // namespace

int main(int argc, char *argv[])
{
    const DWORD sleepMs = parseSleepMs(argc, argv);
    std::cout << "smoke_worker pid=" << GetCurrentProcessId() << " sleep_ms=" << sleepMs << "\n";
    Sleep(sleepMs);
    return 0;
}
