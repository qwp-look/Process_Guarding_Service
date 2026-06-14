#include "Process_Guard/PGLogger.h"

namespace ProcessGuard
{
std::mutex Logger::m_mutex;
std::ofstream Logger::m_logFile;
} // namespace ProcessGuard
