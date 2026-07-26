#ifndef PGS_REGISTRY_INSTALL_H
#define PGS_REGISTRY_INSTALL_H

#include <string>

namespace ProcessGuard::tools
{
    int runModuleInstallFromRegistry(const std::string &moduleName,
                                     bool trustCurated,
                                     bool trustCommunity,
                                     bool confirmOperation,
                                     const std::string &token,
                                     const std::string &host,
                                     int port);
}

#endif // PGS_REGISTRY_INSTALL_H
