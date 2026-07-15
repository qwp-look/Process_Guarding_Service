# PGS module staging

Community or external modules should land here first during an install flow. PGS must verify the manifest, path, hash/signature policy, capabilities, and risk before anything is copied into the protected `modules/<name>/` tree or loaded by the core loader.
