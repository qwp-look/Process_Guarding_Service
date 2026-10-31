# Manifest-driven modules.lock generation (manifest v2).
# Scans PGS_MODULES_ROOT for module directories containing module.manifest.json
# and a built DLL, and derives the lock entries (name/version/class/capabilities/
# risk) from the manifests. The DLL sha256 anchors the supply chain.

set(out "${PGS_MODULES_LOCK_OUT}")
if(NOT out)
    message(FATAL_ERROR "PGS_MODULES_LOCK_OUT is required")
endif()
if(NOT PGS_MODULES_ROOT)
    message(FATAL_ERROR "PGS_MODULES_ROOT is required")
endif()

file(GLOB module_dirs LIST_DIRECTORIES true "${PGS_MODULES_ROOT}/*")
list(SORT module_dirs)

set(json "{\n  \"version\": 2,\n  \"generated_at\": \"cmake-build\",\n  \"modules\": [\n")
set(first TRUE)
set(count 0)

foreach(dir ${module_dirs})
    if(NOT IS_DIRECTORY "${dir}")
        continue()
    endif()
    set(manifest "${dir}/module.manifest.json")
    if(NOT EXISTS "${manifest}")
        continue()
    endif()
    get_filename_component(name "${dir}" NAME)
    set(dll "${dir}/pgs_${name}_module.dll")
    if(NOT EXISTS "${dll}")
        message(FATAL_ERROR "module manifest present but DLL missing: ${dll}")
    endif()

    file(READ "${manifest}" manifest_json)
    string(JSON mname GET "${manifest_json}" "name")
    if(NOT mname STREQUAL name)
        message(FATAL_ERROR "manifest name '${mname}' does not match module folder '${name}'")
    endif()
    string(JSON mversion GET "${manifest_json}" "version")
    string(JSON mrisk GET "${manifest_json}" "risk")
    string(JSON mclass ERROR_VARIABLE class_err GET "${manifest_json}" "class")
    if(class_err)
        set(mclass "command")
    endif()
    string(JSON mcaps GET "${manifest_json}" "capabilities")
    file(SHA256 "${dll}" hash)

    if(first)
        set(first FALSE)
    else()
        string(APPEND json ",\n")
    endif()
    string(APPEND json "    {\"name\":\"${mname}\",\"version\":\"${mversion}\",\"class\":\"${mclass}\",\"sha256\":\"${hash}\",\"publisher\":\"PGS bundled\",\"source\":\"bundled\",\"capabilities\":${mcaps},\"risk\":\"${mrisk}\",\"trustedAt\":\"cmake-build\",\"signature_policy\":\"hash\",\"require_signed\":false}")
    math(EXPR count "${count} + 1")
endforeach()

if(count EQUAL 0)
    message(FATAL_ERROR "no module manifests found under ${PGS_MODULES_ROOT}")
endif()

string(APPEND json "\n  ]\n}\n")
file(WRITE "${out}" "${json}")
