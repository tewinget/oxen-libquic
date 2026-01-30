include(ExternalProject)

function(enable_lto)
  if(IPO_ENABLED)
    set_target_properties(${ARGN} PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
  endif()
endfunction()

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)

# Force shared libs off for any libraries we build inside here so that if we build a shared lib we
# don't end up with a libspdlog.so or whatever that would need to be distributed alongside the
# libquic.so
set(BUILD_SHARED_LIBS OFF)

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

check_submodule(oxen-logging fmt spdlog)
check_submodule(oxen-encoding)

# oxen-logging
if (NOT TARGET oxen::logging)
    if(BUILD_STATIC_DEPS)
        set(OXEN_LOGGING_FORCE_SUBMODULES ON CACHE INTERNAL "")
    endif()
    sessiondep_or_submodule(liboxen-logging 1.2.0 oxen-logging oxen::logging)
    if(NOT TARGET oxen-logging)
        # If we load oxen-logging via system lib then we won't necessarily have fmt/spdlog targets,
        # but this script will give us them:
        include(oxen-logging/cmake/load_fmt_spdlog.cmake)

        add_library(oxen-logging-fmt-spdlog INTERFACE)
        target_link_libraries(oxen-logging-fmt-spdlog INTERFACE oxen::logging ${OXEN_LOGGING_FMT_TARGET} ${OXEN_LOGGING_SPDLOG_TARGET})
        add_library(oxen::logging-fmt ALIAS oxen-logging-fmt-spdlog)
    else()
        # Otherwise oxen-logging from the submodule will already publicly provide fmt/spdlog:
        add_library(oxen::logging-fmt ALIAS oxen-logging)
    endif()
endif()

# oxenc
if (NOT TARGET oxenc::oxenc)
    sessiondep_or_submodule(liboxenc 1.4.0 oxen-encoding oxenc::oxenc)
endif()
