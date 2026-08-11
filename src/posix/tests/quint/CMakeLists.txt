# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

# POSIX model-based tests: the Quint specification (posix.qnt and friends)
# generates traces of POSIX file-API calls with expected results baked into
# every step; posix_replay.py replays them against chimera's POSIX client
# backed by an in-process memfs mount, through the JSON line protocol served
# by posix_driver, and fails on any unregistered divergence.
#
# Traces are generated at build time from fixed seeds against the posixMemfs
# instance (capability/policy profile pinned to memfs's probed behavior, see
# posix_run.qnt), so every trace's LInit profile matches the live backend and
# no trace is skipped by profile reconciliation.

add_executable(posix_quint_driver posix_driver.c)
target_link_libraries(posix_quint_driver
    chimera_posix chimera_client chimera_server jansson)

find_program(QUINT_BIN quint)
find_package(Python3 COMPONENTS Interpreter)

if(NOT QUINT_BIN OR NOT Python3_FOUND)
    message(STATUS "posix MBT tests skipped (need quint + python3)")
    return()
endif()

set(POSIX_MBT_MODEL ${CMAKE_CURRENT_SOURCE_DIR}/posix_run.qnt)
set(POSIX_MBT_REPLAY ${CMAKE_CURRENT_SOURCE_DIR}/posix_replay.py)
set(POSIX_MBT_TRACE_DIR ${CMAKE_CURRENT_BINARY_DIR}/traces)

file(MAKE_DIRECTORY ${POSIX_MBT_TRACE_DIR})

set(POSIX_MBT_TRACE_FILES)

# Generate a batch of N traces for one (flavor, steps) with a single quint
# invocation (same amortization as the NFS3 suite: node startup + parse
# dominate, so --n-traces batches are nearly free).  --invariant=inv gates
# every trace, so a model bug fails the build.
function(posix_mbt_add_batch flavor steps ntraces seed)
    set(traces)
    math(EXPR last "${ntraces} - 1")
    foreach(seq RANGE 0 ${last})
        list(APPEND traces
             ${POSIX_MBT_TRACE_DIR}/${flavor}_${steps}_${seed}_${seq}.itf.json)
    endforeach()

    # quint exits 0 without writing anything if the output directory is
    # missing (e.g. after an rm -rf of the trace dir, which only configure
    # recreates), so make the directory part of the recipe.
    add_custom_command(OUTPUT ${traces}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${POSIX_MBT_TRACE_DIR}
        COMMAND ${QUINT_BIN} run ${POSIX_MBT_MODEL} --main=posixMemfs
                --step=${flavor} --max-steps=${steps}
                --max-samples=${ntraces} --n-traces=${ntraces} --seed=${seed}
                --invariant=inv
                --out-itf=${POSIX_MBT_TRACE_DIR}/${flavor}_${steps}_${seed}_{seq}.itf.json > /dev/null
        DEPENDS ${POSIX_MBT_MODEL}
                ${CMAKE_CURRENT_SOURCE_DIR}/posix.qnt
                ${CMAKE_CURRENT_SOURCE_DIR}/posix_ops.qnt
                ${CMAKE_CURRENT_SOURCE_DIR}/posix_fs.qnt
                ${CMAKE_CURRENT_SOURCE_DIR}/posix_state.qnt
        COMMENT "Generating ${ntraces} POSIX MBT traces ${flavor} steps=${steps}"
        VERBATIM)

    list(APPEND POSIX_MBT_TRACE_FILES ${traces})
    set(POSIX_MBT_TRACE_FILES ${POSIX_MBT_TRACE_FILES} PARENT_SCOPE)

    foreach(trace ${traces})
        get_filename_component(tname ${trace} NAME_WE)
        set(name chimera/posix/mbt/${tname}_memfs)
        add_test(NAME ${name}
            COMMAND ${Python3_EXECUTABLE} ${POSIX_MBT_REPLAY}
                    --trace ${trace}
                    --driver $<TARGET_FILE:posix_quint_driver>)
        set_tests_properties(${name} PROPERTIES
            LABELS "posix_mbt;memfs"
            ENVIRONMENT "PYTHONUNBUFFERED=1"
            SKIP_RETURN_CODE 77
            TIMEOUT 120)
    endforeach()
endfunction()

posix_mbt_add_batch(step            128 10 0x1)
posix_mbt_add_batch(step            128  6 0x2)
posix_mbt_add_batch(step            256  3 0x100)
posix_mbt_add_batch(step            512  2 0x5)
posix_mbt_add_batch(stepNamespace   128  4 0x1)
posix_mbt_add_batch(stepNamespace   256  2 0x9)
posix_mbt_add_batch(stepDescriptors 128  4 0x1)
posix_mbt_add_batch(stepMetadata    128  4 0x1)
posix_mbt_add_batch(stepDirs        128  3 0x1)
posix_mbt_add_batch(stepData        128  4 0x1)
posix_mbt_add_batch(stepLocks       128  2 0x1)
posix_mbt_add_batch(stepPerms       128  5 0x1)
posix_mbt_add_batch(stepLinks       128  5 0x1)
posix_mbt_add_batch(stepFds         128  5 0x1)

add_custom_target(posix_mbt_traces ALL DEPENDS ${POSIX_MBT_TRACE_FILES})

# Model self-checks (deterministic run definitions plus bounded random
# walks); catches model regressions without involving the client.
add_test(NAME chimera/posix/mbt/model_selftest_std
    COMMAND ${QUINT_BIN} test --max-samples=100 --main=posixTestStd
            ${CMAKE_CURRENT_SOURCE_DIR}/posixTest.qnt)
add_test(NAME chimera/posix/mbt/model_selftest_root
    COMMAND ${QUINT_BIN} test --max-samples=100 --main=posixTestRoot
            ${CMAKE_CURRENT_SOURCE_DIR}/posixTest.qnt)
set_tests_properties(chimera/posix/mbt/model_selftest_std
                     chimera/posix/mbt/model_selftest_root PROPERTIES
    LABELS "posix_mbt"
    TIMEOUT 600)
