# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

# NFS3 model-based tests: a Quint specification (nfs3.qnt) generates traces
# of NFS3 RPCs with expected replies baked into every step; replay.py sends
# them to a live chimera daemon through the standalone client in
# nfs3_client.py and fails on any divergence.
#
# Traces are generated at build time from fixed seeds, so they always match
# the current model source; determinism comes from the pinned quint version
# (see .devcontainer/Dockerfile) plus the fixed seed per trace.

find_program(QUINT_BIN quint)
find_package(Python3 COMPONENTS Interpreter)

if(NOT QUINT_BIN)
    message(STATUS "quint not found - NFS3 model-based tests will be skipped "
                   "(npm install -g @informalsystems/quint)")
    return()
endif()
if(NOT Python3_FOUND OR NOT CHIMERA_NETNS_TESTING)
    message(STATUS "NFS3 model-based tests skipped (need python3 + netns)")
    return()
endif()

set(NFS3_MBT_MODEL ${CMAKE_CURRENT_SOURCE_DIR}/nfs3.qnt)
set(NFS3_MBT_REPLAY ${CMAKE_CURRENT_SOURCE_DIR}/replay.py)
set(NFS3_MBT_TRACE_DIR ${CMAKE_CURRENT_BINARY_DIR}/traces)
set(CHIMERA_DAEMON ${CMAKE_BINARY_DIR}/src/daemon/chimera)

file(MAKE_DIRECTORY ${NFS3_MBT_TRACE_DIR})

set(NFS3_MBT_TRACE_FILES)

# Generate a batch of N traces for one (flavor, steps) with a SINGLE quint
# invocation, then register one CTest entry per trace.  `flavor` selects the
# model's step distribution (--step): "step" is the uniform mix;
# stepChurn/stepDir/stepExcl bias toward namespace churn, empty-directory
# operations, and exclusive-create retries respectively.  The blend is chosen
# to saturate coverage.py's behavior buckets (uniform stepping alone starves
# successful-rmdir, dir-into-empty-dir rename, and idempotent exclusive-create
# retries).
#
# Batching matters: quint's ~1.5s per-invocation cost is node startup + model
# parse, not the (millisecond) simulation, so `--n-traces=N --out-itf=..{seq}..`
# amortizes that fixed cost across all N traces of a group -- one invocation
# emits N distinct walks from the seed's sample stream in about the time one
# trace used to take.  --invariant=inv still gates every generated trace, so a
# model bug fails the build rather than producing a nonsense corpus.
function(nfs3_mbt_add_batch flavor steps ntraces seed)
    set(traces)
    math(EXPR last "${ntraces} - 1")
    foreach(seq RANGE 0 ${last})
        list(APPEND traces ${NFS3_MBT_TRACE_DIR}/${flavor}_${steps}_${seq}.itf.json)
    endforeach()

    add_custom_command(OUTPUT ${traces}
        COMMAND ${QUINT_BIN} run ${NFS3_MBT_MODEL}
                --step=${flavor} --max-steps=${steps}
                --max-samples=${ntraces} --n-traces=${ntraces} --seed=${seed}
                --invariant=inv
                --out-itf=${NFS3_MBT_TRACE_DIR}/${flavor}_${steps}_{seq}.itf.json > /dev/null
        DEPENDS ${NFS3_MBT_MODEL}
        COMMENT "Generating ${ntraces} NFS3 MBT traces ${flavor} steps=${steps}"
        VERBATIM)

    list(APPEND NFS3_MBT_TRACE_FILES ${traces})
    set(NFS3_MBT_TRACE_FILES ${NFS3_MBT_TRACE_FILES} PARENT_SCOPE)

    foreach(trace ${traces})
        get_filename_component(tname ${trace} NAME_WE)
        set(name chimera/server/nfs/mbt/${tname}_memfs)
        add_test(NAME ${name}
            COMMAND ${CMAKE_SOURCE_DIR}/scripts/netns_test_wrapper.sh
                    ${Python3_EXECUTABLE} ${NFS3_MBT_REPLAY}
                    --trace ${trace}
                    --chimera ${CHIMERA_DAEMON})
        set_tests_properties(${name} PROPERTIES
            LABELS "nfs3_mbt;memfs"
            ENVIRONMENT "PYTHONUNBUFFERED=1"
            TIMEOUT 120)
    endforeach()
endfunction()

# Coverage-derived blend (see coverage.py): the uniform flavor gives broad
# op/attr/IO coverage; the biased flavors fill the buckets it starves.  One
# invocation per (flavor, steps) group; the seed makes the batch reproducible.
nfs3_mbt_add_batch(step      128 10 0x1)
nfs3_mbt_add_batch(step      256  3 0x100)
nfs3_mbt_add_batch(stepChurn 128  6 0x1)
nfs3_mbt_add_batch(stepChurn 256  2 0x200)
nfs3_mbt_add_batch(stepDir   128  4 0x1)
nfs3_mbt_add_batch(stepExcl  128  3 0x1)

add_custom_target(nfs3_mbt_traces ALL DEPENDS ${NFS3_MBT_TRACE_FILES})

# Coverage gate: classify every step of the generated corpus into behavior
# buckets and fail if any bucket is never exercised.  This catches a
# generation blend (or a model change) that silently stops covering a
# scenario -- the report also prints the LOW buckets worth more seeds.  No
# server needed; it reads the same traces the replays consume.
add_test(NAME chimera/server/nfs/mbt/coverage
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/coverage.py
            --fail-on-starved --glob "${NFS3_MBT_TRACE_DIR}/*.itf.json")
set_tests_properties(chimera/server/nfs/mbt/coverage PROPERTIES
    LABELS "nfs3_mbt"
    ENVIRONMENT "PYTHONUNBUFFERED=1"
    TIMEOUT 120)

# Model self-checks (deterministic run definitions plus a bounded random
# walk); catches model regressions without involving a server.
add_test(NAME chimera/server/nfs/mbt/model_selftest
    COMMAND ${QUINT_BIN} test --max-samples=500
            ${CMAKE_CURRENT_SOURCE_DIR}/nfs3Test.qnt)
set_tests_properties(chimera/server/nfs/mbt/model_selftest PROPERTIES
    LABELS "nfs3_mbt"
    TIMEOUT 120)

# Deviation probe: asserts each documented chimera deviation (DEVIATIONS.md)
# still reproduces, and that the two fixed deadlocks (LINK/RENAME self-alias)
# do not hang.  Goes red when chimera is fixed -- the signal to retire a
# deviation -- or if a deadlock regresses.
add_test(NAME chimera/server/nfs/mbt/deviation_probe_memfs
    COMMAND ${CMAKE_SOURCE_DIR}/scripts/netns_test_wrapper.sh
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/deviation_probe.py
            --chimera ${CHIMERA_DAEMON})
set_tests_properties(chimera/server/nfs/mbt/deviation_probe_memfs PROPERTIES
    LABELS "nfs3_mbt;memfs"
    ENVIRONMENT "PYTHONUNBUFFERED=1"
    TIMEOUT 120)
