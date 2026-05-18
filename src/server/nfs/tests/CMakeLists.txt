# SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
#
# SPDX-License-Identifier: LGPL-2.1-only

# Unit test for the NFS4.1 SEQUENCE replay slot state machine.  Drives
# nfs4_replay_slot_acquire / _finalize directly.  We compile the
# session source file straight into the test executable (rather than
# linking libchimera_nfs.so) because the replay-slot functions are not
# SYMBOL_EXPORT'd -- they are only called from inside the chimera_nfs
# library at runtime.
add_executable(test_replay_slot
    test_replay_slot.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../nfs4_session.c)
target_include_directories(test_replay_slot PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${NFS_COMMON_INCLUDE_DIR})
target_link_libraries(test_replay_slot chimera_vfs chimera_common evpl evpl_rpc2 pthread uuid)
add_test(NAME chimera/server/nfs/replay_slot COMMAND test_replay_slot)
