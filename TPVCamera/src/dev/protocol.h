/**
 * @file protocol.h
 * @brief Fixed-width contract between the resident dev loader and one logic generation.
 *
 * The loader outlives every generation, so everything it hands across the DLL boundary must have a layout
 * both sides agree on without sharing a C++ ABI. A plain C struct with an explicit size and version does
 * that: the logic DLL validates both before touching a field, so a stale generation left in the deploy
 * directory fails loudly instead of reading through a shifted layout.
 *
 * The request layout, the export signatures, and each export's result values are ONE versioned contract.
 * In particular Shutdown() is tri-state: a Boolean check cannot tell a clean retirement (the loader may
 * release its reference) from a retirement that left resources behind (the loader must keep its reference
 * for the rest of the process). Bump TPVCAMERA_RELOAD_ABI_VERSION on any change and rebuild both DLLs.
 *
 * Modelled on DetourModKit's checked-in examples/staged_reload pair, which its hot-reload guide treats as
 * the reference implementation.
 */
#ifndef TPVCAMERA_PROTOCOL_H
#define TPVCAMERA_PROTOCOL_H

#include <DetourModKit/abi/wheel_host.h>

#include <stdint.h>

/** @brief ABI revision of the request layout, the export signatures, and the result values below. */
#define TPVCAMERA_RELOAD_ABI_VERSION 2u

/** @brief A live Init result, or a Shutdown result after a clean retirement with no retained resources. */
#define TPVCAMERA_RELOAD_OK 1u

/** @brief A Shutdown result after a retirement that left resources behind: the loader keeps its module reference. */
#define TPVCAMERA_RELOAD_RETAINED 2u

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @struct TpvReloadInitRequest
     * @brief Fixed-width request passed from the resident loader to one logic generation.
     */
    typedef struct TpvReloadInitRequest
    {
        /** @brief sizeof(TpvReloadInitRequest) as the LOADER knows it. */
        uint32_t struct_size;
        /** @brief TPVCAMERA_RELOAD_ABI_VERSION as the loader knows it. */
        uint32_t abi_version;
        /** @brief Loader-assigned, strictly increasing, never zero. */
        uint64_t generation_id;
        /** @brief The identity the logic DLL must find in wheel_host, so a foreign table is rejected. */
        uint64_t expected_host_identity;
        /** @brief The process-lifetime resident wheel host owned by the loader. */
        const WheelHostTable *wheel_host;
    } TpvReloadInitRequest;

    /** @brief The exports the loader resolves by name on every generation. */
#define TPVCAMERA_RELOAD_INIT_SYMBOL "Init"
#define TPVCAMERA_RELOAD_SHUTDOWN_SYMBOL "Shutdown"
#define TPVCAMERA_RELOAD_REVISION_SYMBOL "Revision"

#ifdef __cplusplus
}
#endif

#endif /* TPVCAMERA_PROTOCOL_H */
