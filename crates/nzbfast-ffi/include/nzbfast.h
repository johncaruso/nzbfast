/* C ABI for the embedded nzbfast engine (libnzbfast_ffi.a).
 *
 * The engine runs inside the host process and serves the nzbfast API and
 * web dashboard on 127.0.0.1:<port>. Hand-written on purpose - three
 * functions do not earn a cbindgen step; keep in sync with src/lib.rs.
 */
#ifndef NZBFAST_H
#define NZBFAST_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start the engine on a background thread.
 * config_dir: writable directory (UTF-8); config, settings, spool and
 *             downloads live under it.
 * port:       TCP port to serve on (bound to 127.0.0.1 only).
 * apikey:     API key to require, or NULL for an open loopback API.
 * Returns 0 = started (asynchronously - poll the port for readiness),
 * -1 = already running, -2 = bad arguments.
 */
int32_t nzbfast_start(const char *config_dir, uint16_t port, const char *apikey);

/* Stop the engine and release the port. Blocks briefly (bounded).
 * Returns 0 = stopped, -1 = not running. */
int32_t nzbfast_stop(void);

/* 1 while the engine thread is alive; readiness is the HTTP port. */
int32_t nzbfast_is_up(void);

#ifdef __cplusplus
}
#endif

#endif /* NZBFAST_H */
