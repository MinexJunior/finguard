#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
  #ifdef FINGUARD_EXPORTS
    #define FINGUARD_API __declspec(dllexport)
  #else
    #define FINGUARD_API __declspec(dllimport)
  #endif
#else
  #define FINGUARD_API __attribute__((visibility("default")))
#endif

// PreFlight Decision Codes
#define FINGUARD_DECISION_ALLOW_LAUNCH        0
#define FINGUARD_DECISION_WARN_USER           1
#define FINGUARD_DECISION_REQUIRE_USER_REVIEW 2
#define FINGUARD_DECISION_BLOCK_LAUNCH        3

/**
 * Perform full system endpoint integrity scan and return JSON string.
 * Caller MUST free the returned string using finguard_free_string().
 */
FINGUARD_API char* finguard_scan_system_json(bool real_procfs);

/**
 * Perform static PE file inspection and return JSON string.
 * Caller MUST free the returned string using finguard_free_string().
 */
FINGUARD_API char* finguard_analyze_pe_json(const char* filepath);

/**
 * Quick query for pre-flight decision integer code (0=Allow, 1=Warn, 2=Review, 3=Block).
 */
FINGUARD_API int finguard_get_preflight_decision(bool real_procfs);

/**
 * Quick query for numerical composite risk score (0 - 100).
 */
FINGUARD_API uint32_t finguard_get_system_risk_score(bool real_procfs);

/**
 * Free memory allocated by FinGuard C-ABI strings.
 */
FINGUARD_API void finguard_free_string(char* ptr);

#ifdef __cplusplus
}
#endif
