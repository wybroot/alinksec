//go:build nativeyara && cgo && (linux || windows)

package yara

/*
#cgo linux LDFLAGS: -Wl,-Bstatic -lyara -Wl,-Bdynamic -lm -lpthread
#cgo windows LDFLAGS: -static -lyara -lws2_32 -lcrypt32
#include <yara.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char identifiers[32][129]; int severity[32]; int count; int issue; } alink_yara_result;
static int alink_severity(YR_RULE* rule) {
  YR_META* meta; int severity = 4;
  yr_rule_metas_foreach(rule, meta) {
    if (strcmp(meta->identifier, "severity") == 0) {
      if (meta->type != META_TYPE_INTEGER || meta->integer < 1 || meta->integer > 5) return 0;
      severity = (int)meta->integer;
    }
  }
  return severity;
}
static int alink_callback(YR_SCAN_CONTEXT* context, int message, void* data, void* user) {
  alink_yara_result* out = (alink_yara_result*)user;
  if (message == CALLBACK_MSG_TOO_MANY_MATCHES) {out->issue = 4; return CALLBACK_ERROR;}
  if (message == CALLBACK_MSG_TOO_SLOW_SCANNING) {out->issue = 5; return CALLBACK_ERROR;}
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    YR_RULE* rule = (YR_RULE*)data;
    if (out->count >= 32 || strlen(rule->identifier) > 128) {out->issue = 4; return CALLBACK_ERROR;}
    strcpy(out->identifiers[out->count], rule->identifier);
    out->severity[out->count] = alink_severity(rule); out->count++;
  }
  // No matching strings, metadata text, module dumps or console logs escape.
  return CALLBACK_CONTINUE;
}
static void alink_scan(const char* source, const uint8_t* data, size_t size, int probe, int seconds, alink_yara_result* out) {
  YR_COMPILER* compiler = NULL; YR_RULES* rules = NULL; YR_RULE* rule; int count = 0; int error;
  memset(out, 0, sizeof(*out));
  if (yr_initialize() != ERROR_SUCCESS) {out->issue = 6; return;}
  yr_set_configuration_uint32(YR_CONFIG_STACK_SIZE, 4096);
  yr_set_configuration_uint32(YR_CONFIG_MAX_STRINGS_PER_RULE, 1000);
  yr_set_configuration_uint32(YR_CONFIG_MAX_MATCH_DATA, 0);
  if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {out->issue = 6; goto done;}
  yr_compiler_set_include_callback(compiler, NULL, NULL, NULL);
  if (yr_compiler_add_string(compiler, source, NULL) != 0 || yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {out->issue = 1; goto done;}
  yr_rules_foreach(rules, rule) {
    count++;
    if (alink_severity(rule) == 0) {out->issue = 1; goto done;}
    if (count > 2000) {out->issue = 3; goto done;}
  }
  if (count == 0) {out->issue = 2; goto done;}
  if (probe) goto done;
  error = yr_rules_scan_mem(rules, data, size, SCAN_FLAGS_REPORT_RULES_MATCHING, alink_callback, out, seconds);
  if (out->issue != 0) goto done;
  if (error == ERROR_SCAN_TIMEOUT) out->issue = 5;
  else if (error != ERROR_SUCCESS) out->issue = 6;
done:
  if (rules != NULL) yr_rules_destroy(rules);
  if (compiler != NULL) yr_compiler_destroy(compiler);
  yr_finalize();
}
*/
import "C"

import "unsafe"

func nativeVersion() string { return C.YR_VERSION }
func nativeScan(rules, data []byte, probe bool, seconds int) ([]Match, string) {
	source := C.CString(string(rules))
	defer C.free(unsafe.Pointer(source))
	var ptr unsafe.Pointer
	if len(data) > 0 {
		ptr = C.CBytes(data)
		defer C.free(ptr)
	}
	var result C.alink_yara_result
	var p C.int
	if probe {
		p = 1
	}
	C.alink_scan(source, (*C.uint8_t)(ptr), C.size_t(len(data)), p, C.int(seconds), &result)
	codes := []string{"", "yara_compile_error", "yara_empty_rules", "yara_rule_limit", "yara_match_limit", "yara_timeout", "yara_scan_error"}
	if result.issue != 0 {
		if int(result.issue) >= len(codes) {
			return nil, "yara_scan_error"
		}
		return nil, codes[result.issue]
	}
	matches := make([]Match, 0, int(result.count))
	for i := 0; i < int(result.count); i++ {
		matches = append(matches, Match{Rule: C.GoString(&result.identifiers[i][0]), Severity: int32(result.severity[i])})
	}
	return matches, ""
}
