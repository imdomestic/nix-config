package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*free_fn)(void*, size_t);
typedef struct { uint32_t abi_version; void* host_ctx; host_call_fn call; free_fn free_buffer; } cliproxy_host_api;
typedef int (*plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*shutdown_fn)(void);
typedef struct { uint32_t abi_version; plugin_call_fn call; free_fn free_buffer; shutdown_fn shutdown; } cliproxy_plugin_api;
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
static const cliproxy_host_api* host_api;
static void set_host(const cliproxy_host_api* h) { host_api = h; }
static int host_call(const char* method, const uint8_t* req, size_t len, cliproxy_buffer* out) {
  if (!host_api || !host_api->call) return 1;
  return host_api->call(host_api->host_ctx, method, req, len, out);
}
static void host_free(void* ptr, size_t len) {
  if (host_api && host_api->free_buffer && ptr) host_api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"encoding/json"
	"unsafe"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *problem        `json:"error,omitempty"`
}

type problem struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status"`
}

func (p *problem) Error() string                     { return p.Message }
func fail(status int, code, message string) *problem { return &problem{code, message, status} }

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil || host.abi_version != 1 {
		return 1
	}
	C.set_host(host)
	plugin.abi_version = 1
	plugin.call = C.plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, length C.size_t, response *C.cliproxy_buffer) (code C.int) {
	if response == nil {
		return 1
	}
	response.ptr, response.len = nil, 0
	defer func() {
		if recover() != nil {
			writeABI(response, nil, fail(500, "rewind_plugin_error", "Rewind plugin failed"))
			code = 1
		}
	}()
	if method == nil || uint64(length) > 64<<20 || (length > 0 && request == nil) {
		writeABI(response, nil, fail(400, "invalid_request", "Invalid plugin request"))
		return 1
	}
	raw := C.GoBytes(unsafe.Pointer(request), C.int(length))
	result, err := dispatch(C.GoString(method), raw)
	writeABI(response, result, err)
	if err != nil {
		return 1
	}
	return 0
}

func writeABI(out *C.cliproxy_buffer, result any, err *problem) {
	env := envelope{OK: err == nil, Error: err}
	if err == nil {
		env.Result, _ = json.Marshal(result)
	}
	raw, _ := json.Marshal(env)
	out.ptr, out.len = C.CBytes(raw), C.size_t(len(raw))
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) { C.free(ptr) }

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() { quiesce() }

func callHost(method string, value, result any) *problem {
	raw, err := json.Marshal(value)
	if err != nil {
		return fail(500, "rewind_plugin_error", "Invalid host callback")
	}
	m, data := C.CString(method), C.CBytes(raw)
	defer C.free(unsafe.Pointer(m))
	defer C.free(data)
	var out C.cliproxy_buffer
	code := C.host_call(m, (*C.uint8_t)(data), C.size_t(len(raw)), &out)
	if out.ptr == nil {
		return fail(502, "rewind_transport", "Rewind request canceled or transport unavailable")
	}
	defer C.host_free(out.ptr, out.len)
	if uint64(out.len) > 64<<20 {
		return fail(502, "rewind_transport", "Rewind response is too large")
	}
	var env envelope
	if json.Unmarshal(C.GoBytes(out.ptr, C.int(out.len)), &env) != nil || code != 0 || !env.OK {
		return fail(502, "rewind_transport", "Rewind request canceled or transport unavailable")
	}
	if result != nil && json.Unmarshal(env.Result, result) != nil {
		return fail(502, "rewind_transport", "Invalid host response")
	}
	return nil
}
