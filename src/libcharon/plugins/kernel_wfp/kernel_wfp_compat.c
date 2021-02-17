/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <library.h>

/**
 * Load a function symbol from a loaded dll
 */
static inline void *load_function(char *dll, char *name)
{
	HANDLE handle;
	void *sym = NULL;

	handle = GetModuleHandle(dll);
	if (!handle)
	{
		return NULL;
	}
	sym = GetProcAddress(handle, name);
	return sym;
}

/**
 * Macro that defines a stub for a function that calls the same DLL function
 *
 * @param dll		DLL to find function in
 * @param ret		return type of function
 * @param name		function name
 * @param size		size of all arguments on stack
 * @param ...		arguments of function
 */
#define STUB(dll, ret, name, size, ...) \
ret WINAPI name(__VA_ARGS__) \
{ \
	static void (*fun)() = NULL; \
	if (!fun) \
	{ \
		fun = load_function(#dll, #name); \
	} \
	if (fun) \
	{ \
		__builtin_return(__builtin_apply(fun, __builtin_apply_args(), size)); \
	} \
	return ERROR_NOT_SUPPORTED; \
}

STUB(fwpuclnt, DWORD, IPsecSaContextCreate1, 40,
	HANDLE engineHandle, const void *outboundTraffic,
	const void *virtualIfTunnelInfo, UINT64 *inboundFilterId, UINT64 *id)

STUB(fwpuclnt, DWORD, IPsecSaContextSetSpi0, 32,
	HANDLE engineHandle, UINT64 id, const void *getSpi, UINT32 inboundSpi)

STUB(fwpuclnt, DWORD, IPsecSaContextGetById1, 24,
	HANDLE engineHandle, UINT64 id, void **saContext)

STUB(fwpuclnt, DWORD, IPsecSaContextUpdate0, 24,
	HANDLE engineHandle, UINT32 flags, const void *newValues)

STUB(fwpuclnt, DWORD, IPsecSaContextEnum1, 40,
	HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
	void ***entries, UINT32 *numEntriesReturned)

STUB(fwpuclnt, DWORD, FwpmNetEventSubscribe0, 40,
	HANDLE engineHandle, const void *subscription, void(*callback)(),
	void *context, HANDLE *eventsHandle)

STUB(fwpuclnt, DWORD, FwpmNetEventUnsubscribe0, 16,
	HANDLE engineHandle, HANDLE eventsHandle)
