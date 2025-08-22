//!
//! This file contains miscellaneous function definitions that may be
//! helpful.
//!
//! Some examples are inline functions or macros defined in WDK headers
//! that don't get bindings because they are inline.
//!
#![allow(non_snake_case)]

use core::ptr::null_mut;

use wdk_sys::{
    ntddk::MmMapLockedPagesSpecifyCache, BOOLEAN, MDL_MAPPED_TO_SYSTEM_VA,
    MDL_SOURCE_IS_NONPAGED_POOL, PIO_COMPLETION_ROUTINE, PIO_STACK_LOCATION, PIRP, PMDL, PVOID,
    SL_INVOKE_ON_CANCEL, SL_INVOKE_ON_ERROR, SL_INVOKE_ON_SUCCESS, ULONG,
    _MEMORY_CACHING_TYPE::MmCached, _MODE::KernelMode,
};

pub unsafe fn IoSetCompletionRoutine(
    Irp: PIRP,
    CompletionRoutine: PIO_COMPLETION_ROUTINE,
    Context: PVOID,
    InvokeOnSuccess: BOOLEAN,
    InvokeOnError: BOOLEAN,
    InvokeOnCancel: BOOLEAN,
) {
    debug_assert!(
        if InvokeOnSuccess > 0 || InvokeOnError > 0 || InvokeOnCancel > 0 {
            CompletionRoutine.is_some()
        } else {
            true
        }
    );

    let irpSp = IoGetNextIrpStackLocation(Irp);
    (*irpSp).CompletionRoutine = CompletionRoutine;
    (*irpSp).Context = Context;
    (*irpSp).Control = 0;

    if InvokeOnSuccess > 0 {
        (*irpSp).Control = SL_INVOKE_ON_SUCCESS as u8;
    }

    if InvokeOnError > 0 {
        (*irpSp).Control |= SL_INVOKE_ON_ERROR as u8;
    }

    if InvokeOnCancel > 0 {
        (*irpSp).Control |= SL_INVOKE_ON_CANCEL as u8;
    }
}

pub unsafe fn IoGetNextIrpStackLocation(Irp: PIRP) -> PIO_STACK_LOCATION {
    debug_assert!((*Irp).CurrentLocation > 0);

    return (*Irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
        .sub(1);
}

pub unsafe fn MmGetSystemAddressForMdlSafe(Mdl: PMDL, Priority: ULONG) -> PVOID {
    if ((*Mdl).MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) as i16) != 0 {
        return (*Mdl).MappedSystemVa;
    } else {
        return MmMapLockedPagesSpecifyCache(
            Mdl,
            KernelMode as i8,
            MmCached,
            null_mut(),
            false as ULONG,
            Priority,
        );
    }
}
