use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::null_mut,
};

use wdk::nt_success;
use wdk_alloc::WdkAllocator;
use wdk_sys::{
    ntddk::{IoAllocateIrp, IoFreeIrp, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject},
    BOOLEAN, IO_NO_INCREMENT, KEVENT, NTSTATUS, PDEVICE_OBJECT, PIRP, PKEVENT, PVOID,
    STATUS_MORE_PROCESSING_REQUIRED, STATUS_PENDING, STATUS_SUCCESS,
    _EVENT_TYPE::NotificationEvent,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
};

use crate::misc::IoSetCompletionRoutine;
use crate::DEALLOC_LAYOUT;

#[derive(Debug)]
pub enum BlockingIrpErr {
    FailedToCreateIrp,
    FailedToCreateContext,
    #[allow(dead_code)]
    FailedToWaitForEvent(NTSTATUS),
    #[allow(dead_code)]
    IRPCallFailed(NTSTATUS),
}

/// A function that takes the irp.IoStatus.Information value, and stores its
/// meaning in the CompletionRoutineContext.data field.
///
/// If set to none, no processing is done on irp.IoStatus.Information.
type ResultAssigner<T> = Option<fn(&mut CompletionRoutineContext<T>, u64)>;

///
/// `call_irp_blocking` handles all behavior around calling a **WSK** IRP call,
/// and blocking until it completes.
///
/// If the IRP passed via `irp_call` is never completed, this function will
/// never returned.
///
/// **ONLY for use with WSK IRP calls.**
///
/// # Generic Parameters
///
/// * `T` - The data type to return, and to hold in the context passed to the
///   call completion routine.
/// * `F` - The caller of the WSK IRP function. This closure wraps any WSK call
///   (ex: WskSocket, WskBind, etc), passing in any necessary parameters. The
///   closure is given the irp to call, and the context, if it chooses to use it
///   to fetch/store any data.
///
/// # Arguments:
///
/// * `irp_call` - The WSK IRP function caller (see Generic Parameter F's
///   definition).
/// * `result_assigner` - An optional function, called upon the irp's success,
///   responsible for assigning the result of `call_irp_blocking` via being
///   passed a reference to the CompletionRoutineContext, and
///   irp.IoStatus.Information's value.
///
/// # Return Value:
///
/// * `Ok(T)` - The result data, assigned by `result_assigner`, upon success.
/// * `Err(BlockingIrpErr)` - The reason the call failed.
///
pub fn call_irp_blocking<T: Clone, F>(
    irp_call: F,
    result_assigner: ResultAssigner<T>,
) -> Result<T, BlockingIrpErr>
where
    F: FnOnce(PIRP, &mut CompletionRoutineContext<T>) -> NTSTATUS,
{
    // SAFETY: This is safe because:
    //         Result is compared to nullptr.
    let irp = unsafe { IoAllocateIrp(1, false as BOOLEAN) };
    if irp.is_null() {
        return Err(BlockingIrpErr::FailedToCreateIrp);
    }

    let context_layout = Layout::new::<CompletionRoutineContext<T>>();
    // SAFETY: This is safe because:
    //         Result is compared to nullptr.
    let context_ptr =
        unsafe { WdkAllocator.alloc_zeroed(context_layout) as *mut CompletionRoutineContext<T> };
    if context_ptr.is_null() {
        return Err(BlockingIrpErr::FailedToCreateContext);
    }
    // SAFETY: This is safe because:
    //         1. `context_ptr` is a valid pointer to a valid
    //            CompletionRoutineContext.
    let context = unsafe { &mut *context_ptr };

    context.result_assigner = result_assigner;

    // SAFETY: This is safe because:
    //         1. `Event` is an obviously valid event.
    unsafe {
        KeInitializeEvent(&mut context.event, NotificationEvent, false as BOOLEAN);
    }

    // SAFETY: This is safe because:
    //         1. `irp` is a valid pointer to a valid IRP.
    //         2. `CompletionRoutine` is either None, or contains a
    //            guaranteed safe function.
    //         3. `Context` is allowed to be null.
    unsafe {
        IoSetCompletionRoutine(
            irp,
            Some(irp_handler_completion_routine::<T>),
            context_ptr as *mut _,
            true as BOOLEAN,
            true as BOOLEAN,
            true as BOOLEAN,
        );
    }

    let status = irp_call(irp, context);

    if status == STATUS_PENDING {
        // SAFETY: This is safe because:
        //         1. `Object` is an obviously valid object, which has been
        //            initialized by KeInitializeEvent.
        //         2. `Timeout` is allowed to be null for limitless waits.
        let status = unsafe {
            KeWaitForSingleObject(
                &mut context.event as PKEVENT as *mut _,
                Executive,
                KernelMode as i8,
                false as BOOLEAN,
                null_mut(),
            )
        };

        if status != STATUS_SUCCESS {
            // SAFETY: This is safe because:
            //         `context_ptr` is a valid pointer to a WdkAllocator
            //         allocated object.
            unsafe {
                WdkAllocator.dealloc(context_ptr as *mut _, DEALLOC_LAYOUT);
            }

            return Err(BlockingIrpErr::FailedToWaitForEvent(status));
        }
    }

    if !nt_success(status) || !nt_success(context.status) {
        let context_status = context.status;
        // SAFETY: This is safe because:
        //         `context_ptr` is a valid pointer to a WdkAllocator
        //         allocated object.
        unsafe {
            WdkAllocator.dealloc(context_ptr as *mut _, DEALLOC_LAYOUT);
        }

        if !nt_success(status) {
            return Err(BlockingIrpErr::IRPCallFailed(status));
        } else {
            return Err(BlockingIrpErr::IRPCallFailed(context_status));
        }
    }

    // not sure if moving the value is unsafe, given the container (context) is
    // deallocted before returning, so we clone instead.
    let result = context.data.clone();

    // SAFETY: This is safe because:
    //         1. `context_ptr` is a valid pointer to a WdkAllocator allocated
    //            object.
    //         2. `context` and `context_ptr` are not used after deallocation.
    unsafe {
        WdkAllocator.dealloc(context_ptr as *mut _, DEALLOC_LAYOUT);
    }

    Ok(result)
}

///
/// `irp_handler_completion_routine` is the completion routine for
/// `irp_helper::call_irp_blocking`. Its behavior is tightly coupled with the
/// function to behave safely.
///
/// Specifically, this function is responsible to fill the context's status
/// field, call the context's result_assigner to fill the data field, set the
/// context's kevent, and then free the IRP, before returning.
///
/// # Arguments:
///
/// * `_device_object` - An possibly null PDEVICE_OBJECT, unused.
/// * `irp_ptr` - A pointer to the IRP being completed. This must not be null.
/// * `context` - A pointer to the call's context, stored in a
///   CompletionRoutineContext<T>. This must not be null.
///
/// # Return Value:
///
/// * `NTSTATUS` - The status of the call. This should always be
///   STATUS_MORE_PROCESSING_REQUIRED, as is required for all WSK IRPs.
///
unsafe extern "C" fn irp_handler_completion_routine<T: Clone>(
    _device_object: PDEVICE_OBJECT,
    irp_ptr: PIRP,
    context: PVOID,
) -> NTSTATUS {
    if context.is_null() || irp_ptr.is_null() {
        // invalid/impossible call
        return STATUS_MORE_PROCESSING_REQUIRED;
    }

    // SAFETY: This is safe because:
    //         `context` is a verified non null pointer.
    let context = unsafe { &mut *(context as *mut CompletionRoutineContext<T>) };

    // SAFETY: This is safe because:
    //         `irp_ptr` is a verified non null pointer.
    let irp = unsafe { &*irp_ptr };

    // SAFETY: This is safe because:
    //         `Status` is apart of a union, so at worst this is an invalid
    //         NTSTATUS value. It is not being used as a pointer.
    let status = unsafe { irp.IoStatus.__bindgen_anon_1.Status };

    context.status = status;
    if let Some(result_assigner) = context.result_assigner {
        if nt_success(status) {
            result_assigner(context, irp.IoStatus.Information);
        }
    }

    // SAFETY: This is safe because:
    //         `Event` is a valid pointer to an initialized KEVENT.
    let _ = unsafe {
        KeSetEvent(
            &mut context.event as PKEVENT,
            IO_NO_INCREMENT as i32,
            false as BOOLEAN,
        )
    };

    // SAFETY: This is safe because:
    //         1. `irp_ptr` has been verified as a non null ptr.
    //         2. The irp is not freed anywhere else.
    unsafe {
        IoFreeIrp(irp_ptr);
    }

    STATUS_MORE_PROCESSING_REQUIRED
}

///
/// Context for a completion routine.
///
/// Stores the status and associated KEvent for the IRP.
///
/// Also stores a generic object T, and the function responsible for
/// assigning/modifying it based on the irp.IoStatus.Information value.
///
pub struct CompletionRoutineContext<T: Clone> {
    status: NTSTATUS,
    event: KEVENT,

    result_assigner: ResultAssigner<T>,
    pub data: T,
}
