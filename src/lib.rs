#![no_std]

use core::{
    alloc::{GlobalAlloc, Layout},
    fmt::Debug,
    ptr::null_mut,
    slice,
    sync::atomic::{AtomicPtr, Ordering},
};

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use wdk::nt_success;
use wdk_alloc::WdkAllocator;
use wdk_mutex::{errors::DriverMutexError, kmutex::KMutex};
use wdk_sys::{
    in_addr__bindgen_ty_1, in_addr__bindgen_ty_1__bindgen_ty_1,
    network::{WskCaptureProviderNPI, WskDeregister, WskRegister, WskReleaseProviderNPI},
    ntddk::{ExQueueWorkItem, IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool},
    AF_INET, BOOLEAN, IN_ADDR,
    IPPROTO::IPPROTO_UDP,
    NPI_WSK_INTERFACE_ID, NTSTATUS, PSOCKADDR, PSOCKADDR_IN, PVOID, PWORK_QUEUE_ITEM, PWSK_BUF,
    PWSK_DATAGRAM_INDICATION, PWSK_EVENT_CALLBACK_CONTROL, PWSK_PROVIDER_BASIC_DISPATCH,
    PWSK_PROVIDER_DATAGRAM_DISPATCH, PWSK_SOCKET, SOCKADDR_IN, SOCK_DGRAM, SOL_SOCKET,
    SO_WSK_EVENT_CALLBACK, STATUS_SUCCESS, WORK_QUEUE_ITEM, WSK_BUF, WSK_CLIENT_DATAGRAM_DISPATCH,
    WSK_CLIENT_DISPATCH, WSK_CLIENT_NPI,
    WSK_CONTROL_SOCKET_TYPE::WskSetOption,
    WSK_EVENT_CALLBACK_CONTROL, WSK_EVENT_RECEIVE_FROM, WSK_FLAG_DATAGRAM_SOCKET,
    WSK_INFINITE_WAIT, WSK_PROVIDER_NPI, WSK_REGISTRATION, WSK_SOCKET,
    _MM_PAGE_PRIORITY::NormalPagePriority,
    _WORK_QUEUE_TYPE::DelayedWorkQueue,
};

use irp_helper::{call_irp_blocking, BlockingIrpErr};
use misc::MmGetSystemAddressForMdlSafe;

mod irp_helper;
mod misc;

/// A global variable for the WSK_REGISTRATION, which cannot be deallocated
/// until all sockets are closed and we deregister.
///
/// This is lazy loaded, and set during the first `UdpSocket::new` call.
static WSK_REGISTRATION: AtomicPtr<KMutex<*mut WSK_REGISTRATION>> = AtomicPtr::new(null_mut());

const WSK_APP_DISPATCH: WSK_CLIENT_DISPATCH = WSK_CLIENT_DISPATCH {
    Version: 0x0100,
    Reserved: 0,
    WskClientEvent: None,
};

const WSK_CLIENT_DATAGRAM_DISPATCH: WSK_CLIENT_DATAGRAM_DISPATCH = WSK_CLIENT_DATAGRAM_DISPATCH {
    WskReceiveFromEvent: Some(receive_from_event_handler_unsafe),
};

/// Used because the WdkAllocator does not use layouts in deallocation, but the
/// trait requires them.
/// As an aside, it's also worth noting that the allocator doesn't use alignment
/// either (because ExAllocatePool2 doesn't use it either).
static DEALLOC_LAYOUT: Layout = Layout::new::<u8>();

/// An arbitrary value for the maximum number of open sockets at once. Required
/// by the current concurrency safety measures.
const MAX_OPEN_SOCKETS: usize = 5;
/// A global array of open sockets, used for thread safe access to sockets.
/// Be sure to compare the value against `RESERVED` prior to using as a KMutex.
///
/// KMutexes in this array MUST have been placed in a Box before having their
/// pointer set here.
static OPEN_SOCKETS: [AtomicPtr<KMutex<UdpSocket>>; MAX_OPEN_SOCKETS] = [
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
    AtomicPtr::new(null_mut()),
];
/// A value representing a reserved OPEN_SOCKET entry, without a valid socket.
const RESERVED: *mut () = 1 as *mut ();
/// The ordering to use when loading/storing in the OPEN_SOCKETS array.
const SOCKET_ORDERING: Ordering = Ordering::SeqCst;

pub struct GlobalSockets {}

impl GlobalSockets {
    ///
    /// Finds the next available slot in the OPEN_SOCKETS array, and marks it as
    /// in use, returning the identifier. Returns None if no open slots were
    /// found.
    ///
    fn reserve_slot() -> Option<SocketIdentifier> {
        for socket_idx in 0..MAX_OPEN_SOCKETS {
            let ptr = OPEN_SOCKETS[socket_idx].load(SOCKET_ORDERING);
            if ptr.is_null() {
                OPEN_SOCKETS[socket_idx].store(RESERVED as *mut _, SOCKET_ORDERING);
                return Some(SocketIdentifier::from_socket_idx(socket_idx));
            }
        }
        None
    }

    ///
    /// Inserts a `socket` to the `id` slot in the OPEN_SOCKETS array, if the
    /// previous value in the array was RESERVED.
    ///
    /// Does nothing if identifier is invalid (too large), or if the pointer in
    /// the slot was not RESERVED.
    ///
    /// TODO: Should I add an error return in case it fails?
    ///
    fn insert_socket(id: SocketIdentifier, socket: *mut KMutex<UdpSocket>) {
        if id.socket_idx >= MAX_OPEN_SOCKETS {
            return;
        }

        if OPEN_SOCKETS[id.socket_idx].load(SOCKET_ORDERING) != RESERVED as *mut _ {
            return;
        }

        OPEN_SOCKETS[id.socket_idx].store(socket, SOCKET_ORDERING);
    }

    ///
    /// Attempts to locate a socket by its identifier.
    ///
    /// Returns a pointer to the socket's mutex. Returns None if it cannot be
    /// found. If Some is returned, the pointer is guaranteed to be non null.
    ///
    pub fn get_socket(id: SocketIdentifier) -> Option<*mut KMutex<UdpSocket>> {
        if id.socket_idx >= MAX_OPEN_SOCKETS {
            return None;
        }

        let socket = OPEN_SOCKETS[id.socket_idx].load(SOCKET_ORDERING);
        if socket.is_null() || socket == RESERVED as *mut _ {
            return None;
        }

        Some(socket)
    }

    ///
    /// Attempts to close a socket by its identifier.
    ///
    /// TODO: Should I add a status return in case the socket wasn't found or
    /// couldn't be locked?
    ///
    pub fn close_socket(identifier: SocketIdentifier) {
        if identifier.socket_idx >= MAX_OPEN_SOCKETS {
            return;
        }

        if let Some(mutex_ptr) = GlobalSockets::get_socket(identifier) {
            if mutex_ptr.is_null() || mutex_ptr == RESERVED as *mut _ {
                return;
            }

            OPEN_SOCKETS[identifier.socket_idx].store(null_mut(), SOCKET_ORDERING);
            // SAFETY: This is safe because:
            //         `mutex_ptr` is a confirmed valid KMutex pointer.
            let mutex = unsafe { &*mutex_ptr };
            let socket = mutex.lock().unwrap();
            socket.close();
            // SAFETY: This is safe because:
            //         `mutex_ptr` is a confirmed valid KMutex pointer in a Box.
            let _ = unsafe { Box::from_raw(mutex_ptr) };
        }
    }

    ///
    /// Attempts to close all open sockets. Typically used when the driver is
    /// exiting. Deregisters and clears WSK_REGISTRATION.
    ///
    pub fn close_all_sockets() {
        for idx in 0..MAX_OPEN_SOCKETS {
            GlobalSockets::close_socket(SocketIdentifier::from_socket_idx(idx));
        }

        un_init();
    }
}

/// A structure representing an IPV4 address.
#[derive(Clone, Copy)]
pub struct IP(pub [u8; 4]);

impl Debug for IP {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3],)
    }
}

///
/// Holds the key to access sockets via GlobalSockets::get_socket. This identifier
/// is unique to each Socket, easily comparable, and easily copyable.
///
/// ASIDE:
///
/// This data structure can likely be removed if the method of safe concurrency
/// is changed (if `OPEN_PORTS`) is removed.
///
/// Technically GlobalSockets and SocketIdentifier could be represented as traits
/// with implementations, however given their limited and coupled uses, that
/// seems unnecessarily complex.
///
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketIdentifier {
    /// The underlying data used to identify and reference a socket. This is used
    /// for this specific GlobalSockets implementation.
    socket_idx: usize,
}

impl SocketIdentifier {
    ///
    /// Creates a new SocketIdentifier from the underlying identifier data.
    ///
    fn from_socket_idx(socket_idx: usize) -> Self {
        Self {
            socket_idx: socket_idx,
        }
    }
}

#[derive(Debug)]
pub enum InitErr {
    FailedToAllocRegistration,
    #[allow(dead_code)]
    FailedToCreateMutex(DriverMutexError),
    #[allow(dead_code)]
    FailedToRegister(NTSTATUS),
}

///
/// `try_init` checks if WSK_REGISTRATION has been intialized, and initializes
/// it if it hasn't been yet.
///
/// # Return value:
///
/// * `Ok()` - Upon success.
/// * `Err(InitErr)` - Otherwise.
///
fn try_init() -> Result<(), InitErr> {
    if WSK_REGISTRATION.load(SOCKET_ORDERING) != null_mut() {
        return Ok(());
    }

    let registration_layout = Layout::new::<WSK_REGISTRATION>();

    // SAFETY: This is safe because:
    //         The result pointer is compared against null.
    let registration =
        unsafe { WdkAllocator.alloc_zeroed(registration_layout) as *mut WSK_REGISTRATION };
    if registration.is_null() {
        return Err(InitErr::FailedToAllocRegistration);
    }

    let mutex = KMutex::new(registration).map_err(|e| InitErr::FailedToCreateMutex(e))?;
    let mutex_boxed = Box::new(mutex);
    let mutex_ptr = Box::into_raw(mutex_boxed);
    WSK_REGISTRATION.store(mutex_ptr, SOCKET_ORDERING);

    // SAFETY: This is safe because:
    //         The mutex and mutex pointer are guaranteed to be valid.
    let registration_ptr_grd = unsafe { (*mutex_ptr).lock().unwrap() };

    let mut wsk_client_npi = WSK_CLIENT_NPI {
        ClientContext: null_mut(),
        Dispatch: &WSK_APP_DISPATCH,
    };

    // SAFETY: This is safe because:
    //         *registration_ptr_grd is guaranteed to be a valid
    //         WSK_REGISTRATION pointer.
    let status = unsafe { WskRegister(&mut wsk_client_npi, *registration_ptr_grd) };
    if !nt_success(status) {
        return Err(InitErr::FailedToRegister(status));
    }

    Ok(())
}

///
/// `un_init` uninitializes WSK_REGISTRATION. Does nothing if it wasn't already
/// initialized.
///
/// Blocks until all captured provider NPI instances are released, all calls to
/// functions pointed to by WSK_PROVIDER_DISPATCH members have returned, and all
/// sockets are closed.
///
fn un_init() {
    let registration = WSK_REGISTRATION.load(SOCKET_ORDERING);
    if registration.is_null() {
        return;
    }
    WSK_REGISTRATION.store(null_mut(), SOCKET_ORDERING);

    // SAFETY: This is safe because:
    //         `registration` is a verified valid KMutex<PWSK_REGISTRATION>
    //         pointer.
    let registration = unsafe { (*registration).lock().unwrap() };
    if registration.is_null() {
        return;
    }

    // SAFETY: This is safe because:
    //         `registration` is a verified valid PWSK_REGISTRATION.
    unsafe {
        WskDeregister(*registration);
    }
}

#[derive(Debug)]
pub enum NewSocketErr {
    #[allow(dead_code)]
    FailedInit(InitErr),
    FailedToReserveSlot,
    #[allow(dead_code)]
    FailedToMakeSocket(SocketCreationErr),
    #[allow(dead_code)]
    FailedToBindSocket(SocketBindErr),
    #[allow(dead_code)]
    FailedToGetSocketAddress(GetSocketAddressErr),
    #[allow(dead_code)]
    FailedToEnableCallback(SocketEnableCallbackErr),

    FailedToAddToGlobalSockets,
}

#[derive(Debug)]
pub enum SocketCreationErr {
    InvalidRegistration,
    #[allow(dead_code)]
    FailedToCaptureProviderNPI(NTSTATUS),
    ProviderNPIDispatchWasNull,
    ProviderNPIClientWasNull,
    WskSocketWasNull,
    FailedToMakeContext,
    #[allow(dead_code)]
    IrpErr(BlockingIrpErr),
    InvalidSocket,
}

#[derive(Debug)]
pub enum SocketBindErr {
    InvalidSocket,
    DatagramDispatchWasNull,
    WskBindWasNull,
    #[allow(dead_code)]
    FailedToBindSocket(NTSTATUS),
    #[allow(dead_code)]
    IrpErr(BlockingIrpErr),
}

#[derive(Debug)]
pub enum GetSocketAddressErr {
    InvalidSocket,
    DatagramDispatchWasNull,
    WskGetLocalAddressWasNull,
    #[allow(dead_code)]
    FailedToGetSocketIp(NTSTATUS),
    #[allow(dead_code)]
    IrpErr(BlockingIrpErr),
}

#[derive(Debug)]
pub enum SocketEnableCallbackErr {
    InvalidSocket,
    BasicDispatchWasNull,
    WskControlSocketWasNull,
    FailedToMakeEventCallbackControl,
    #[allow(dead_code)]
    FailedToControlSocket(NTSTATUS),
}

#[derive(Debug)]
pub enum SocketWriteErr {
    InvalidSocket,
    DatagramDispatchWasNull,
    WskSendToWasNull,
    FailedToAllocateMdl,
    #[allow(dead_code)]
    FailedToSendToSocket(NTSTATUS),
    #[allow(dead_code)]
    IrpErr(BlockingIrpErr),
}

///
/// `AsyncReadCallback` defines a completion routine called when an asynchronous
/// read finishes on the udp socket. It passes the datagram's data to the
/// callback, as well as the sender's ip address and port.
///
/// # Arguments
///
/// * `identifier` - The socket's identifier, telling the callback which socket
///   the read came from.
/// * `data` - All data from the datagram. This is a Vec to guarantee it is
///   comprised of non paged memory.
/// * `ip` - The IP that sent the datagram.
/// * `port` - The Port that sent the datagram.
///
type AsyncReadCallback = fn(identifier: SocketIdentifier, data: &Vec<u8>, ip: IP, port: u16);

///
/// All the data representing a UdpSocket.
/// 
pub struct UdpSocket {
    /// The Socket's current IPV4 address.
    ip: IP,
    /// The Socket's current port number.
    port: u16,

    /// The underlying socket pointer, used for cleanup, socket writes, and
    /// everything else regarding the socket.
    socket_ptr: PWSK_SOCKET,

    /// An identifier used to retrieve the port from the GlobalSockets manager.
    /// This value should always be Some(SocketIdentifier), outside of
    /// construction.
    identifier: Option<SocketIdentifier>,
}

impl UdpSocket {
    ///
    /// `new` constructs a new socket, binds it to the ip and port, and then
    /// sets the struct's ip and port fields to the values read back. Just
    /// because the function succeeds does not mean the port and ip are still
    /// accurate. After this function returns success, the caller should read
    /// the IP and Port back off of the newly created port.
    ///
    /// # Arguments:
    ///
    /// * `ip` - The 4 byte IPV4, in the form of [127, 0, 0, 1].
    /// * `port` - The 16 bit port number in little endian form.
    /// * `read_callback` - A function to be called at IRQL_PASSIVE_LEVEL when a
    ///   datagram is received on the socket.
    ///
    /// # Return value:
    ///
    /// * `Ok(SocketIdentifier)` - The socket identifier, upon success.
    /// * `Err(InitErr)` - Otherwise.
    ///
    pub fn new(
        ip: IP,
        port: u16,
        read_callback: AsyncReadCallback,
    ) -> Result<SocketIdentifier, NewSocketErr> {
        try_init().map_err(|e| NewSocketErr::FailedInit(e))?;

        let identifier = GlobalSockets::reserve_slot().ok_or(NewSocketErr::FailedToReserveSlot)?;

        let socket_ptr = Self::make_socket(identifier, read_callback)
            .map_err(|e| NewSocketErr::FailedToMakeSocket(e))?;

        if let Err(e) = Self::bind_socket(socket_ptr, ip, port) {
            Self::close_socket(socket_ptr);
            return Err(NewSocketErr::FailedToBindSocket(e));
        }

        let (ip, port) = match Self::get_socket_address(socket_ptr) {
            Ok(address) => address,
            Err(e) => {
                Self::close_socket(socket_ptr);
                return Err(NewSocketErr::FailedToGetSocketAddress(e));
            }
        };

        if let Err(e) = Self::enable_receive_callback(socket_ptr) {
            Self::close_socket(socket_ptr);
            return Err(NewSocketErr::FailedToEnableCallback(e));
        }

        let socket = UdpSocket {
            ip,
            port,
            socket_ptr,
            identifier: None,
        };

        let mutex = Box::new(KMutex::new(socket).unwrap());
        let mutex_ptr = Box::into_raw(mutex);

        GlobalSockets::insert_socket(identifier, mutex_ptr);
        let mutex_ptr = match GlobalSockets::get_socket(identifier) {
            Some(mutex_ptr) => mutex_ptr,
            None => {
                // undefined behavior, likely mem leak on socket struct.
                Self::close_socket(socket_ptr);
                return Err(NewSocketErr::FailedToAddToGlobalSockets);
            },
        };

        // SAFETY: This is safe because:
        //         `mutex_ptr` is a confirmed valid KMutex pointer.
        let mut socket = unsafe { (*mutex_ptr).lock().unwrap() };
        socket.identifier = Some(identifier);

        Ok(identifier)
    }

    ///
    /// `get_address` returns the port's IP address and port.
    ///
    /// # Return value:
    ///
    /// * `(ip: IP, port: u16)` - The ip and port.
    ///
    pub fn get_address(&self) -> (IP, u16) {
        (self.ip, self.port)
    }

    ///
    /// `write_data` takes a socket, and writes some data to it.
    ///
    /// # Arguments:
    ///
    /// * `data` - A buffer of data in NON_PAGEABLE memory, to write from the
    ///   socket to the receiver at the ip and port.
    /// * `ip` - The IP to write the data to.
    /// * `port` - The port to write the data to.
    ///
    /// Note: `data` must be a Vec<u8>, as IoAllocateMdl requires non paged
    /// memory.
    ///
    /// # Return value:
    ///
    /// * `Ok(())` - Upon success.
    /// * `Err(SocketWriteErr)` - Otherwise.
    ///
    pub fn write_blocking(&self, data: &Vec<u8>, ip: IP, port: u16) -> Result<(), SocketWriteErr> {
        let socket_ptr = self.socket_ptr;
        if socket_ptr.is_null() {
            return Err(SocketWriteErr::InvalidSocket);
        }

        // SAFETY: This is safe because:
        //         `socket` has been verified as a valid pointer.
        let socket = unsafe { &*socket_ptr };

        let dispatch = socket.Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH;
        if dispatch.is_null() {
            return Err(SocketWriteErr::DatagramDispatchWasNull);
        }

        // SAFETY: This is safe because:
        //         `dispatch` has been verified as a valid pointer.
        let dispatch = unsafe { &*dispatch };
        if dispatch.WskSendTo.is_none() {
            return Err(SocketWriteErr::WskSendToWasNull);
        }

        // SAFETY: This is safe because:
        //         1. `VirtualAddress` is a pointer to a WdkAllocator allocated
        //            buffer, with length `Length`.
        //         2. `irp` is allowed to be null.
        //         3. The result is compared to null.
        let mdl_ptr = unsafe {
            IoAllocateMdl(
                data.as_ptr() as PVOID,
                data.len() as u32,
                false as BOOLEAN,
                false as BOOLEAN,
                null_mut(),
            )
        };
        if mdl_ptr.is_null() {
            return Err(SocketWriteErr::FailedToAllocateMdl);
        }

        // SAFETY: This is safe because:
        //         `mdl_ptr` is a valid PMDL.
        unsafe {
            MmBuildMdlForNonPagedPool(mdl_ptr);
        }

        let mut buffer = WSK_BUF {
            Mdl: mdl_ptr,
            Offset: 0,
            Length: data.len() as u64,
        };

        let mut address = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: port.swap_bytes(),
            sin_addr: in_addr_from_ip(ip),
            sin_zero: [0; 8],
        };

        let _ = call_irp_blocking::<(), _>(
            |irp, _ctx| {
                // SAFETY: This is safe because:
                //         1. `socket_ptr` is a valid PWSK_SOCKET.
                //         2. `Buffer` is a valid PWSK_BUF, allocated and locked
                //            in memory until after the IRP completes.
                //         3. `Address` is a valid PSOCKADDR.
                //         4. `ControlInfo` can be null, since
                //            `ControlInfoLength` is 0.
                //         5. `irp` is a valid PIRP, properly freed after use.
                unsafe {
                    dispatch.WskSendTo.unwrap()(
                        socket_ptr,
                        &mut buffer as PWSK_BUF,
                        0,
                        &mut address as PSOCKADDR_IN as PSOCKADDR,
                        0,
                        null_mut(),
                        irp,
                    )
                }
            },
            None, // result is already stored in context.data
        )
        .map_err(|e| SocketWriteErr::IrpErr(e))?;

        // SAFETY: This is safe because:
        //         `mdl_ptr` is a valid PMDL.
        unsafe {
            IoFreeMdl(mdl_ptr);
        }

        Ok(())
    }

    ///
    /// `close` cleans up all stored data held by the Socket, freeing any in use
    /// memory. The caller is required to immediately dispose of the socket
    /// after calling this function. This function is internal, and only for use
    /// by `GlobalSockets::close_socket`.
    ///
    fn close(&self) {
        Self::close_socket(self.socket_ptr);
    }
}

impl UdpSocket {
    ///
    /// `make_socket` captures the WSK Provider NPI, calls the WskSocket
    /// function to create a datagram socket, and waits for it to complete,
    /// cleaning up all used memory (and the captured NPI), and returning either
    /// the socket, or an error.
    ///
    /// # Arguments:
    ///
    /// * `identifier` - A socket identifier, used as context for the read
    ///   completion routine.
    /// * `read_callback` - A function to be called when the socket has received
    ///   a datagram.
    ///
    /// # Return value:
    ///
    /// * `Ok(*mut WSK_SOCKET)` - The newly created socket.
    /// * `Err(SocketCreationErr)` - Otherwise.
    ///
    fn make_socket(
        identifier: SocketIdentifier,
        read_callback: AsyncReadCallback,
    ) -> Result<*mut WSK_SOCKET, SocketCreationErr> {
        let mutex_ptr = WSK_REGISTRATION.load(SOCKET_ORDERING);
        if mutex_ptr.is_null() {
            return Err(SocketCreationErr::InvalidRegistration);
        }

        // SAFETY: This is safe because:
        //         The mutex and mutex pointer are guaranteed to be valid.
        let registration_ptr_grd = unsafe { (*mutex_ptr).lock().unwrap() };

        let mut wsk_provider_npi = WSK_PROVIDER_NPI::default();

        // SAFETY: This is safe because:
        //         *registration_ptr_grd is guaranteed to be a valid
        //         WSK_REGISTRATION pointer.
        let status = unsafe {
            WskCaptureProviderNPI(
                *registration_ptr_grd,
                WSK_INFINITE_WAIT,
                &mut wsk_provider_npi,
            )
        };
        if !nt_success(status) {
            return Err(SocketCreationErr::FailedToCaptureProviderNPI(status));
        }

        if wsk_provider_npi.Client.is_null() {
            // SAFETY: This is safe because:
            //         1. `WskRegistration` is a valid PWSK_REGISTRATION.
            //         2. WskReleaseProviderNPI is only called once, matching
            //            the number of WskCaptureProviderNPI calls.
            unsafe {
                WskReleaseProviderNPI(*registration_ptr_grd);
            }
            return Err(SocketCreationErr::ProviderNPIClientWasNull);
        }

        let dispatch = wsk_provider_npi.Dispatch;
        if dispatch.is_null() {
            // SAFETY: This is safe because:
            //         1. `WskRegistration` is a valid PWSK_REGISTRATION.
            //         2. WskReleaseProviderNPI is only called once, matching
            //            the number of WskCaptureProviderNPI calls.
            unsafe {
                WskReleaseProviderNPI(*registration_ptr_grd);
            }
            return Err(SocketCreationErr::ProviderNPIDispatchWasNull);
        }

        // SAFETY: This is safe because:
        //         `dispatch` has been verified as a valid pointer.
        let dispatch = unsafe { &*dispatch };
        if dispatch.WskSocket.is_none() {
            // SAFETY: This is safe because:
            //         1. `WskRegistration` is a valid PWSK_REGISTRATION.
            //         2. WskReleaseProviderNPI is only called once, matching
            //            the number of WskCaptureProviderNPI calls.
            unsafe {
                WskReleaseProviderNPI(*registration_ptr_grd);
            }
            return Err(SocketCreationErr::WskSocketWasNull);
        }

        let context_layout = Layout::new::<WskSocketContext>();

        // SAFETY: This is safe because:
        //         The result is compared to nullptr.
        let context_ptr =
            unsafe { WdkAllocator.alloc_zeroed(context_layout) as *mut WskSocketContext };
        if context_ptr.is_null() {
            // SAFETY: This is safe because:
            //         1. `WskRegistration` is a valid PWSK_REGISTRATION.
            //         2. WskReleaseProviderNPI is only called once, matching
            //            the number of WskCaptureProviderNPI calls.
            unsafe {
                WskReleaseProviderNPI(*registration_ptr_grd);
            }
            return Err(SocketCreationErr::FailedToMakeContext);
        }

        // SAFETY: This is safe because:
        //         1. `context_ptr` is a valid WskSocketContext pointer.
        let context = unsafe { &mut *context_ptr };

        context.identifier = identifier;
        context.read_callback = read_callback;

        let status = call_irp_blocking::<PWSK_SOCKET, _>(
            |irp, _ctx| {
                // SAFETY: This is safe because:
                //         1. `Client` has been checked as being non null.
                //         2. `Context` is a valid SocketIdentifier pointer.
                //         3. `Dispatch` is a valid WSK_CLIENT_DATAGRAM_DISPATCH
                //            pointer.
                //         4. `OwningProcess`, `OwningThread`, and
                //            `SecurityDescriptor` are allowed to be null.
                //         5. `irp` is a valid PIRP, properly freed after use.
                unsafe {
                    dispatch.WskSocket.unwrap()(
                        wsk_provider_npi.Client,
                        AF_INET as u16,
                        SOCK_DGRAM as u16,
                        IPPROTO_UDP as u32,
                        WSK_FLAG_DATAGRAM_SOCKET,
                        context_ptr as *mut _,
                        &WSK_CLIENT_DATAGRAM_DISPATCH as *const WSK_CLIENT_DATAGRAM_DISPATCH
                            as *const _,
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        irp,
                    )
                }
            },
            Some(|context, result| {
                context.data = result as PWSK_SOCKET;
            }),
        );

        let socket = status.map_err(|e| SocketCreationErr::IrpErr(e))?;
        if socket.is_null() {
            // SAFETY: This is safe because:
            //         1. `WskRegistration` is a valid PWSK_REGISTRATION.
            //         2. WskReleaseProviderNPI is only called once, matching
            //            the number of WskCaptureProviderNPI calls.
            unsafe {
                WskReleaseProviderNPI(*registration_ptr_grd);
            }
            return Err(SocketCreationErr::InvalidSocket);
        }

        // SAFETY: This is safe because:
        //         1. `WskRegistration` is a valid PWSK_REGISTRATION.
        //         2. WskReleaseProviderNPI is only called once, matching the
        //            number of WskCaptureProviderNPI calls.
        unsafe {
            WskReleaseProviderNPI(*registration_ptr_grd);
        }

        Ok(socket)
    }

    ///
    /// `close_socket` attempts to close a socket. The passed socket pointer should
    /// be dropped after this function returns.
    /// 
    /// # Arguments
    /// 
    /// * `socket_ptr` - The socket to close.
    /// 
    fn close_socket(socket_ptr: PWSK_SOCKET) {
        if socket_ptr.is_null() {
            return;
        }

        // SAFETY: This is safe because:
        //         `self.socket` has been verified as a valid pointer.
        let socket = unsafe { &*socket_ptr };

        let dispatch = socket.Dispatch as PWSK_PROVIDER_BASIC_DISPATCH;
        if dispatch.is_null() {
            return;
        }

        // SAFETY: This is safe because:
        //         `dispatch` has been verified as a valid pointer.
        let dispatch = unsafe { &*dispatch };
        if dispatch.WskCloseSocket.is_none() {
            return;
        }

        let _ = call_irp_blocking::<(), _>(
            |irp, _ctx| {
                // SAFETY: This is safe because:
                //         1. `self.socket` is a valid PWSK_SOCKET.
                //         2. `irp` is a valid PIRP, properly freed after use.
                unsafe { dispatch.WskCloseSocket.unwrap()(socket_ptr, irp) }
            },
            None, // result is already stored in context.data
        );
    }

    ///
    /// `bind_socket` takes a socket, and binds it to a specified ip and port.
    ///
    /// # Arguments:
    ///
    /// * `socket_ptr` - A valid pointer to a WSK_SOCKET. The socket to be
    ///   bound.
    /// * `ip` - The 4 byte IPV4, in the form of [127, 0, 0, 1].
    /// * `port` - The 16 bit port number in little endian form.
    ///
    /// # Return value:
    ///
    /// * `Ok(*mut WSK_SOCKET)` - The newly created socket.
    /// * `Err(SocketCreationErr)` - Otherwise.
    ///
    fn bind_socket(socket_ptr: PWSK_SOCKET, ip: IP, port: u16) -> Result<(), SocketBindErr> {
        if socket_ptr.is_null() {
            return Err(SocketBindErr::InvalidSocket);
        }

        // SAFETY: This is safe because:
        //         `socket` has been verified as a valid pointer.
        let socket = unsafe { &*socket_ptr };

        let dispatch = socket.Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH;
        if dispatch.is_null() {
            return Err(SocketBindErr::DatagramDispatchWasNull);
        }

        // SAFETY: This is safe because:
        //         `dispatch` has been verified as a valid pointer.
        let dispatch = unsafe { &*dispatch };
        if dispatch.WskBind.is_none() {
            return Err(SocketBindErr::WskBindWasNull);
        }

        let mut address = SOCKADDR_IN {
            sin_family: AF_INET as u16,
            sin_port: port.swap_bytes(),
            sin_addr: in_addr_from_ip(ip),
            sin_zero: [0; 8],
        };

        let status = call_irp_blocking::<(), _>(
            |irp, _ctx| {
                // SAFETY: This is safe because:
                //         1. `socket_ptr` is a valid PWSK_SOCKET.
                //         2. `Address` is a valid PSOCKADDR.
                //         3. `irp` is a valid PIRP, properly freed after use.
                unsafe {
                    dispatch.WskBind.unwrap()(
                        socket_ptr,
                        &mut address as PSOCKADDR_IN as PSOCKADDR,
                        0,
                        irp,
                    )
                }
            },
            None, // result is already stored in context.data
        );

        status.map_err(|e| SocketBindErr::IrpErr(e))
    }

    ///
    /// `get_socket_address` takes a socket, and reqeusts its current address
    /// (ip and port).
    ///
    /// # Arguments:
    ///
    /// * `socket_ptr` - A valid pointer to a WSK_SOCKET. The socket whose ip is
    ///   to be fetched.
    ///
    /// # Return value:
    ///
    /// * `Ok((ip: IP, port: u16))` - The socket's ip and port.
    /// * `Err(SocketCreationErr)` - Otherwise.
    ///
    fn get_socket_address(socket_ptr: PWSK_SOCKET) -> Result<(IP, u16), GetSocketAddressErr> {
        if socket_ptr.is_null() {
            return Err(GetSocketAddressErr::InvalidSocket);
        }

        // SAFETY: This is safe because:
        //         `socket` has been verified as a valid pointer.
        let socket = unsafe { &*socket_ptr };

        let dispatch = socket.Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH;
        if dispatch.is_null() {
            return Err(GetSocketAddressErr::DatagramDispatchWasNull);
        }

        // SAFETY: This is safe because:
        //         `dispatch` has been verified as a valid pointer.
        let dispatch = unsafe { &*dispatch };
        if dispatch.WskGetLocalAddress.is_none() {
            return Err(GetSocketAddressErr::WskGetLocalAddressWasNull);
        }

        let result = call_irp_blocking::<SOCKADDR_IN, _>(
            |irp, context| {
                // SAFETY: This is safe because:
                //         1. `socket_ptr` is a valid PWSK_SOCKET.
                //         2. `Address` is a valid PSOCKADDR.
                //         3. `irp` is a valid PIRP, properly freed after use.
                unsafe {
                    dispatch.WskGetLocalAddress.unwrap()(
                        socket_ptr,
                        &mut context.data as PSOCKADDR_IN as PSOCKADDR,
                        irp,
                    )
                }
            },
            None, // result is already stored in context.data
        )
        .map_err(|e| GetSocketAddressErr::IrpErr(e))?;

        let port = result.sin_port.swap_bytes();
        let ip = ip_from_in_addr(&result.sin_addr);

        Ok((ip, port))
    }

    ///
    /// `enable_receive_callback` takes a socket, and enables the
    /// OnReceiveFromEvent callback.
    ///
    /// # Arguments:
    ///
    /// * `socket_ptr` - A valid pointer to a WSK_SOCKET. The socket whose
    ///   OnReceiveFromEvent callback is to be enabled.
    ///
    /// # Return value:
    ///
    /// * `Ok(())` - Upon success.
    /// * `Err(SocketEnableCallbackErr)` - Otherwise.
    ///
    fn enable_receive_callback(socket_ptr: PWSK_SOCKET) -> Result<(), SocketEnableCallbackErr> {
        if socket_ptr.is_null() {
            return Err(SocketEnableCallbackErr::InvalidSocket);
        }

        // SAFETY: This is safe because:
        //         `socket` has been verified as a valid pointer.
        let socket = unsafe { &*socket_ptr };

        let dispatch = socket.Dispatch as PWSK_PROVIDER_BASIC_DISPATCH;
        if dispatch.is_null() {
            return Err(SocketEnableCallbackErr::BasicDispatchWasNull);
        }

        // SAFETY: This is safe because:
        //         `dispatch` has been verified as a valid pointer.
        let dispatch = unsafe { &*dispatch };
        if dispatch.WskControlSocket.is_none() {
            return Err(SocketEnableCallbackErr::WskControlSocketWasNull);
        }

        let context_layout = Layout::new::<WSK_EVENT_CALLBACK_CONTROL>();

        // SAFETY: This is safe because:
        //         The result is compared to nullptr.
        let event_callback_control_ptr =
            unsafe { WdkAllocator.alloc_zeroed(context_layout) as PWSK_EVENT_CALLBACK_CONTROL };
        if event_callback_control_ptr.is_null() {
            return Err(SocketEnableCallbackErr::FailedToMakeEventCallbackControl);
        }

        // SAFETY: This is safe because:
        //         1. `event_callback_control_ptr` is a valid
        //            PWSK_EVENT_CALLBACK_CONTROL.
        let event_callback_control = unsafe { &mut *event_callback_control_ptr };

        // SAFETY: This is safe because:
        //         `NPI_WSK_INTERFACE_ID` is properly defined via linking
        //         `um\x64\uuid.lib`.
        event_callback_control.NpiId = unsafe { &NPI_WSK_INTERFACE_ID };
        event_callback_control.EventMask = WSK_EVENT_RECEIVE_FROM;

        // SAFETY: This is safe because:
        //         1. `socket_ptr` is a valid PWSK_SOCKET.
        //         2. `event_callback_control_ptr` is a valid
        //            WSK_EVENT_CALLBACK_CONTROL pointer.
        //         3. `InputSize` matches the `InputBuffer`
        //            (WSK_EVENT_CALLBACK_CONTROL) size.
        //         4. `OutputBuffer` and `OutputSizeReturned` can be
        //            null since `OutputSize` is 0.
        //         5. `irp` is required to be null, as this enablings a callback
        //            function. See SO_WSK_EVENT_CALLBACK docs for more info.
        let status = unsafe {
            dispatch.WskControlSocket.unwrap()(
                socket_ptr,
                WskSetOption,
                SO_WSK_EVENT_CALLBACK,
                SOL_SOCKET,
                size_of::<WSK_EVENT_CALLBACK_CONTROL>() as u64,
                event_callback_control_ptr as PVOID,
                0,
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };

        // SAFETY: This is safe because:
        //         `event_callback_control_ptr` is a valid pointer to a
        //          WdkAllocator allocated data structure.
        unsafe {
            WdkAllocator.dealloc(event_callback_control_ptr as *mut _, DEALLOC_LAYOUT);
        }

        if !nt_success(status) {
            return Err(SocketEnableCallbackErr::FailedToControlSocket(status));
        }

        Ok(())
    }
}

///
/// Context for a WskSocket call, maintained throughout all socket events.
///
struct WskSocketContext {
    identifier: SocketIdentifier,
    read_callback: AsyncReadCallback,
}

///
/// `in_addr_from_ip` takes an ip, and initializes an IN_ADDR using it.
///
/// # Arguments:
/// * `ip` - The 4 byte IPV4, in the form of [127, 0, 0, 1].
///
/// # Return value:
///
/// * `IN_ADDR` - The newly populated data structure.
///
fn in_addr_from_ip(ip: IP) -> IN_ADDR {
    IN_ADDR {
        S_un: in_addr__bindgen_ty_1 {
            S_un_b: in_addr__bindgen_ty_1__bindgen_ty_1 {
                s_b1: ip.0[0],
                s_b2: ip.0[1],
                s_b3: ip.0[2],
                s_b4: ip.0[3],
            },
        },
    }
}

///
/// `ip_from_in_addr` takes an IN_ADDR, and extracts the raw ipv4 data from it.
///
/// # Arguments:
/// * `in_addr` - The IN_ADDR data.
///
/// # Return value:
///
/// * `IP` - The 4 byte IPV4, in the form of [127, 0, 0, 1].
///
fn ip_from_in_addr(in_addr: &IN_ADDR) -> IP {
    // SAFETY: This is safe because:
    //         Regardless of the actual data type, either this returns an
    //         invalid IP, which is still memory safe, or it returns a valid IP,
    //         which is memory safe.
    unsafe {
        IP([
            in_addr.S_un.S_un_b.s_b1,
            in_addr.S_un.S_un_b.s_b2,
            in_addr.S_un.S_un_b.s_b3,
            in_addr.S_un.S_un_b.s_b4,
        ])
    }
}

#[derive(Debug)]
enum WskBufReadErr {
    FailedToMapToSysAddr,
    InvariantViolated,
}

///
/// `vec_from_wsk_buf` creates a vec, fills it with the contents of the wsk_buf,
/// and returns it.
///
/// # Arguments:
///
/// * `wsk_buf` - The WSK_BUF whose contents are to fill the vector.
///
/// # Return Value
///
/// * `Vec<u8>` - The vec, now filled from the wsk_buf.
///
fn vec_from_wsk_buf(wsk_buf: &WSK_BUF) -> Result<Vec<u8>, WskBufReadErr> {
    let mut vec = Vec::with_capacity(wsk_buf.Length as usize);

    let mut len_so_far = 0;
    let mut cur_mdl = wsk_buf.Mdl;
    let mut first_mdl_offset = wsk_buf.Offset;
    while len_so_far < wsk_buf.Length {
        if cur_mdl.is_null() {
            return Err(WskBufReadErr::InvariantViolated);
        }

        // SAFETY: This is safe because:
        //         `cur_mdl` is a verified valid pointer to an MDL.
        let mdl = unsafe { &*cur_mdl };
        if first_mdl_offset >= mdl.ByteCount {
            first_mdl_offset = 0;
            cur_mdl = mdl.Next;
            continue;
        }

        let mdl_len = mdl.ByteCount - first_mdl_offset;

        // SAFETY: This is safe because:
        //         `cur_mdl` is a verified valid pointer to an MDL.
        let sys_addr = unsafe { MmGetSystemAddressForMdlSafe(cur_mdl, NormalPagePriority as u32) };
        if sys_addr.is_null() {
            return Err(WskBufReadErr::FailedToMapToSysAddr);
        }

        // SAFETY: This is safe because:
        //         1. `sys_addr` is a pointer to raw memory with length >
        //            first_mdl_offset, as proven by the prior size comparison.
        //         2. `sys_addr` is only accessed with a length updated to
        //            account for the offset applied here.
        let sys_addr = unsafe { sys_addr.add(first_mdl_offset as usize) };

        // SAFETY: This is safe because:
        //         1. `sys_addr` is a valid pointer to accessible memory, with
        //            len == mdl_len.
        let slice = unsafe { slice::from_raw_parts(sys_addr as *mut u8, mdl_len as usize) };
        vec.extend_from_slice(slice);

        first_mdl_offset = 0;
        len_so_far += mdl_len as u64;
        cur_mdl = mdl.Next;
    }

    Ok(vec)
}

///
/// A wrapper around the `receive_from_event_handler`, which ensures safety.
/// 
unsafe extern "C" fn receive_from_event_handler_unsafe(
    context: PVOID,
    flags: u32,
    data_indication: PWSK_DATAGRAM_INDICATION,
) -> NTSTATUS {
    receive_from_event_handler(context, flags, data_indication)
}

///
/// `receive_from_event_handler` is the callback function for datagram sockets'
/// WskReceiveFromEvent. Its behavior matches the invariant described by the
/// WskSocket call.
///
/// # Arguments:
///
/// * `context` - A valid WskSocketContext pointer, as per the WskSocket call.
/// * `flags` - See PFN_WSK_RECEIVE_FROM_EVENT documentation.
/// * `data_indication` - See PFN_WSK_RECEIVE_FROM_EVENT documentation.
///
/// # Return Value
///
/// * `NTSTATUS` - See PFN_WSK_RECEIVE_FROM_EVENT documentation.
///
fn receive_from_event_handler(
    context: PVOID,
    _flags: u32,
    data_indication: PWSK_DATAGRAM_INDICATION,
) -> NTSTATUS {
    if context.is_null() {
        // invariant violated
        return STATUS_SUCCESS;
    }

    // SAFETY: This is safe because:
    //         `context` is a non null pointer, and by the invariant, must be a
    //         WskSocketContext pointer as such.
    let socket_context = unsafe { &*(context as *const WskSocketContext) };

    if data_indication.is_null() {
        // "If [data_indication] is NULL, the socket is no longer functional and
        //  the WSK application must call the WskCloseSocket function to close
        //  the socket as soon as possible." - PFN_WSK_RECEIVE_FROM_EVENT MSDN
        GlobalSockets::close_socket(socket_context.identifier);
        return STATUS_SUCCESS;
    }

    let mut cur_datagram_ptr = data_indication;
    while !cur_datagram_ptr.is_null() {
        // SAFETY: This is safe because:
        //         `data_indication` was verified as non null prior to
        //         dereferencing.
        let datagram = unsafe { &*cur_datagram_ptr };

        let address = datagram.RemoteAddress;
        if address.is_null() {
            cur_datagram_ptr = datagram.Next;
            continue;
        }

        // SAFETY: This is safe because:
        //         1. `address` is a non null pointer.
        //         2. All sockets using this callback are using IPV4, as per the
        //            `make_socket` definition.
        let address = unsafe { *(address as PSOCKADDR_IN) };

        let port = address.sin_port.swap_bytes();
        let ip = ip_from_in_addr(&address.sin_addr);

        let data = vec_from_wsk_buf(&datagram.Buffer);

        if let Ok(data) = data {
            let context_layout = Layout::new::<WorkItemContext>();
            let context_ptr =
                unsafe { WdkAllocator.alloc_zeroed(context_layout) as *mut WorkItemContext };
            if !context_ptr.is_null() {
                // SAFETY: This is safe because:
                //         `context_ptr` is a valid pointer.
                let context = unsafe { &mut *context_ptr };
                context.identifier = socket_context.identifier;
                context.read_callback = socket_context.read_callback;
                context.data = data;
                context.ip = ip;
                context.port = port;

                context.work_item.List.Flink = null_mut();
                context.work_item.Parameter = context_ptr as *mut _;
                context.work_item.WorkerRoutine = Some(datagram_received_workitem_routine_unsafe);

                unsafe {
                    ExQueueWorkItem(&mut context.work_item as PWORK_QUEUE_ITEM, DelayedWorkQueue);
                }
            }
        }

        cur_datagram_ptr = datagram.Next;
    }

    0
}

///
/// Context for a datagram received work item. This is used to store all
/// necessary information for carrying out a datagram received callback.
///
struct WorkItemContext {
    work_item: WORK_QUEUE_ITEM,

    identifier: SocketIdentifier,
    read_callback: AsyncReadCallback,
    data: Vec<u8>,
    ip: IP,
    port: u16,
}


///
/// A wrapper around the `datagram_received_workitem_routine`, which ensures
/// safety.
/// 
unsafe extern "C" fn datagram_received_workitem_routine_unsafe(
    context: PVOID,
) {
    datagram_received_workitem_routine(context)
}

///
/// `datagram_received_workitem_routine` is the callback function for datagram
/// receive related work items. Its behavior matches the invariant described by
/// the ExQueueWorkItem call in `receive_from_event_handler`.
/// 
/// Because this function is only called from a work item queue finishing, it
/// runs at IRQL_PASSIVE_LEVEL, ensuring the callback is run at
/// IRQL_PASSIVE_LEVEL.
///
/// # Arguments:
///
/// * `context` - A valid WorkItemContext pointer, as per the ExQueueWorkItem
///   call in `receive_from_event_handler`.
///
fn datagram_received_workitem_routine(context_ptr: PVOID) {
    if context_ptr.is_null() {
        return;
    }

    // SAFETY: This is safe because:
    //         `context_ptr` is a valid pointer.
    let context = unsafe { &*(context_ptr as *mut WorkItemContext) };

    (context.read_callback)(context.identifier, &context.data, context.ip, context.port);

    // SAFETY: This is safe because:
    //         `context_ptr` is a valid WdkAllocator allocated buffer, as per
    //         the ExQueueWorkItem call in `receive_from_event_handler`.
    unsafe {
        WdkAllocator.dealloc(context_ptr as *mut u8, DEALLOC_LAYOUT);
    }
}
