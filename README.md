
# wdk-udp-socket

A Rust based UDP socket library for my Ferrum Windows kernel driver development.

To install this crate:
```
cargo add wdk-udp-socket --git https://github.com/GameGuyThrowaway/wdk-udp-socket.git
```

This crate gives easy access to udp sockets from a KMDF driver. It lets users host udp sockets, write from sockets, and
asynchronously read datagrams on the socket. All in a (hopefully) safe way.

This crate was designed strictly for my use in the Rust based Ferrum kernel driver for Windows. As such, it doesn't
exactly have a standardized use, and is instead optimized for how I use it. However with some simple changes, I'm sure
it may be useful to someone else trying to work with udp sockets (or sockets in general) from the kernel.

My understanding of the Windows kernel is lacking, and I am rather inexperienced with low level
multi-threaded/asynchronous systems. In this project, I opted to attempt to try to be as memory safe as possible by
using Rust, and by following in the footsteps of others with seemingly more experience. For example, many of the memory
concurrency practices were based on https://github.com/0xflux/Sanctum, a project by the developer of the crate I use for
most concurrency safety, wdk-mutex.

## Features

* Hosting a UDP socket on a specific IP and port.
* Writing synchronously to UDP sockets on other IPs and ports.
* Processing incoming datagrams asynchronously via callbacks.
    * Just pass a callback, and the library will automatically call your function when a datagram is received by the
      socket.

## TODO/Limitations

* Documentation could be better.
* Currently there is a fixed limit on the number of opened sockets at once.
    * This is because of the nature of the memory safety, and using global mutex pointers to handle multi threaded
      access to sockets.
* Broadcasting is not supported yet. Only unicasting.
* There is no automated testing of this code.
    * However I don't see much room for unit tests, and integration/system tests are a bit complex, requiring user mode
      and kernel mode apps, so I haven't designed them yet.
* This code is potentially unsafe.
    * Being a novice kernel developer, I'm not extremely experienced with writing safe production code, and don't know
      what to look out for, and how systems behave in the Windows kernel.
    * I don't recommend this for use in production environments until further analysis is done.

# Examples

TODO: Link the Ferrum driver once it is published.

## Hosting a socket, and echoing data

This example attempts to host a socket at IP: 127.0.0.1, Port: 54070, and echo any data received on it.

```rust
extern crate alloc;
use alloc::vec::Vec;
use wdk_udp_socket::{UdpSocketIdentifier, UdpSocket, UdpSocketAddr};

fn read_async() {
    match UdpSocket::new(UdpSocketAddr::new([127, 0, 0, 1], 54070), socket_read_handler) {
        Ok(identifier) => {
            let mutex_ptr = GlobalUdpSockets::get_socket(identifier).unwrap();
            let socket_locked = unsafe { (*mutex_ptr).lock().unwrap() };

            let address = socket_locked.get_address();
            println!(
                "Opened a UDP Socket on: {address} with ID: {:?}",
                identifier,
            );

            // leave open for the read handler
            //GlobalUdpSockets::close_socket(identifier);
            //println!("Closed the socket");
        }
        Err(e) => println!("Failed to create Socket: {:?}", e),
    }
}

fn socket_read_handler(identifier: UdpSocketIdentifier, data: &Vec<u8>, address: UdpSocketAddr) {
    use alloc::string::String;
    println!(
        "Socket Read: {:?} | {}",
        data,
        String::from_utf8_lossy(&data)
    );

    let mutex_ptr = GlobalUdpSockets::get_socket(identifier).unwrap();
    let socket_locked = unsafe { (*mutex_ptr).lock().unwrap() };

    match socket_locked.write_blocking(data, address) {
        Ok(_) => println!("Echoed Back {} bytes", data.len()),
        Err(e) => println!("Failed to write any data: {:?}", e),
    }
}
```
