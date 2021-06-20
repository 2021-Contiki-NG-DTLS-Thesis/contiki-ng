# Compiling and running the MbedTLS DTLS example programs

Each example program has a folder with the relevant name.

## Available programs

There are four available example programs, two client and server pairs, one using Pre-shared keys (PSK) mode and the other using X.509 certificate mode.

Folders `/dtls-example-client-PSK` and `/dtls-example-server-PSK` contain the example programs run in PSK mode.

Folders `/dtls-example-client` and `/dtls-example-server` contain the example programs run in certificate mode.

## Folder structure

Each folder contains:
1. C file `*name_of_folder*.c`
2. `Makefile`,
3. Contiki-NG config file `project-conf.h`,
4. MbedTLS config file `mbedtls/config.h`

The C file contains the code of the example program.

The makefile has the compilation options of Contiki-NG; note the `MBEDTLS_PATH` and its addition to `MODULES`.

Contiki-NG config file contains macros for Contiki-NG debugging and memory size. `HEAPMEM_CONF_ALIGNMENT` should be set to `sizeof(uint64_t)` to achieve correct memory alignment.

MbedTLS config file is an extensive configuration file that provides a lot of options for each individual program. This file should be edited to obtain optimal resource usage for each program by disabling unnecessary features.

## Settings

For a client and server pair to work the client needs to have the ip address of the server. Enter the ipv6 address of the server into the C file of the client in string form:

```
uiplib_ipaddrconv("fd00::1", &server_addr);
```

The other important setting is the correct minimal buffer size for each mode of operation. In `mbedtls/config.h` the following macros need to be defined for smaller memory usage.

In PSK mode
```
#define MBEDTLS_SSL_MAX_CONTENT_LEN             1070
```
In X.509 Certificate mode
```
#define MBEDTLS_SSL_MAX_CONTENT_LEN             3*1024
```

Smaller sizes for these modes will return an MbedTLS timeout error.

## Compiling

Compiling the DTLS example programs is done the same as other Contiki-NG programs.
```
make
```
or
```
make TARGET=<PLATFORM>
```
When not specifying platform the Contiki-NG native platform is used by default.

Compiling for Cooja works the same as any other example program run from within Cooja.

## Running

Running the example programs on the native platform as native processes of Linux, they need to be run using `sudo` for Contiki-NG to obtain access to the tunneling device `tun0`. Since only one program can have access to this device at a time only the client or server can be run. To provide the other peer the example programs need to be run on the native platform. These example programs can be obtained from a copy of the original MbedTLS library in `programs/ssl`. An easier method would be to run both nodes in Cooja so that the tunneling interface is not a problem.
### Steps to run DTLS example client

These steps work for both modes.

1. Run `make` in the root directory of a copy of the original mbedtls repository to compile the example programs. Run MbedTLS `dtls_server` using `sudo`, take note of the IP address used by the server,
2. Set the server IP address into the relevant Contiki-NG client program, `dtls-example-client.c` and compile it.
3. Run the Contiki-NG client program with `sudo`.


Following these step you should get printouts of the steps of the TLS connection and the sent message of the client, as well as the received message from the server.

The server will close the connection and might try to immediately try to connect a second time although the client is still closing a connection, thus and error will be thrown in the server side. This is expected normal behavior.

### Steps to run DTLS example server

1. Run the Contiki-NG DTLS example server `dtls_example_server.native`  with `sudo`.
2. Input the server IP into the MbedTLS `dtls_client` and recompile the MbedTLS library by running make at the root `/mbedtls` directory.
3. Run the MbedTLS client program with `sudo`.

The output should be the same as the example client.

The original MbedTLS library does not provide a client and server examples using PSKs. As a result, the PSK versions have to be run in Cooja.

## Errors

If an MbedTLS errors has occurred, look up the given error code in `/mbedtls/include/mbedtls/error.h` or search the library for a comment referring to it.