# DerpNET

(Ab)using Tailscale's DERP servers to connect any two machines without a Tailscale account.

Tailscale operates many [DERP servers](https://tailscale.com/kb/1232/derp-servers) which implement the [DERP protocol](https://github.com/tailscale/tailscale/blob/main/derp/derp.go).
DERP servers support routing a packet to any client connected to the same DERP server using their curve25519 address.

We (ab)use this routing to implement UDP-like connections through DERP server. Instead of IP addresses, we use curve25519 public keys as the address. TCP-like stream semantics are added by running [QUIC](https://en.wikipedia.org/wiki/QUIC) on top of the UDP-like connection.

This project is not affiliated with Tailscale in any way. I've used it to connect to small HTTP servers on my personal machine. It is not optimized for high bandwidth.

## Usage

To install the binary, run:  
`go install github.com/ntnj/derpnet/cmd/derpconnect@latest`

Find a DERP server closest to you from [here](https://login.tailscale.com/derpmap/default). Use it as the value of `--derp` flags in the commands below. To override the default DERP TLS port, pass `--derp=<host>:<port>`. To fetch the comma-separated DERP server list from a URL instead, pass `--derp-list=<url>`.

To expose a port running on a server:  
`derpconnect --derp=... serve <port>`  
The above command will print a public key, which you can use on different client machine.

On a client machine, run:  
`derpconnect --derp=... join <pubkey> <listen_addr>`  
This will start listening on `<listen_addr>`, and any connections to that address are forwarded to `<port>` on the server. For compatibility, a bare port listens on `127.0.0.1:<port>`; use an address like `:8080` only if you want to listen on all interfaces.

To connect a single stream directly over stdin/stdout instead of opening a local listener, use `stdio` as the address:  
`derpconnect --derp=... join <pubkey> stdio`

For self-hosted DERP servers with private or self-signed certificates, `--insecure-derp` disables TLS certificate verification for the DERP server connection only. The inner QUIC link still authenticates peers with their DERP keypairs.

## Use as a library

To get a UDP like connection, you can use `derpnet.ListenPacket`, which is similar to `net.ListenPacket` function:

```go
import github.com/ntnj/derpnet

conn, err := derpnet.ListenPacket("<derp>.tailscale.com", <privatekeybytes>)

n, err := conn.WriteTo(<msg>, <pubkeybytes>)

n, addr, err := conn.ReadFrom(<bytes>)
```

TCP-like semantics are added based on QUIC streams implemented with [quic-go](https://github.com/quic-go/quic-go).

On server side:

```go
import github.com/ntnj/derpnet/derpquic

l, err := derpquic.Listen("<derp>.tailscale.com", <privatekeybytes>)

for {
    conn, err := l.Accept()
    // conn implements net.Conn
}

```

On the client:

```go
import github.com/ntnj/derpnet/derpquic

d, err := derpquic.NewDialer("<derp>.tailscale.com", <privatekeybytes>)

conn, err := d.Dial(<pubkeybytes>)
// conn implements net.Conn
```

### Caveats

- It doesn't attempt to establish P2P connections like Tailscale does, so will be limited by DERP server's bandwidth and latency.
- quic-go [doesn't currently allow](https://github.com/quic-go/quic-go/issues/3385) setting configurable packet size and uses a default of 1200, which causes a large amount of packets to be sent to DERP server for connections sending a lot of data.
- It doesn't currently handle reconnecting to DERP server in case the connection to the DERP server drops.
