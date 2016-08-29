# 🏎🏎🏎  shoop  🏎🏎🏎   [![Build Status](https://travis-ci.org/mcginty/shoop.svg?branch=master)](https://travis-ci.org/mcginty/shoop)
SCP for the modern era. If I were better at marketing I might call this "insanely" fast.

# security and stability
This is so incredibly alpha. not alpha like how fraternities use it. alpha like unverified.

**DO NOT USE THIS FOR SECURITY SENSITIVE MATERIAL.**

THIS IS A PREVIEW. As time passes, software gets more secure assuming I keep my unlaziness. Also right now, the protocol isn't stabilized, so you will need to keep the binaries on the server and client at (more or less) the same revision until we leave pre-alpha state.

# what's it do
Shoop is a high-speed encrypted file transfer tool reminiscent of scp. It uses SSH to bootstrap authentication and encryption, then uses UDT (a reliable protocol from the 2000s) instead of TCP (a reliable protocol from the 1970s).

It is **particularly** useful in connections that are "bursty".

From Vietnam, for example, it typically speeds up my downloads by about 2x, if not more for larger files.

# install
The server-side and client-side use the same binary (at least for now). Follow these instructions for both sides (at the moment, I'm not distributing binaries until this is more stable). If you're familiar with `mosh`, it's a very similar setup.

## macos
1. install rust (I recommend [rustup](https://www.rustup.rs/))
3. `cargo install shoop`

## debian (and, basically, any other linux)
1. install build dependencies `sudo apt install build-essentials pkg-config`
3. install rust via rustup `curl https://sh.rustup.rs -sSf | sh`
4. source cargo env variables `source $HOME/.cargo/env`
5. build and install shoop `source $HOME/.cargo/env`

**Important note**: on server side you should copy (or symlink) shoop binary to the system binary directories (e.g. /usr/bin). For some cases, it not launching from `$HOME/.cargo/bin`.

### server
If you have a firewall, the default port range shoop uses is 55000-55050 (if you want 50 simultaneous connections). In Ubuntu this might look like:
```
sudo ufw allow 55000:55010/udp
```

# your typical performance example
```
☁  shoop [master] ⚡ time scp host-in-germany:~/125mb.file .
1.65s user 2.20s system 2% cpu 2:15.39 total
☁  shoop [master] ⚡ time shoop host-in-germany:~/125mb.file
2.39s user 4.53s system 8% cpu 1:18.53 total
```

# why should i use it
* It deals with unreliable/shoddy connections much more gracefully
* It survives network interruptions

# but isn't there tool X, Y, and Z already for this?
no, actually, not really.
