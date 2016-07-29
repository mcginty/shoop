# 🏎🏎🏎  shoop  🏎🏎🏎
SCP for the modern era. If I were better at marketing I might call this "insanely" fast.

# security
🖕🖕🖕 This is so incredibly alpha. not alpha like how fraternities use it. alpha like unverified.🖕🖕🖕

**DO NOT USE THIS FOR SECURITY SENSITIVE MATERIAL. THERE ARE KNOWN WEAKNESSES IN ITS CURRENT STATE.**

THIS IS A PREVIEW. As time passes, software gets more secure assuming I keep my unlaziness.

# what's it do
Shoop is a high-speed encrypted file transfer tool reminiscent of scp. It uses SSH to bootstrap authentication and encryption, then uses UDT (a reliable protocol from the 2000s) instead of TCP (a reliable protocol from the 1970s).

It is **particularly** useful in connections that are "bursty".

From Vietnam, for example, it typically speeds up my downloads by about 2x, if not more for larger files.

# install
The server-side and client-side use the same binary (at least for now). Follow these instructions for both sides (at the moment, I'm not distributing binaries until this is more stable). If you're familiar with `mosh`, it's a very similar setup.

* install rust (I recommend [rustup](https://www.rustup.rs/))
* install libsodium (this is temporary until libsodium 1.0.11 is released and https://github.com/dnaq/sodiumoxide/pull/135 is merged). 
  * **macOS**: `brew install libsodium`
  * **everyone else**: Follow the instructions at https://github.com/jedisct1/libsodium. I believe in you.
  
```
git clone https://github.com/mcginty/shoop
cd shoop
cargo build --release
target/release/shoop <remote-host>:<remote-path> # on the client-side
```

### server
On the server-side, make sure that "shoop" is somewhere in your PATH. There's no `make install` right now, but for example on my server, I just did a quick:
```
ln -s $HOME/git/shoop/target/release/shoop /usr/local/bin/shoop
```

Also, if you have a firewall, the default port range shoop uses is 55000-55050 (if you want 50 simultaneous connections). In Ubuntu this might look like:
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
