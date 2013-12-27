Cryptotronix Hashlet
=====

Status
---

As of 16 December, 2013 this software is in an alpha state.  The code can certainly be a lot cleaner.  Feel free to look around but I'd recommend waiting to jump in until the Beta release.  This is because there are certain one-way operations on the device that can't be undone once set.  This may leave the device in a undesirable state.

Building
----

This project uses Autotools and you need that installed to configure and build the executable.  I am mainly developing on a BeagleBone Black using Debian.

If you pull this repo (i.e. a non-release), you will need the following dependencies:
- autotools (i.e. automake, autconf, and libtool)
- Flex and Bison

The run time dependencies are:
- libgcrypt (Hashlet will compile without it, but you will lose features)

Hardware
---

In early January, you will be able to buy the hardware from [Cryptotronix](http://cryptotronix.com/products/hashlet/).  We are an open hardware company, so see the `hardware` folder for the design to make this yourself.

The Hashlet is 3.3V and 5V friendly. The headers are setup for BeagleBone but one can use it on a Raspberry Pi as well.

Running
---

see `./hashlet --help` for full details.

Currently supported commands:

### personalize
```bash
./hashlet /dev/i2c-1 personalize
```
On success it will not output anything.  Random keys are loaded into the device and saved to `~/.hashlet` as a backup.  Don't lose that file.

### random
```bash
./hashlet /dev/i2c-1 random
62F95589AC76855A8F9204C9C6B8B85F06E6477D17C3888266AEE8E1CBD65319
```

### mac
```bash
./hashlet /dev/i2c-1 mac --file test.txt
FB19B1C63161B6C34CA9D291D1CD16F98247BBA9A298775F795161BEB95BB6EF
```
On success it will simply output an exit code of 0.

### hash
```bash
./hashlet /dev/null hash --file test.txt
322B3FFC3BE16B4CC5B445F8E666D0BA5C5E676D00FABD2308AD51243FA0B067
```

Performs a SHA256 of the file, this is the challenge input into `offline-verify`.

### offline-verify
```bash
./hashlet /dev/null offline-verify -c 322B3FFC3BE16B4CC5B445F8E666D0BA5C5E676D00FABD2308AD51243FA0B067 -r FB19B1C63161B6C34CA9D291D1CD16F98247BBA9A298775F795161BEB95BB6EF
```

On success, it will output an exit code of 0, otherwise it will fail.  The point of this command is that a remote server can verify the MAC from the Hashlet without a device.  The keys are written to `~/.hashlet` upon personalization and if this file is store on the server, it can verify a MAC.

The workflow goes like this:

1. Mac some data to produce a challenge response.
2. Hash the same data to produce the challenge.
3. Send the Hash and MAC to the remote server, which has the key_store.
4. Perform offline-verify on the remote server.

### serial-num
```bash
./hashlet /dev/i2c-1 serial-num
0123XXXXXXXXXXXXEE
```
X's indicate the unique serial number.

### state
```bash
./hashlet /dev/i2c-1 state
Factory
```
Factory indicates that the device is in it's original factory state.

Design
---

In the `hardware` folder, one should find the design files for the Hashlet.  The IC on the hashlet is the [Atmel ATSHA204](http://www.atmel.com/Images/Atmel-8740-CryptoAuth-ATSHA204-Datasheet.pdf).

Contributing
---
See the wiki page on [contributing](https://github.com/cryptotronix/hashlet/wiki/Contributing).
