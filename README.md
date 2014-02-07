Cryptotronix Hashlet
=====

[![Build Status](https://travis-ci.org/cryptotronix/hashlet.png)](https://travis-ci.org/cryptotronix/hashlet)

Status
---

As of 7 February, 2014 the 1.0.0 release is considered a second Beta release and is available on the [release](http://download.savannah.gnu.org/releases/hashlet/) page.  It has been tested on a BeagleBone Black, rev 5AC running Debian Wheezy and a Raspberry Pi running Raspian.  It *should* work with Angstrom, but has not been tested.  Beta testers are welcome!

Building
----

This project uses Autotools and you need that installed to configure and build the executable.  I am mainly developing on a BeagleBone Black using Debian.

If you pull this repo (i.e. a non-release), you will need the following dependencies:
- autotools (i.e. automake, autconf, and libtool)
- Flex and Bison
- texinfo (for the documentation if you so desire)

The run time dependencies are:
- libgcrypt

Hardware
---

The hardware is available from [Cryptotronix](http://cryptotronix.com/products/hashlet/).  We are an open hardware company, so see the `hardware` folder for the design to make this yourself.

BOM
---

The chip on the Hashlet is Atmel's ATSHA204.

Running
---

see `./hashlet --help` for full details.  The default I2C bus is `/dev/i2c-1` and this can be changed with the `-b` option.  On some BBB, the bus is `/dev/i2c-2`.  See this [blog post](http://datko.net/2013/11/03/bbb_i2c/) for further details on BBB I2C.

Root
---

You'll need to run as root to access `/dev/i2c*` initially.  You can change this by adding your user to the `i2c` group with:

`sudo usermod -aG i2c user`

Or:

`sudo chmod o+rw /dev/i2c*`


Currently supported commands:

### state
```bash
./hashlet state
Factory
```

This is the first command you should run and verify it's in the Factory state.  This provides the assurance that the device has not been tampered during transit.

### personalize
```bash
./hashlet personalize
```

With the key import feature:

```bash
./hashlet personalize -f keys.txt
```

This is the second command you should run.  On success it will not output anything.  Random keys are loaded into the device and saved to `~/.hashlet` as a backup.  Don't lose that file.  Keys from another hashlet can be imported with the `-f` option, where the file is not also named `~/.hashlet`.

### random
```bash
./hashlet random
62F95589AC76855A8F9204C9C6B8B85F06E6477D17C3888266AEE8E1CBD65319
```

### mac
```bash
./hashlet mac --file test.txt
mac       : C3466ABB8640B50938B260E17D86489D0EBB3F9C8009024683CB225FFFD3B4E4
challenge : 9F0751C90770E6B40E34BA8E06EFE453FAA46B5FB26925FFBD664FAF951D000A
meta      : 08000000000000000000000000
```

On success it will output three parameters:

1. mac: (aka challenge response) The result of the operation
2. challenge: This is the input to the Hashlet, after a SHA256 digest
3. meta: Meta data that must accompany the result

### check-mac
```bash
./hashlet check-mac -r C3466ABB8640B50938B260E17D86489D0EBB3F9C8009024683CB225FFFD3B4E4 -c 9F0751C90770E6B40E34BA8E06EFE453FAA46B5FB26925FFBD664FAF951D000A -m 08000000000000000000000000
```

Checks the MAC that was produced by the Hashlet.  On success, it will with an exit value of 0.

### offline-verify
```bash
./hashlet offline-verify -c 322B3FFC3BE16B4CC5B445F8E666D0BA5C5E676D00FABD2308AD51243FA0B067 -r FB19B1C63161B6C34CA9D291D1CD16F98247BBA9A298775F795161BEB95BB6EF
```

On success, it will output an exit code of 0, otherwise it will fail.  The point of this command is that a remote server can verify the MAC from the Hashlet without a device.  The keys are written to `~/.hashlet` upon personalization and if this file is store on the server, it can verify a MAC.

The workflow goes like this:

1. Mac some data to produce a challenge response.
2. Send the challenge and MAC to the remote server, which has the key store file.
3. Perform offline-verify on the remote server.

### serial-num
```bash
./hashlet serial-num
0123XXXXXXXXXXXXEE
```
X's indicate the unique serial number.

Options
---

Options are listed in the `--help` command, but a useful one, if there are issues, is the `-v` option.  This will dump all the data that
travels across the I2C bus with the device.


Design
---

In the `hardware` folder, one should find the design files for the Hashlet.  The IC on the hashlet is the [Atmel ATSHA204](http://www.atmel.com/Images/Atmel-8740-CryptoAuth-ATSHA204-Datasheet.pdf).

Support
---

IRC: Join the `#cryptotronix` channel on freenode.

Mailing lists: `hashlet-announce` and `hashlet-users` are open for subscriptions [here](https://savannah.nongnu.org/mail/?group=hashlet).

Contributing
---
See the wiki page on [contributing](https://github.com/cryptotronix/hashlet/wiki/Contributing).
