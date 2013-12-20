Cryptotronix Hashlet
=====

Status
---

As of 16 December, 2013 this software is in an alpha state.

Building
----

This project uses Autotools and you need that installed to configure and build the executable.  I am mainly developing on a BeagleBone Black using Debian.

Hardware
---

In early January, you will be able to buy the hardware from [Cryptotronix](http://cryptotronix.com/products/hashlet/).  We are an open hardware company, so see the `hardware` folder for the design to make this yourself.

The Hashlet is 3.3V and 5V friendly. The headers are setup for BeagleBone but one can use it on a Raspberry Pi as well.

Running
---

see `./hashlet --help` for full details.

Currently supported commands:

### random
```bash
./hashlet /dev/i2c-1 random
62F95589AC76855A8F9204C9C6B8B85F06E6477D17C3888266AEE8E1CBD65319
```


Design
---

In the `hardware` folder, one should find the design files for the Hashlet.  The IC on the hashlet is the [Atmel ATSHA204](http://www.atmel.com/Images/Atmel-8740-CryptoAuth-ATSHA204-Datasheet.pdf).
