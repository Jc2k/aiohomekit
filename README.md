# aiohomekit

[![Build Status](https://travis-ci.com/Jc2k/aiohomekit.svg?branch=master)](https://travis-ci.com/Jc2k/aiohomekit)  | [![codecov](https://codecov.io/gh/Jc2k/aiohomekit/branch/master/graph/badge.svg)](https://codecov.io/gh/Jc2k/aiohomekit)

This library implements the HomeKit protocol for controlling Homekit accessories using asyncio.

It's primary use is for with Home Assistant. We target the same versions of python as them and try to follow their code standards.

At the moment we don't offer any API guarantees. API stability and documentation will happen after we are happy with how things are working within Home Assistant.


## FAQ

### How do I use this?

It's published on pypi as `aiohomekit` but its still under early development - proceed with caution.

### Does this support BLE accessories?

No. Eventually we hope to via aioble which provides an asyncio bluetooth abstraction that works on Linux, macOS and Windows.

### Can i use this to make a homekit accessory?

No, this is just the client part. You should use one the of other implementations:

 * [homekit_python](https://github.com/jlusiardi/homekit_python/)
 * [HAP-python](https://github.com/ikalchev/HAP-python)


### Why don't you use library X instead?

At the time of writing this is the only python 3.7/3.8 asyncio HAP client.


## Thanks

This library wouldn't have been possible without homekit_python, a synchronous implementation of both the client and server parts of HAP. 
