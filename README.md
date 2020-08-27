# aiohomekit

![CI](https://github.com/Jc2k/aiohomekit/workflows/CI/badge.svg?event=push) [![codecov](https://codecov.io/gh/Jc2k/aiohomekit/branch/master/graph/badge.svg)](https://codecov.io/gh/Jc2k/aiohomekit)

This library implements the HomeKit protocol for controlling Homekit accessories using asyncio.

It's primary use is for with Home Assistant. We target the same versions of python as them and try to follow their code standards.

At the moment we don't offer any API guarantees. API stability and documentation will happen after we are happy with how things are working within Home Assistant.

## Contributing

`aiohomekit` is primarily for use with Home Assistant. Lots of users are using it with devices from a wide array of vendors. As a community open source project we do not have the hardware or time resources to certify every device with multiple vendors projects. We may be conservative about larger changes or changes that are low level. We do ask where possible that any changes should be tested with a certified HomeKit implementations of shipping products, not just against emulators or other uncertified implementations.

Because API breaking changes would hamper our ability to quickly update Home Assistant to the latest code, if you can please submit a PR to update [homekit_controller](https://github.com/home-assistant/core/tree/dev/homeassistant/components/homekit_controller) too. If they don't your PR maybe on hold until someone is available to write such a PR.

Please bear in mind that some shipping devices interpret the HAP specification loosely. In general we prefer to match the behaviour of real HAP controllers even where their behaviour is not strictly specified. Here are just some of the kinds of problems we've had to work around:

* Despite the precise formatting of JSON being unspecified, there are devices in the wild that cannot handle spaces when parsing JSON. For example, `{"foo": "bar"}` vs `{"foo":"bar"}`. This means we never use a "pretty" encoding of JSON.
* Despite a boolean being explicitly defined as `0`, `1`, `true` or `false` in the spec, some devices only support 3 of the 4. This means booleans must be encoded as `0` or `1`.
* Some devices have shown themselves to be sensitive to headers being missing, in the wrong order or if there are extra headers. So we ensure that only the headers iOS sends are present, and that the casing and ordering is the same.
* Some devices are sensitive to a HTTP message being split into separate TCP packets. So we take care to only write a full message to the network stack.

And so on. As a rule we need to be strict about what we send and loose about what we receive.

## Device compatibility

`aiohomekit` is primarily tested via Home Assistant with a Phillips Hue bridge and an Eve Extend bridge. It is known to work to some extent with many more devices though these are not currently explicitly documented anywhere at the moment.

You can look at the problems your device has faced in the home-assistant [issues list](https://github.com/home-assistant/core/issues?q=is%3Aopen+is%3Aissue+label%3A%22integration%3A+homekit_controller%22).

## FAQ

### How do I use this?

It's published on pypi as `aiohomekit` but its still under early development - proceed with caution.

The main consumer of the API is the [homekit_controller](https://github.com/home-assistant/core/tree/dev/homeassistant/components/homekit_controller) in Home Assistant so that's the best place to get a sense of the API.

### Does this support BLE accessories?

No. Eventually we hope to via [aioble](https://github.com/detectlabs/aioble) which provides an asyncio bluetooth abstraction that works on Linux, macOS and Windows.

### Can i use this to make a homekit accessory?

No, this is just the client part. You should use one the of other implementations:

 * [homekit_python](https://github.com/jlusiardi/homekit_python/) (this is used a lot during aiohomekit development)
 * [HAP-python](https://github.com/ikalchev/HAP-python)

### Why doesn't Home Assistant use library X instead?

At the time of writing this is the only python 3.7/3.8 asyncio HAP client with events support.

### Why doesn't aiohomekit use library X instead?

Where possible aiohomekit uses libraries that are easy to install with pip, are ready available as wheels (including on Raspberry Pi via piwheels), are cross platform (including Windows) and are already used by Home Assistant. They should not introduce hard dependencies on uncommon system libraries. The intention here is to avoid any difficulty in the Home Assistant build process.

People are often alarmed at the hand rolled HTTP code and suggest using an existing HTTP library like `aiohttp`. High level HTTP libraries are pretty much a non-starter because:

* Of the difficulty of adding in HAP session security without monkey patches.
* They don't expect responses without requests (i.e. events).
* As mentioned above, some of these devices are very sensitive. We don't care if your change is compliant with every spec if it still makes a real world device cry. We are not in a position to demand these devices be fixed. So instead we strive for byte-for-byte accuracy on our write path. Any library would need to give us that flexibility.
* Some parts of the responses are actually not HTTP, even though they look it.

We are also just reluctant to make a change that large for something that is working with a lot of devices. There is a big chance of introducing a regression.

Of course a working proof of concept (using a popular well maintained library) that has been tested with something like a Tado internet bridge (including events) would be interesting.

## Thanks

This library wouldn't have been possible without homekit_python, a synchronous implementation of both the client and server parts of HAP. 
