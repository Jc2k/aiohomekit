#
# Copyright 2019 aiohomekit team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Provide a non-blocking wrapper around the zeroconf library.

There is aiozercoonf but it doesn't work on Windows - there isn't a
version of asyncio with UDP support on Windows that also supports subprocess.
This is fixed in Python 3.8, but until then it's probably best to stick
with zeroconf.

This also means we don't need to add any extra dependencies.
"""

from aiohomekit.zeroconf import (  # noqa: F401
    async_discover_homekit_devices,
    discover_homekit_devices,
)
