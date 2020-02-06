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

import setuptools


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aiohomekit",
    packages=setuptools.find_packages(exclude=["tests"]),
    version="0.0.2",
    description="asyncio library for HomeKit accessories",
    author="John Carr",
    author_email="pypi@unrouted.co.uk",
    url="https://github.com/Jc2k/aiohomekit",
    keywords=["HomeKit"],
    install_requires=["hkdf", "ed25519", "cryptography>=2.5",],
    extras_require={"IP": ["zeroconf"], "BLE": ["aioble"]},
    license="Apache License 2.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
)
