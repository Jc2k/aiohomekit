from abc import ABCMeta, abstractmethod
from typing import Awaitable, Callable, final

from aiohomekit.model.categories import Categories
from aiohomekit.model.feature_flags import FeatureFlags
from aiohomekit.model.status_flags import StatusFlags

from .pairing import AbstractPairing

FinishPairing = Callable[[str], Awaitable[AbstractPairing]]


class AbstractDiscovery(metaclass=ABCMeta):

    name: str
    id: str
    model: str
    feature_flags: FeatureFlags
    status_flags: StatusFlags
    config_num: int
    state_num: int
    category: Categories

    @final
    @property
    def paired(self) -> bool:
        return not (self.status_flags & StatusFlags.UNPAIRED)

    @final
    @property
    def pair_with_auth(self) -> bool:
        if self.feature_flags & FeatureFlags.SUPPORTS_APPLE_AUTHENTICATION_COPROCESSOR:
            return True

        if self.feature_flags & FeatureFlags.SUPPORTS_SOFTWARE_AUTHENTICATION:
            return False

        # We don't know what kind of pairing this is, assume no auth
        return False

    @abstractmethod
    async def start_pairing(self, alias: str) -> FinishPairing:
        pass

    @abstractmethod
    async def identify(self) -> None:
        pass
