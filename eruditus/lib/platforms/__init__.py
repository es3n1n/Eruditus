from enum import Enum, EnumMeta
from typing import Optional

import aiohttp

from lib.platforms.abc import PlatformABC, PlatformCTX
from lib.platforms.ctfd import CTFd
from lib.platforms.ctfjs import CTFJs
from lib.platforms.rctf import RCTF
from lib.platforms.traboda import Traboda


class PlatformMeta(EnumMeta):
    def __iter__(cls):
        for platform in super().__iter__():
            if not platform.value:
                continue

            yield platform.value


class Platform(Enum, metaclass=PlatformMeta):
    CTFd = CTFd
    RCTF = RCTF
    Traboda = Traboda
    CTFJs = CTFJs
    UNKNOWN = None


async def match_platform(ctx: PlatformCTX) -> Optional[PlatformABC]:
    for platform in Platform:
        try:
            if await platform.match_platform(ctx):
                return platform
        except aiohttp.ClientError:
            continue

    return None
