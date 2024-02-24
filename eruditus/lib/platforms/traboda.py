import io
from typing import AsyncIterator

import aiohttp

from lib.platforms.abc import Challenge
from lib.platforms.abc import ChallengeHint
from lib.platforms.abc import ChallengeSolver
from lib.platforms.abc import Optional
from lib.platforms.abc import PlatformABC
from lib.platforms.abc import PlatformCTX
from lib.platforms.abc import RegistrationStatus
from lib.platforms.abc import Session
from lib.platforms.abc import SubmittedFlag
from lib.platforms.abc import Team
from lib.platforms.abc import TeamScoreHistory
from lib.util import deserialize_response
from lib.validators import traboda


def generate_headers(ctx: PlatformCTX) -> dict[str, str]:
    if not ctx.session or not ctx.session.validate():
        return {}

    return {"Authorization": f'Bearer {ctx.args["authToken"]}'}


class Traboda(PlatformABC):
    name = "Traboda"

    @classmethod
    async def match_platform(cls, ctx: PlatformCTX) -> bool:
        """Check whether a website is using the rCTF framework.

        Args:
            ctx: Platform context.

        Returns:
            True if the platform is using rCTF, else False.

        Raises:
            aiohttp.ClientError: if something goes wrong while communicating with the
                platform.
        """
        async with aiohttp.request(
            method="get",
            url=f"{ctx.url_stripped}/",
        ) as response:
            _text: str = await response.text()

            return "https://arena.traboda.com/" in _text

    @classmethod
    async def login(cls, ctx: PlatformCTX) -> Optional[Session]:
        if ctx.is_authorized():
            return ctx.session

        # Send authentication request
        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/api/graphql/",
            json={
                "query": "mutation ($username: String!, $password: String!) { login(username: $username, password: $password) { id username name type } }",
                "variables": {
                    "username": ctx.args.get("username"),
                    "password": ctx.args.get("password"),
                },
            },
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(response, model=traboda.LoginResponse)
            if not data or not data.data.login:
                return None

            # Save the cookies
            cookies = {cookie.key: cookie.value for cookie in response.cookies.values()}
            ctx.session = Session(cookies=cookies)
            return ctx.session

    @classmethod
    async def fetch(cls, ctx: PlatformCTX, url: str) -> Optional[io.BytesIO]:
        """Fetch a URL endpoint from the rCTF platform and return its response.

        Args:
            ctx: Platform context.
            url: The URL to fetch.

        Returns:
            A file-like object for reading the response data.
        """
        if not await ctx.login(cls.login):
            return None

        if not url.startswith(ctx.base_url):
            return None

        async with aiohttp.request(
            method="get",
            url=url,
            cookies=ctx.session.cookies,
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                return None
            try:
                content = await response.read()
            except aiohttp.ClientError:
                return None
            return io.BytesIO(content)

    @classmethod
    async def submit_flag(
        cls, ctx: PlatformCTX, challenge_id: str, flag: str
    ) -> Optional[SubmittedFlag]:
        # todo
        return None

    @classmethod
    async def pull_challenges(cls, ctx: PlatformCTX) -> AsyncIterator[Challenge]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/api/graphql/",
            json={
                "query": "query ($after: String, $keyword: String, $filters: ChallengeFilterInput, $sort: ChallengeSortInput) {  challenges(after: $after, keyword: $keyword, filters: $filters, sort: $sort) {    hasNext    lastCursor    facets{        categories {            category {                name                id                slug            }            results        }    }    challenges{      id      name      points      solveStatus{        label      }      difficulty{        label        level      }      category{        id        name        slug      }    }  }}",
                "variables": {
                    "keyword": None,
                    "filters": {
                        "categoryID": None,
                        "tag": None,
                        "difficultyLevel": None,
                        "solveStatus": None,
                    },
                    "sort": None,
                    "after": None,
                },
            },
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(
                response, model=traboda.GetChallengesResponse
            )
            if not data or not data.data:
                return

            # Iterate over challenges and parse them
            for challenge in data.data.challenges:
                yield Challenge(
                    id=str(challenge.id),
                    name=challenge.name,
                    category=challenge.category.name,
                    description="none",
                )

    @classmethod
    async def pull_scoreboard(
        cls, ctx: PlatformCTX, max_entries_count: int = 20
    ) -> AsyncIterator[Team]:
        # todo
        for x in []:
            yield x

    @classmethod
    async def pull_scoreboard_datapoints(
        cls, ctx: PlatformCTX, count: int = 10
    ) -> Optional[list[TeamScoreHistory]]:
        # todo
        return None

    @classmethod
    async def get_me(cls, ctx: PlatformCTX) -> Optional[Team]:
        # todo
        return None

    @classmethod
    async def register(cls, ctx: PlatformCTX) -> RegistrationStatus:
        # todo
        return RegistrationStatus(success=False, message="Unsupported")

    @classmethod
    async def pull_challenge_solvers(
        cls, ctx: PlatformCTX, challenge_id: str, limit: int = 10
    ) -> AsyncIterator[ChallengeSolver]:
        # todo
        for x in []:
            yield x

    @classmethod
    async def get_challenge(
        cls, ctx: PlatformCTX, challenge_id: str
    ) -> Optional[Challenge]:
        """Retrieve a challenge from the rCTF platform.

        Args:
            ctx: Platform context.
            challenge_id: Challenge identifier.

        Returns:
            Parsed challenge.

        Notes:
            Because rCTF doesn't have an API endpoint for fetching a single challenge
            at a time, we need to request all challenges using the `/api/v1/challs`
            endpoint and loop through them in order to fetch a specific challenge.
        """

        # Iterate over unsolved challenges
        async for challenge in cls.pull_challenges(ctx):
            # Compare challenge IDs
            if challenge.id != challenge_id:
                continue

            return challenge

        # Obtain our team object
        our_team: Team = await cls.get_me(ctx)
        if our_team is None:
            return None

        # Iterate over solved challenges
        for challenge in our_team.solves or []:
            # Compare challenge IDs
            if challenge.id != challenge_id:
                continue

            return challenge

        return None

    @classmethod
    async def get_hint(cls, ctx: PlatformCTX, hint_id: str) -> Optional[ChallengeHint]:
        # No hints on traboda
        return None

    @classmethod
    async def unlock_hint(cls, ctx: PlatformCTX, hint_id: str) -> bool:
        # No hints on traboda
        return False