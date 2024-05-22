import io
import json.decoder
from typing import Any, AsyncIterator

import aiohttp

from config import USER_AGENT
from lib.platforms.abc import (
    Challenge,
    ChallengeHint,
    ChallengeSolver,
    Optional,
    PlatformABC,
    PlatformCTX,
    RegistrationStatus,
    Session,
    SubmittedFlag,
    SubmittedFlagState,
    Team,
    TeamScoreHistory,
)
from lib.util import deserialize_response, substitute_base_url
from lib.validators.ctfjs import (
    AuthResponse,
    ChallengeItem,
    ChallengeResponse,
    Competition,
    SelfResponse,
    SubmissionResponse,
    TeamItem,
    TeamResponse,
)


def generate_headers(ctx: PlatformCTX) -> dict[str, str]:
    if not ctx.session or not ctx.session.validate():
        return {}

    return {
        "Authorization": f"Token {ctx.session.token}",
        "User-Agent": USER_AGENT(),
    }


class CTFJs(PlatformABC):
    name = "ctfjs"

    @classmethod
    async def match_platform(cls, ctx: PlatformCTX) -> bool:
        """Check whether a website is using the ctfjs framework.

        Args:
            ctx: Platform context.

        Returns:
            True if the platform is using ctfjs, else False.
        """

        async def try_match(url_to_req: str) -> bool:
            try:
                async with aiohttp.request(
                    method="get",
                    url=f"{url_to_req}/competitions/",
                    headers={"User-Agent": USER_AGENT()},
                ) as response:
                    if response.status != 200:
                        return False

                    content_type: str = response.headers.get("content-type", "text")
                    if "application/json" not in content_type:
                        return False

                    if response.headers.get("x-powered-by", "Express") != "Express":
                        return False

                    response_json: list[dict[str, Any]] = await response.json()
                    if not isinstance(response_json, list):
                        return False

                    # Match a competition object if there is any
                    if len(response_json) > 0:
                        first_competition = response_json[0]
                        if not isinstance(first_competition, dict):
                            return False

                        return not any(
                            x not in first_competition
                            for x in ["name", "about", "start", "end", "teamSize"]
                        )

                    # :fingers_crossed:
                    return True
            except (aiohttp.ClientError, json.decoder.JSONDecodeError):
                return False

        matched: bool = False
        for url in substitute_base_url(ctx.url_stripped):
            matched = matched or await try_match(url)

            # Swap url if matched
            if matched:
                ctx.base_url = url
                break

        return matched

    @classmethod
    async def login(cls, ctx: PlatformCTX) -> Optional[Session]:
        if ctx.is_authorized():
            return ctx.session

        base_url: str = ctx.args.get("api_url", ctx.url_stripped).strip("/")

        # We are playing the last competition by default!
        async with aiohttp.request(
            method="get",
            url=f"{base_url}/competitions",
            headers={"User-Agent": USER_AGENT()},
        ) as response:
            competitions = await deserialize_response(response, model=list[Competition])
            if not competitions or len(competitions) == 0:
                return None

            competition_id: int = competitions[-1].id
            ctx.args["api_url"] = base_url
            ctx.base_url = f"{base_url}/competitions/{competition_id}/"
            ctx.args["competition_id"] = competition_id

        # Send authentication request
        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/auth",
            json={
                "username": ctx.args.get("username"),
                "password": ctx.args.get("password"),
            },
            headers={"User-Agent": USER_AGENT()},
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                return None

            # Validate and deserialize response
            data = await deserialize_response(response, model=AuthResponse)
            if not data:
                return None

            # Save the token
            return Session(token=data.token)

    @classmethod
    async def fetch(cls, ctx: PlatformCTX, url: str) -> Optional[io.BytesIO]:
        """Fetch a URL endpoint from the ctfjs platform and return its response.

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
            headers=generate_headers(ctx),
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
        # Authorize if needed
        if not await ctx.login(cls.login):
            return None

        # Send submission request
        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/challenges/{challenge_id}/submissions",
            json={"flag": flag},
            headers=generate_headers(ctx),
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(response, model=SubmissionResponse)
            if not data:
                return

            # Initialize result
            result: SubmittedFlag = SubmittedFlag(
                state=SubmittedFlagState.CORRECT
                if data.correct
                else SubmittedFlagState.INCORRECT
            )

            # Lookup table for flag submission states
            statuses: dict[str, SubmittedFlagState] = {
                "user_not_on_team": SubmittedFlagState.INVALID_USER,
                "challenge_not_found": SubmittedFlagState.INVALID_CHALLENGE,
                # they have 2 different errors smh
                "challenge not found": SubmittedFlagState.INVALID_CHALLENGE,
                "challenge_already_solved": SubmittedFlagState.ALREADY_SUBMITTED,
                "invalid_values": SubmittedFlagState.INCORRECT,
            }
            if data.message is not None:
                result.state = statuses[data.message]

            # Update `is_first_blood` if state is correct
            await result.update_first_blood(
                ctx,
                cls.pull_challenge_solvers,
                cls.get_challenge,
                challenge_id,
                await cls.get_me(ctx),
            )

            return result

    @classmethod
    async def pull_challenges(cls, ctx: PlatformCTX) -> AsyncIterator[Challenge]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        async with aiohttp.request(
            method="get",
            url=f"{ctx.url_stripped}/challenges",
            headers=generate_headers(ctx),
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(response, model=list[ChallengeItem])
            if not data:
                return

            # Get a team object
            me = await cls.get_me(ctx)

            # Iterate over challenges and parse them
            for challenge in data:
                yield challenge.convert(me)

    @classmethod
    async def pull_scoreboard(
        cls, ctx: PlatformCTX, max_entries_count: int = 20
    ) -> AsyncIterator[Team]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        async with aiohttp.request(
            method="get",
            url=f"{ctx.url_stripped}/teams",
            params={"frozen": "1"},  # frozen - scores during the ctf
            headers=generate_headers(ctx),
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(response, model=list[TeamItem])
            if not data:
                return

            # Sort by score
            leaderboard = sorted(
                data,
                key=lambda x: (
                    -x.score,  # reverse order
                    x.lastSolve,
                ),
            )

            # Iterate over teams and parse them
            for team in leaderboard[:max_entries_count]:
                yield team.convert()

    @classmethod
    async def pull_scoreboard_datapoints(
        cls, ctx: PlatformCTX, count: int = 10
    ) -> Optional[list[TeamScoreHistory]]:
        """Get scoreboard data points for the top teams.

        Args:
            ctx: Platform context.
            count: Number of teams to fetch.

        Returns:
            A list where each element is a struct containing:
                - The team name (used as the label in the graph).
                - The timestamps of each solve (as `datetime` objects, these will fill
                  the x axis).
                - The number of accumulated points after each new solve (these will
                  fill the y axis).
        """
        if not await ctx.login(cls.login):
            return

        me = await cls.get_me(ctx)

        graphs: list[TeamScoreHistory] = []
        async for team in cls.pull_scoreboard(ctx, count):
            entry = TeamScoreHistory(
                name=team.name,
                is_me=team.id == me.id if me is not None else False,
            )

            async with aiohttp.request(
                method="get",
                url=f"{ctx.url_stripped}/teams/{team.id}",
                headers=generate_headers(ctx),
            ) as response:
                data = await deserialize_response(response, model=TeamResponse)
                if not data:
                    return

                total_pts: int = 0
                for solve in sorted(data.solves, key=lambda x: x.time):
                    total_pts += solve.challenge.value
                    entry.history.append(
                        TeamScoreHistory.HistoryItem(
                            time=solve.time,
                            score=total_pts,
                        )
                    )

            graphs.append(entry)

        return graphs

    @classmethod
    async def get_me(cls, ctx: PlatformCTX) -> Optional[Team]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return None

        async with aiohttp.request(
            method="get",
            url=f"{ctx.args['api_url']}/self",
            headers=generate_headers(ctx),
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(response, model=SelfResponse)
            if not data or not data.user.team:
                return

            # Parse as a team
            return data.user.team.convert()

    @classmethod
    async def register(cls, ctx: PlatformCTX) -> RegistrationStatus:
        return RegistrationStatus(
            success=False, message="ctfjs registration is unsupported due to recaptcha"
        )

    @classmethod
    async def pull_challenge_solvers(
        cls, ctx: PlatformCTX, challenge_id: str, limit: int = 10
    ) -> AsyncIterator[ChallengeSolver]:
        challenge = await cls.get_challenge(ctx, challenge_id)
        if not challenge:
            return

        for solver in (challenge.solved_by or [])[:limit]:
            yield solver

    @classmethod
    async def get_challenge(
        cls, ctx: PlatformCTX, challenge_id: str
    ) -> Optional[Challenge]:
        """Retrieve a challenge from the ctfjs platform.

        Args:
            ctx: Platform context.
            challenge_id: Challenge identifier.

        Returns:
            Parsed challenge.
        """
        async with aiohttp.request(
            method="get",
            url=f"{ctx.url_stripped}/challenges/{challenge_id}",
            headers=generate_headers(ctx),
        ) as response:
            data = await deserialize_response(response, model=ChallengeResponse)
            if not data:
                return None

            return data.convert(await cls.get_me(ctx))

    @classmethod
    async def get_hint(cls, ctx: PlatformCTX, hint_id: str) -> Optional[ChallengeHint]:
        # Hints are working on a weirder way on ctfjs
        return None

    @classmethod
    async def unlock_hint(cls, ctx: PlatformCTX, hint_id: str) -> bool:
        # Hints are working on a weirder way on ctfjs
        return False
