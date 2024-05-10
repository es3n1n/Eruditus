import io
import re
from json import JSONDecodeError, loads
from typing import AsyncIterator

import aiohttp

from lib.platforms.abc import (
    Challenge,
    ChallengeFile,
    ChallengeHint,
    ChallengeSolver,
    Optional,
    PlatformABC,
    PlatformCTX,
    RegistrationStatus,
    Retries,
    Session,
    SubmittedFlag,
    SubmittedFlagState,
    Team,
    TeamScoreHistory,
)
from lib.util import deserialize_response
from lib.validators import traboda


class Traboda(PlatformABC):
    name = "Traboda"

    @classmethod
    async def match_platform(cls, ctx: PlatformCTX) -> bool:
        """Check whether a website is using the Traboda framework.

        Args:
            ctx: Platform context.

        Returns:
            True if the platform is using Traboda, else False.

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
                "query": "mutation ($username: String!, $password: String!) { login(use"
                "rname: $username, password: $password) { id username name type } }",
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
        """Fetch a URL endpoint from the Traboda platform and return its response.

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
    async def extract_next_data(cls, ctx: PlatformCTX, url: str) -> Optional[dict]:
        content = await cls.fetch(ctx, url)
        if not content:
            return None

        content_str: str = content.read().decode("utf-8")
        matched = re.search(
            r'<script\s+id="__NEXT_DATA__"\s+type="application/json">(\{.*?})</script>',
            content_str,
        )
        if not matched:
            return None

        try:
            return loads(matched.group(1))
        except JSONDecodeError:
            return None

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
            url=f"{ctx.url_stripped}/api/graphql/",
            json={
                "query": "mutation ($challengeID: ID!, $flag: String!){submitFlag(chall"
                "engeID:$challengeID,flag:$flag){isAccepted isLogged isDuplicate points"
                " attemptsLeft explanation}}",
                "variables": {"challengeID": challenge_id, "flag": flag},
            },
            cookies=ctx.session.cookies,
        ) as response:
            # Validate and deserialize response
            data = await deserialize_response(
                response, model=traboda.SubmitFlagResponse
            )

            # Initialize result
            result: SubmittedFlag = SubmittedFlag(state=SubmittedFlagState.UNKNOWN)

            # Something went wrong
            if not data or not data.data or not data.data.submitFlag:
                # Treat this error as invalid flag
                if (
                    data
                    and data.error
                    and data.error.message == "Flag value is too short"
                ):
                    result.state = SubmittedFlagState.INCORRECT
                return result

            # Flag accepted! yay
            result.state = SubmittedFlagState.INCORRECT
            if data.data.submitFlag.isAccepted:
                result.state = SubmittedFlagState.CORRECT

            # Merge retries left, if needed
            if data.data.submitFlag.attemptsLeft is not None:
                result.retries = Retries(left=data.data.submitFlag.attemptsLeft)

            # Update first blood state
            await result.update_first_blood(
                ctx,
                cls.pull_challenge_solvers,
                cls.get_challenge,
                challenge_id,
                await cls.get_me(ctx),
            )

            # We are done here
            return result

    @classmethod
    async def pull_challenges(cls, ctx: PlatformCTX) -> AsyncIterator[Challenge]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        after = None
        has_next = True

        while has_next:
            async with aiohttp.request(
                method="post",
                url=f"{ctx.url_stripped}/api/graphql/",
                json={
                    "query": "query($after:String,$keyword:String,$filters:ChallengeFil"
                    "terInput,$sort:ChallengeSortInput){challenges(after:$after,keyword"
                    ":$keyword,filters:$filters,sort:$sort){hasNext lastCursor challeng"
                    "es{id name points solveStatus{label}difficulty{label level}categor"
                    "y{id name slug}}}}",
                    "variables": {
                        "keyword": None,
                        "filters": {
                            "categoryID": None,
                            "tag": None,
                            "difficultyLevel": None,
                            "solveStatus": None,
                        },
                        "sort": None,
                        "after": after,
                    },
                },
                cookies=ctx.session.cookies,
            ) as response:
                # Validate and deserialize response
                data = await deserialize_response(
                    response, model=traboda.GetChallengesResponse
                )
                if not data or not data.data or not data.data.challenges:
                    return

                # Iterate over challenges and parse them
                for challenge in data.data.challenges.challenges:
                    # Extracting next page data (some challenge info is stored there :/)
                    next_data = await cls.extract_next_data(
                        ctx, f"{ctx.url_stripped}/challenge/{challenge.id}"
                    )
                    if not next_data:
                        continue

                    # Extract challenge data
                    challenge_next_data: Optional[dict] = (
                        next_data.get("props", {})
                        .get("pageProps", {})
                        .get("challenge", None)
                    )
                    if (
                        not challenge_next_data
                        or "description" not in challenge_next_data
                        or "attachments" not in challenge_next_data
                    ):
                        continue

                    files = list()
                    for attachment in challenge_next_data["attachments"] or []:
                        async with aiohttp.request(
                            method="post",
                            url=f"{ctx.url_stripped}/api/graphql/",
                            json={
                                "query": "query($id:ID!,$challengeID:ID!){getAttachment"
                                "Url(id:$id,challengeID:$challengeID)}",
                                "variables": {
                                    "challengeID": str(challenge.id),
                                    "id": str(attachment["id"]),
                                },
                            },
                            cookies=ctx.session.cookies,
                        ) as attachment_response:
                            attachment_data = await deserialize_response(
                                attachment_response, model=traboda.GetAttachmentResponse
                            )
                            if (
                                not attachment_data
                                or not attachment_data.data
                                or not attachment_data.data.getAttachmentUrl
                            ):
                                continue

                            files.append(
                                ChallengeFile(
                                    url=attachment_data.data.getAttachmentUrl,
                                    name=attachment["name"],
                                )
                            )

                    yield Challenge(
                        id=str(challenge.id),
                        name=challenge.name,
                        category=challenge.category.name,
                        value=challenge.points,
                        description=challenge_next_data["description"],
                        solved_by_me=challenge.solveStatus.is_solved,
                        files=files,
                        hints=[
                            ChallengeHint(
                                id=hint["id"],
                                cost=hint["points"],
                                content=hint["content"],
                            )
                            for hint in (challenge_next_data["hints"] or [])
                        ],
                    )

                after = data.data.challenges.lastCursor
                has_next = data.data.challenges.hasNext

    @classmethod
    async def pull_scoreboard(
        cls, ctx: PlatformCTX, max_entries_count: int = 20
    ) -> AsyncIterator[Team]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        # Send submission request
        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/api/graphql/",
            json={
                "query": "query($count:Int,$keyword:String,$offset:Int,$filters:Scorebo"
                "ardFilterInput,$sort:ScoreboardSortInput){scoreboard(offset:$offset,fi"
                "lters:$filters,sort:$sort,count:$count,keyword:$keyword){totalCount ha"
                "sNext scores{rank points lastSubmission firstBloods secondBloods third"
                "Bloods grade{score grade }flagsSubmitted answersSubmitted completion{p"
                "ercent total completed}challenges{challengeID status blood}contestant{"
                "id avatarURL avatarID username name type}}myScore{rank points lastSubm"
                "ission firstBloods secondBloods thirdBloods grade{ score grade}flagsSu"
                "bmitted answersSubmitted completion{percent total completed}challenges"
                "{challengeID status blood}contestant{id avatarURL avatarID username na"
                "me type}}}}",
                "variables": {
                    "count": max_entries_count,
                    "filters": {
                        "affiliationID": None,
                        "categoryID": None,
                        "country": None,
                        "difficultyLevel": None,
                        "tagIDs": None,
                    },
                    "keyword": "",
                    "offset": 0,
                    "sort": {"order": "asc", "sort": "DEFAULT"},
                },
            },
            cookies=ctx.session.cookies,
        ) as response:
            # Deserialize response
            data = await deserialize_response(
                response, model=traboda.ScoreboardResponse
            )
            if not data or not data.data:
                return

            # Yield scoreboard entries
            for entry in data.data.scoreboard.scores:
                it = entry.contestant.convert()
                it.score = entry.points
                yield it

    @classmethod
    async def pull_scoreboard_datapoints(
        cls, ctx: PlatformCTX, count: int = 10
    ) -> Optional[list[TeamScoreHistory]]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        # Request datapoints
        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/api/graphql/",
            json={
                "query": "{contest{stats{participant{topScorersGraph}}}}",
                "variables": None,
            },
            cookies=ctx.session.cookies,
        ) as response:
            # Deserializing response
            data = await deserialize_response(
                response, model=traboda.DataPointsResponse
            )
            if not data or not data.data:
                return None

            # Get ourselves
            me = await cls.get_me(ctx)

            # Assembling score history
            result = list()
            for (
                team_name,
                team_score_history,
            ) in data.data.contest.stats.participant.topScorersGraph.items():
                result.append(
                    TeamScoreHistory(
                        name=team_name,
                        is_me=me and me.username == team_name,
                        history=[
                            TeamScoreHistory.HistoryItem(time=time, score=score)
                            for time, score in team_score_history.items()
                        ],
                    )
                )

            return result

    @classmethod
    async def get_me(cls, ctx: PlatformCTX) -> Optional[Team]:
        next_data = await cls.extract_next_data(ctx, f"{ctx.url_stripped}/profile")
        if not next_data:
            return None

        contestant: Optional[dict] = (
            next_data.get("props", {})
            .get("pageProps", {})
            .get("me", {})
            .get("contestant", None)
        )
        if not contestant:
            return None

        return Team(
            id=contestant["id"],
            name=contestant["name"],
            score=contestant["score"]["points"],
        )

    @classmethod
    async def register(cls, ctx: PlatformCTX) -> RegistrationStatus:
        # No registration on Traboda because we have to request email OTPs and such..
        return RegistrationStatus(success=False, message="Unsupported")

    @classmethod
    async def pull_challenge_solvers(
        cls, ctx: PlatformCTX, challenge_id: str, limit: int = 10
    ) -> AsyncIterator[ChallengeSolver]:
        # Authorize if needed
        if not await ctx.login(cls.login):
            return

        # Send submission request
        async with aiohttp.request(
            method="post",
            url=f"{ctx.url_stripped}/api/graphql/",
            json={
                "query": "query($id:ID!,$after:String,$isAccepted:Boolean,$keyword:Stri"
                "ng){ challenge(id: $id){stats{submissions(after:$after,isAccepted:$isA"
                "ccepted,keyword:$keyword){lastCursor hasNexttotalCount submissions{con"
                "testant{id name username avatarID avatarURL}timestamp points}}}}}",
                "variables": {
                    "after": None,
                    "id": challenge_id,
                    "isAccepted": True,
                    "keyword": "",
                },
            },
            cookies=ctx.session.cookies,
        ) as response:
            # Deserialize response
            data = await deserialize_response(
                response, model=traboda.ChallengeSolversResponse
            )
            if not data or not data.data:
                return

            # Iterating through solvers and returning them
            for solver in data.data.challenge.stats.submissions.submissions:
                yield ChallengeSolver(
                    team=solver.contestant.convert(),
                    solved_at=solver.timestamp,
                )

    @classmethod
    async def get_challenge(
        cls, ctx: PlatformCTX, challenge_id: str
    ) -> Optional[Challenge]:
        """Retrieve a challenge from the Traboda platform.

        Args:
            ctx: Platform context.
            challenge_id: Challenge identifier.

        Returns:
            Parsed challenge.

        Notes:
            Because Traboda doesn't have an API endpoint for fetching a single challenge
            at a time, we need to request all challenges and loop through them in order
            to fetch a specific challenge.
        """

        # Iterate over unsolved challenges
        async for challenge in cls.pull_challenges(ctx):
            # Compare challenge IDs
            if challenge.id != challenge_id:
                continue

            return challenge

        return None

    @classmethod
    async def get_hint(cls, ctx: PlatformCTX, hint_id: str) -> Optional[ChallengeHint]:
        # No hints unlock on traboda
        return None

    @classmethod
    async def unlock_hint(cls, ctx: PlatformCTX, hint_id: str) -> bool:
        # No hints unlock on traboda
        return False
