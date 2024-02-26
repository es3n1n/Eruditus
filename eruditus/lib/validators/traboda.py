from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel

from lib.platforms.abc import Team


class BaseError(BaseModel):
    message: str
    locations: list[Any]
    path: list[Any]


class LoginData(BaseModel):
    id: int
    username: str
    name: str
    type: str


class LoginResponse(BaseModel):
    class Data(BaseModel):
        login: Optional[LoginData]

    data: Data


class Category(BaseModel):
    id: Any
    name: str
    slug: Any


class ESolveStatus(Enum):
    UNATTEMPTED = "UNATTEMPTED"
    SOLVED = "SOLVED"


class ChallengesData(BaseModel):
    class Challenge(BaseModel):
        class Difficulty(BaseModel):
            label: str
            level: int

        class SolveStatus(BaseModel):
            label: ESolveStatus

            @property
            def is_solved(self) -> bool:
                return self.label == ESolveStatus.SOLVED

        id: str
        name: str
        points: int
        solveStatus: SolveStatus
        difficulty: Difficulty
        category: Category

    hasNext: bool
    lastCursor: str
    challenges: List[Challenge]


class GetChallengesResponse(BaseModel):
    class Data(BaseModel):
        challenges: Optional[ChallengesData]

    data: Optional[Data]


class GetAttachmentResponse(BaseModel):
    class Data(BaseModel):
        getAttachmentUrl: Optional[str] = None

    data: Optional[Data]


class SubmitFlag(BaseModel):
    isAccepted: bool
    isLogged: bool
    isDuplicate: bool
    points: Optional[int]
    attemptsLeft: Optional[int]
    explanation: Optional[Any]


class SubmitFlagResponse(BaseModel):
    class Data(BaseModel):
        submitFlag: Optional[SubmitFlag]

    data: Optional[Data]
    error: Optional[BaseError] = None


class Contestant(BaseModel):
    id: str
    name: str
    username: str
    avatarID: Optional[str]
    avatarURL: Optional[str]

    def convert(self) -> Team:
        return Team(id=self.id, name=self.name, username=self.username)


class ChallengeSolver(BaseModel):
    contestant: Contestant
    timestamp: datetime
    points: int


class ChallengeSolversResponse(BaseModel):
    class Data(BaseModel):
        class Challenge(BaseModel):
            class Stats(BaseModel):
                class Submissions(BaseModel):
                    submissions: list[ChallengeSolver]

                submissions: Submissions

            stats: Stats

        challenge: Challenge

    data: Optional[Data]


class ScoreboardEntry(BaseModel):
    rank: int
    points: int
    lastSubmission: Optional[Any]
    firstBloods: Optional[Any]
    secondBloods: Optional[Any]
    thirdBloods: Optional[Any]
    grade: Optional[Any]
    flagsSubmitted: Optional[int]
    answersSubmitted: Optional[int]
    completion: Optional[Any]
    challenges: Optional[list[Any]]
    contestant: Contestant


class ScoreboardResponse(BaseModel):
    class Data(BaseModel):
        class Scoreboard(BaseModel):
            totalCount: int
            hasNext: bool
            scores: list[ScoreboardEntry]

        scoreboard: Scoreboard

    data: Optional[Data]


class DataPointsResponse(BaseModel):
    class Data(BaseModel):
        class Contest(BaseModel):
            class Stats(BaseModel):
                class Participant(BaseModel):
                    # { team: { datetime: points, datetime: points, ... }, ... }
                    topScorersGraph: dict[str, dict[datetime, int]]

                participant: Participant

            stats: Stats

        contest: Contest

    data: Optional[Data]
