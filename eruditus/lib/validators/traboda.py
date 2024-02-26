from datetime import datetime
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel


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


class ChallengeSolver(BaseModel):
    class Contestant(BaseModel):
        id: str
        name: str
        username: str
        avatarID: Optional[str]
        avatarURL: Optional[str]

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
