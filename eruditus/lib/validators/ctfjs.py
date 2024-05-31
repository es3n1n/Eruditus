from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from lib.platforms.abc import (
    Challenge,
    ChallengeHint,
    ChallengeSolver,
    SolvedChallenge,
    Team,
)


class Competition(BaseModel):
    id: int
    created: datetime
    name: str
    about: str
    start: datetime
    end: datetime
    teamSize: int


class AuthResponse(BaseModel):
    token: str


class SubmissionResponse(BaseModel):
    message: str | None = None  # error message
    correct: bool = False


class ChallengeMin(BaseModel):
    id: int
    title: str
    category: str
    value: int
    author: str


class ChallengeItem(ChallengeMin):
    description: str
    hint: str | None = None
    solves: int

    def convert(self, me: Optional[Team] = None) -> Challenge:
        solves = []
        if me is not None:
            solves = me.solves or []
        return Challenge(
            id=str(self.id),
            name=self.title,
            category=self.category,
            description=self.description,
            value=self.value,
            solves=self.solves,
            solved_by_me=str(self.id) in [x.id for x in solves],
            hints=[ChallengeHint(id="", content=self.hint, is_locked=False)]
            if self.hint is not None
            else None,
        )


class TeamMin(BaseModel):
    id: int
    name: str
    affiliation: str | None = None

    def convert(self) -> Team:
        return Team(
            id=str(self.id),
            name=self.name,
        )


class TeamItem(TeamMin):
    created: datetime
    eligible: bool
    score: int
    lastSolve: datetime | None = None

    def convert(self) -> Team:
        return Team(
            id=str(self.id),
            name=self.name,
            score=self.score,
        )


class UserMin(BaseModel):
    id: int
    username: str


class User(UserMin):
    eligible: bool
    created: datetime


class SolveEntry(BaseModel):
    id: int
    time: datetime
    challenge: ChallengeMin
    user: UserMin

    def convert(self) -> SolvedChallenge:
        return SolvedChallenge(
            id=str(self.challenge.id),
            name=self.challenge.title,
            category=self.challenge.category,
            description="",
            value=self.challenge.value,
            solved_at=self.time,
        )


class ChallengeResponse(ChallengeMin):
    class Solve(BaseModel):
        id: int
        time: datetime
        user: UserMin
        team: TeamMin

    description: str
    hint: str | None = None
    solves: list[Solve]

    def convert(self, me: Team | None = None) -> Challenge:
        return Challenge(
            id=str(self.id),
            name=self.title,
            category=self.category,
            description=self.description,
            value=self.value,
            solved_by_me=(str(self.id) in [x.id for x in me.solves])
            if me is not None
            else False,
            solved_by=[
                ChallengeSolver(team=x.team.convert(), solved_at=x.time)
                for x in self.solves
            ],
            hints=[ChallengeHint(id="", content=self.hint, is_locked=False)]
            if self.hint is not None
            else None,
        )


class TeamResponse(BaseModel):
    id: int
    created: datetime
    name: str
    affiliation: str | None = None
    solves: list[SolveEntry]
    members: list[User]
    eligible: bool

    def convert(self) -> Team:
        return Team(
            id=str(self.id),
            name=self.name,
            score=sum(x.challenge.value for x in self.solves),
            solves=[x.convert() for x in self.solves],
        )


class UserMax(User):
    team: TeamResponse | None = None


class SelfResponse(BaseModel):
    user: UserMax
    competition: Competition
