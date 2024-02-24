from typing import Any
from typing import List
from typing import Optional

from pydantic import BaseModel


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


class ChallengesData(BaseModel):
    class Challenge(BaseModel):
        id: Any
        name: str
        points: int
        solveStatus: Any
        difficulty: Any
        category: Category

    challenges: List[Challenge]


class GetChallengesResponse(BaseModel):
    data: Optional[ChallengesData]
