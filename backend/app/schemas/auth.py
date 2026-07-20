"""Auth schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    email: str | None = None
    role: str = Field(default="operator", pattern="^(admin|operator|viewer)$")


class UserLogin(BaseModel):
    username: str
    password: str


class UserUpdate(BaseModel):
    email: str | None = None
    role: str | None = Field(default=None, pattern="^(admin|operator|viewer)$")
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)


class UserOut(BaseModel):
    id: str
    username: str
    email: str | None
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class AuthStatusOut(BaseModel):
    auth_enabled: bool
    user: UserOut | None = None
