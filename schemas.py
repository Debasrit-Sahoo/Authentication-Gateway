from pydantic import BaseModel, StringConstraints
from typing_extensions import Annotated

class LoginRequest(BaseModel):
    username: Annotated[str, StringConstraints(min_length=3, max_length=32, strip_whitespace=True)]
    password: Annotated[str, StringConstraints(min_length=8)]