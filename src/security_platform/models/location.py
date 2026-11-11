from pydantic import BaseModel, Field, model_validator


class SourceLocation(BaseModel):
    file_path: str = Field(..., description="Path relative to the repository root")
    start_line: int = Field(..., gt=0)
    end_line: int = Field(..., gt=0)
    start_column: int | None = Field(default=None, gt=0)
    end_column: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_line_order(self) -> "SourceLocation":
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")

        if self.start_line == self.end_line and self.start_column and self.end_column:
            if self.end_column < self.start_column:
                raise ValueError("end_column must be greater than start_column on the same line")

        return self
