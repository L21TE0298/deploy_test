package com.ghostappi.backend.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TrainingRoutineExcerciseDTO {

    @Positive(message = "The excercise id must be a positive number")
    @Min(value = 1, message = "The excercise id min value is 1")
    @Max(value = 999999999, message = "The excercise id max value is 999999999")
    @NotNull(message = "The excercise id must contain at least one digit")
    private Integer idExcercise;

    @Positive(message = "The sets number must be a positive number")
    @Min(value = 1, message = "The series number min value is 1")
    @Max(value = 100, message = "The series number max value is 100")
    @NotNull(message = "The series number must contain at least one digit")
    private Byte sets;

    @Positive(message = "The repetitions number must be a positive number")
    @Min(value = 1, message = "The repetitions number min value is 1")
    @Max(value = 100, message = "The repetitions number max value is 100")
    @NotNull(message = "The repetitions number must contain at least one digit")
    private Byte reps;
}
