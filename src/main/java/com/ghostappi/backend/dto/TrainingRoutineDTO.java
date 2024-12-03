package com.ghostappi.backend.dto;

import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TrainingRoutineDTO {

    @NotBlank(message = "The routineName must no be null and contain at least one character")
    @Size(min = 1, max = 255)
    private String routineName;

    @NotNull(message = "The date must no be null")
    @JsonProperty("registrationDate")
    private Date registrationDate;

    @Positive(message = "idUser must be a positive number")
    @NotNull(message = "idUser must no be null")
    @Min(value = 1, message = "The idUser must be at least 1.")
    @Max(value = 2147483647, message = "The idUser must be at most 2147483647.")
    private Integer idUser;

    @NotNull(message = "The trainingRoutineExcercises must not be null.")
    private List<TrainingRoutineExcerciseDTO> trainingRoutineExcercises;
}
