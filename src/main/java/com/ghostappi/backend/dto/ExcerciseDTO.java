package com.ghostappi.backend.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
public class ExcerciseDTO {

    private Integer idExercise;
    @NotBlank(message = "The name must no be null and containt at least one character")
    @Size(min = 1, max = 100, message = "The name must be almost 1 character and 100 characters at most")
    private String name;
     @NotBlank(message = "The difficulty must no be null and containt at least one character")
    @Size(min = 1, max = 50, message = "The difficulty must be almost 1 character and 50 characters at most")
    private String difficulty;
    @NotNull(message = "The field reps must be contain min one character")
    @Positive(message = "Reps must be a positive number")
    @Min(value = 1, message = "The reps number min value is 1")
    @Max(value = 255, message = "The reps number max value is 255")
    private Byte reps;
    @NotNull(message = "The field sets must be contain min one character")
    @Positive(message = "Sets must be a positive number")
    @Min(value = 1, message = "The sets number min value is 1")
    @Max(value = 255, message = "The sets number max value is 255")
    private Byte sets;

    public Byte getReps() {
        return reps;
    }

    public void setReps(Byte reps) {
        this.reps = reps;
    }

    public Byte getSets() {
        return sets;
    }

    public void setSets(Byte sets) {
        this.sets = sets;
    }

    public Integer getIdExercise() {
        return idExercise;
    }

    public void setIdExercise(Integer idExercise) {
        this.idExercise = idExercise;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDifficulty() {
        return difficulty;
    }

    public void setDifficulty(String difficulty) {
        this.difficulty = difficulty;
    }
}
