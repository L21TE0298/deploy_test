package com.ghostappi.backend.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "trainingroutineexcercise")
@IdClass(TrainingRoutineExcercisePK.class)
public class TrainingRoutineExcercise {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "idTrainingRoutine")
    @JsonBackReference
    @JsonIgnore
    private TrainingRoutine trainingRoutine;

    @Id
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "idExcercise", referencedColumnName = "idExcercise")
    private Excercise excercise;

    @Positive(message = "The sets number must be a positive number")
    @Min(value = 1, message = "The series number min value is 1")
    @Max(value = 100, message = "The series number max value is 100")
    @NotNull(message = "The series number must contain at least one digit")
    @Column(name = "sets")
    private Byte sets;

    @Positive(message = "The repetitions number must be a positive number")
    @Min(value = 1, message = "The repetitions number min value is 1")
    @Max(value = 100, message = "The repetitions number max value is 100")
    @NotNull(message = "The repetitions number must contain at least one digit")
    @Column(name = "reps")
    private Byte reps;

}
