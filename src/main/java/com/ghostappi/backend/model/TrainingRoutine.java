package com.ghostappi.backend.model;

import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "trainingroutine")
public class TrainingRoutine {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idTrainingRoutine")
    @JsonProperty("idTrainingRoutine")
    private Integer idTrainingRoutine;

    
    @NotBlank(message = "The routineName must no be null and contain at least one character")
    @Size(min = 1, max = 255)
    @Column(name = "routineName", nullable = false)
    @JsonProperty("routineName")
    private String routineName;

    @NotNull(message = "The date must no be null")
    @Column(name = "registrationDate", nullable = false)
    @JsonProperty("registrationDate")
    private Date registrationDate;

    @NotNull(message = "idUser must no be null")
    @Column(name = "idUser", nullable = false)
    @JsonProperty("idUser")
    private Integer idUser;


    @JsonManagedReference
    @OneToMany(mappedBy = "trainingRoutine", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<TrainingRoutineExcercise> trainingRoutineExcercises;
}
