package com.ghostappi.backend.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Entity
public class Points {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Integer idPoints;
    @NotNull(message = "Accumulated points cannot be null")
    @Positive(message = "Accumulated points must be a positive integer")
    @Min(value = 1, message = "Accumulated points must be at least 1")
    private Integer accumulatedPoints;
    @NotNull(message = "User ID cannot be null")
    @Positive(message = "User ID must be a positive integer")
    @Column(name = "idUser", nullable = false)
    private Integer userId;

    public Integer getIdPoints() {
        return idPoints;
    }

    public void setIdPoints(Integer idPoints) {
        this.idPoints = idPoints;
    }

    public Integer getAccumulatedPoints() {
        return accumulatedPoints;
    }

    public void setAccumulatedPoints(Integer accumulatedPoints) {
        this.accumulatedPoints = accumulatedPoints;
    }

    @JsonProperty("idUser")
    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    @Override
    public String toString() {
        return "Points [idPoints=" + idPoints + ", accumulatedPoints=" + accumulatedPoints + ", userId=" + userId + "]";
    }

}