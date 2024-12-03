package com.ghostappi.backend.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;

@Entity
public class Reward {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idReward;

    @NotNull(message = "The product ID cannot be null.")
    @Min(value = 1, message = "The product ID must be at least 1.")
    @Max(value = 2147483647, message = "The product ID must not exceed 2,147,483,647.")
    @Column(name = "idProduct", nullable = false)
    private Integer productId;

    @NotNull(message = "The goal points cannot be null.")
    @Min(value = 1, message = "The goal points must be at least 1.")
    @Max(value = 2147483647, message = "The goal points must not exceed 2,147,483,647.")
    private Integer goalPoints;

    @NotBlank(message = "The description must not be null or empty.")
    @Size(min = 1, max = 255, message = "The description must be between 1 and 255 characters.")
    private String description;

    public Reward() {
    }

    public Integer getIdReward() {
        return idReward;
    }

    public void setIdReward(Integer idReward) {
        this.idReward = idReward;
    }

    public Integer getGoalPoints() {
        return goalPoints;
    }

    public void setGoalPoints(Integer goalPoints) {
        this.goalPoints = goalPoints;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @JsonProperty("idProduct")
    public Integer getProductId() {
        return productId;
    }

    public void setProductId(Integer productId) {
        this.productId = productId;
    }

    @Override
    public String toString() {
        return "Reward [idReward=" + idReward + ", goalPoints=" + goalPoints + ", description=" + description
                + ", productId=" + productId + "]";
    }
}
