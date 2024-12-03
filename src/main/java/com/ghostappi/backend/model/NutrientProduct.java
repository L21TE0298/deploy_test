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
@Table(name = "nutrientproduct")
@IdClass(NutrientProductPK.class)

public class NutrientProduct {

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "idproduct")
    @JsonBackReference
    @JsonIgnore
    private Product product;

    @Id
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "idNutrient", referencedColumnName = "idNutrient")
    private Nutrient nutrient;

    @Positive(message = "Quantity number must be a positive number")
    @Min(value = 1, message = "The quantity number min value is 1")
    @Max(value = 999999999, message = "The quantity number max value is 999999999")
    @NotNull(message = "The quantity number must contain at least one digit")
    @Column(name = "quantity")
    private double quantity;

    @Positive(message = "Percentage must be a positive number")
    @Min(value = 1, message = "The percentage min value is 1")
    @Max(value = 100, message = "The percentage number max value is 100")
    @NotNull(message = "The percentage must contain at least one digit")
    @Column(name = "daily_value_percentage")
    private Short percentage;

}
