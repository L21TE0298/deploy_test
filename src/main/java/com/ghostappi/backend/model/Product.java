package com.ghostappi.backend.model;

import java.math.BigDecimal;
import java.sql.Date;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "product")
public class Product {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idProduct")
    @JsonProperty("idProduct")
    private Integer idProduct;

    @JsonProperty("comercialName")
    @Column(nullable = false, length = 250)
    @NotBlank(message = "The commercial name must not be null and must contain at least one character.")
    @Size(min = 1, max = 250, message = "The commercial name must be between 1 and 250 characters.")
    private String comercialName;

    @JsonProperty("price")
    @Column(nullable = false)
    @NotNull(message = "The price cannot be null.")
    @DecimalMin(value = "0.01", message = "The price must be at least 0.01.")
    @DecimalMax(value = "999999.99", message = "The price must not exceed 999,999.99.")
    private BigDecimal price;

    @JsonProperty("stock")
    @Column(nullable = false)
    @NotNull(message = "The stock cannot be null.")
    @Min(value = 0, message = "The stock must be at least 0.")
    @Max(value = 32767, message = "The stock must not exceed 32,767.") // Máximo para SHORT
    private Short stock;

    @JsonProperty("servingSize")
    @Column(nullable = false)
    @NotNull(message = "The serving size cannot be null.")
    @Min(value = 0, message = "The serving size must be at least 0.")
    @Max(value = 2147483647, message = "The serving size must not exceed 2,147,483,647.") // Máximo para INTEGER
    private Integer servingSize;

    @JsonProperty("unitServingSize")
    @Column(nullable = false, length = 8)
    @NotBlank(message = "The unit serving size cannot be null or empty.")
    @Size(min = 1, max = 8, message = "The unit serving size must be between 1 and 8 characters.")
    private String unitServingSize;

    @JsonProperty("servings")
    @Column(nullable = false)
    @NotNull(message = "The number of servings cannot be null.")
    @Min(value = 0, message = "The number of servings must be at least 0.")
    @Max(value = 32767, message = "The number of servings must not exceed 32,767.") // Máximo para SHORT
    private Short servings;

    @JsonProperty("netContent")
    @Column(nullable = false)
    @NotNull(message = "The net content cannot be null.")
    @Min(value = 0, message = "The net content must be at least 0.")
    @Max(value = 32767, message = "The net content must not exceed 32,767.") // Máximo para SHORT
    private Short netContent;

    @JsonProperty("unitNetContent")
    @Column(nullable = false, length = 8)
    @NotBlank(message = "The unit net content cannot be null or empty.")
    @Size(min = 1, max = 8, message = "The unit net content must be between 1 and 8 characters.")
    private String unitNetContent;

    @JsonProperty("presentation")
    @Column(nullable = false, length = 50)
    @NotBlank(message = "The presentation cannot be null or empty.")
    @Size(min = 1, max = 50, message = "The presentation must be between 1 and 50 characters.")
    private String presentation;

    @JsonProperty("description")
    @Column(nullable = false, length = 500)
    @NotBlank(message = "The description cannot be null or empty.")
    @Size(min = 1, max = 500, message = "The description must be between 1 and 500 characters.")
    private String description;

    @JsonProperty("caducity")
    @Column(nullable = false)
    @NotNull(message = "The caducity date cannot be null.")
    private Date caducity;

    @JsonProperty("lote")
    @Column(nullable = false, length = 25)
    @NotBlank(message = "The lot number cannot be null or empty.")
    @Size(min = 1, max = 25, message = "The lot number must be between 1 and 25 characters.")
    private String lote;

    @JsonProperty("flavor")
    @Column(nullable = false, length = 100)
    @NotBlank(message = "The flavor cannot be null or empty.")
    @Size(min = 1, max = 100, message = "The flavor must be between 1 and 100 characters.")
    private String flavor;

    @JsonProperty("productRecomendation")
    @Column(nullable = false, length = 255)
    @NotBlank(message = "The product recommendation cannot be null or empty.")
    @Size(min = 1, max = 255, message = "The product recommendation must be between 1 and 255 characters.")
    private String productRecomendation;

    @JsonProperty("imgProductPath")
    @Column(nullable = false, length = 255)
    @NotBlank(message = "The image path cannot be null or empty.")
    @Size(min = 1, max = 255, message = "The image path must be between 1 and 255 characters.")
    private String imgProductPath;

    @JsonProperty("idCategory")
    @Column(nullable = false)
    @NotNull(message = "The category ID cannot be null.")
    @Min(value = 1, message = "The category ID must be at least 1.")
    @Max(value = 2147483647, message = "The category ID must not exceed 2,147,483,647.") // Máximo para INTEGER
    private Integer idCategory;

    @JsonProperty("idBrand")
    @Column(nullable = false)
    @NotNull(message = "The brand ID cannot be null.")
    @Min(value = 1, message = "The brand ID must be at least 1.")
    @Max(value = 2147483647, message = "The brand ID must not exceed 2,147,483,647.") // Máximo para INTEGER
    private Integer idBrand;

    @JsonProperty("idAdministrationVia")
    @Column(nullable = false)
    @NotNull(message = "The administration ID cannot be null.")
    @Min(value = 1, message = "The administration ID must be at least 1.")
    @Max(value = 2147483647, message = "The administration ID must not exceed 2,147,483,647.") // Máximo para INTEGER
    private Integer idAdministrationVia;

    @JsonManagedReference
    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<NutrientProduct> nutrientProducts;
}
