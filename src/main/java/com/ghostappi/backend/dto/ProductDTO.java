package com.ghostappi.backend.dto;

import java.math.BigDecimal;
import java.sql.Date;
import java.util.List;

import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProductDTO {

    @NotBlank(message = "The commercial name must not be null or empty.")
    @Size(min = 1, max = 250, message = "The commercial name must be between 1 and 250 characters.")
    private String comercialName;

    @NotNull(message = "The price cannot be null.")
    @DecimalMin(value = "0.01", message = "The price must be at least 0.01.")
    @DecimalMax(value = "999999.99", message = "The price must not exceed 999,999.99.")
    private BigDecimal price;

    @NotNull(message = "The stock cannot be null.")
    @Min(value = 0, message = "The stock must be at least 0.")
    @Max(value = 32767, message = "The stock must not exceed 32,767.")
    private Short stock;

    @NotNull(message = "The serving size cannot be null.")
    @Min(value = 0, message = "The serving size must be at least 0.")
    @Max(value = 2147483647, message = "The serving size must not exceed 2,147,483,647.")
    private Integer servingSize;

    @NotBlank(message = "The unit serving size cannot be null or empty.")
    @Size(min = 1, max = 8, message = "The unit serving size must be between 1 and 8 characters.")
    private String unitServingSize;

    @NotNull(message = "The number of servings cannot be null.")
    @Min(value = 0, message = "The number of servings must be at least 0.")
    @Max(value = 32767, message = "The number of servings must not exceed 32,767.")
    private Short servings;

    @NotBlank(message = "The product recommendation cannot be null or empty.")
    @Size(min = 1, max = 255, message = "The product recommendation must be between 1 and 255 characters.")
    private String productRecomendation;

    @NotBlank(message = "The image path cannot be null or empty.")
    @Size(min = 1, max = 255, message = "The image path must be between 1 and 255 characters.")
    private String imgProductPath;

    @NotNull(message = "The caducity date cannot be null.")
    private Date caducity;

    @NotBlank(message = "The flavor cannot be null or empty.")
    @Size(min = 1, max = 100, message = "The flavor must be between 1 and 100 characters.")
    private String flavor;

    @NotBlank(message = "The lot number cannot be null or empty.")
    @Size(min = 1, max = 25, message = "The lot number must be between 1 and 25 characters.")
    private String lote;

    @NotBlank(message = "The description cannot be null or empty.")
    @Size(min = 1, max = 500, message = "The description must be between 1 and 500 characters.")
    private String description;

    @NotBlank(message = "The presentation cannot be null or empty.")
    @Size(min = 1, max = 50, message = "The presentation must be between 1 and 50 characters.")
    private String presentation;

    @NotNull(message = "The net content cannot be null.")
    @Min(value = 0, message = "The net content must be at least 0.")
    @Max(value = 32767, message = "The net content must not exceed 32,767.")
    private Short netContent;

    @NotBlank(message = "The unit net content cannot be null or empty.")
    @Size(min = 1, max = 8, message = "The unit net content must be between 1 and 8 characters.")
    private String unitNetContent;

    @NotNull(message = "The brand ID cannot be null.")
    @Min(value = 1, message = "The brand ID must be at least 1.")
    @Max(value = 2147483647, message = "The brand ID must not exceed 2,147,483,647.")
    private Integer idBrand;

    @NotNull(message = "The category ID cannot be null.")
    @Min(value = 1, message = "The category ID must be at least 1.")
    @Max(value = 2147483647, message = "The category ID must not exceed 2,147,483,647.")
    private Integer idCategory;

    @NotNull(message = "The administration ID cannot be null.")
    @Min(value = 1, message = "The administration ID must be at least 1.")
    @Max(value = 2147483647, message = "The administration ID must not exceed 2,147,483,647.")
    private Integer idAdministrationVia;

    @NotNull(message = "The list of nutrients cannot be null.")
    private List<NutrientProductDTO> nutrientProducts;
}
