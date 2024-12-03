package com.ghostappi.backend.model;

import java.io.Serializable;
import java.util.Objects;

public class NutrientProductPK implements Serializable{
    private Nutrient nutrient;
    private Product product;


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof NutrientProductPK nutrientProductPK)) return false;
        return product.getIdProduct() == nutrientProductPK.product.getIdProduct() && Objects.equals(nutrient, nutrientProductPK.nutrient);
    }

    @Override
    public int hashCode() {
        return Objects.hash(product,nutrient);
    }   

    public Product getProduct() {
        return product;
    }

    public Nutrient getNutrient() {
        return nutrient;
    }
    
}
