package com.ghostappi.backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.ghostappi.backend.model.Nutrient;
public interface NutrientRepository extends JpaRepository<Nutrient, Integer> {

    @Query(value = "SELECT n.* FROM nutrient AS n JOIN nutrientproduct AS np ON n.idNutrient = np.idNutrient WHERE np.idProduct = :idProduct", nativeQuery = true)
    List<Nutrient> getNutrientsFromProduct(@Param("idProduct") Integer idProduct);
}