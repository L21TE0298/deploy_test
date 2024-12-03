package com.ghostappi.backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface NutrientProductRepository extends JpaRepository<com.ghostappi.backend.model.NutrientProduct, com.ghostappi.backend.model.NutrientProductPK>{

}
