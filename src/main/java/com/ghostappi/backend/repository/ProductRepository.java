package com.ghostappi.backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ghostappi.backend.model.Product;

@Repository
public interface ProductRepository extends JpaRepository<Product, Integer> {
}
