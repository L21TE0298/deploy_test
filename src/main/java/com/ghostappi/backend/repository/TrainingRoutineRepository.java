package com.ghostappi.backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ghostappi.backend.model.TrainingRoutine;

@Repository
public interface TrainingRoutineRepository extends JpaRepository<TrainingRoutine, Integer> {
    
    List<TrainingRoutine> findByIdUser(Integer idUser);;
}
