package com.ghostappi.backend.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ghostappi.backend.model.TrainingRoutineExcercise;
import com.ghostappi.backend.model.TrainingRoutineExcercisePK;

@Repository
public interface TrainingRoutineExcerciseRepository extends JpaRepository<TrainingRoutineExcercise ,TrainingRoutineExcercisePK> {

}
