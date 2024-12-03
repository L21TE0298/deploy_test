package com.ghostappi.backend.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.ghostappi.backend.model.TrainingRoutineExcercise;
import com.ghostappi.backend.repository.TrainingRoutineExcerciseRepository;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class TrainingRoutineExcerciseService {

    @Autowired
    private TrainingRoutineExcerciseRepository trainingRoutineExcerciseRepository;
    
    public List<TrainingRoutineExcercise> getAll(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        Page<TrainingRoutineExcercise> pageResult = trainingRoutineExcerciseRepository.findAll(pageRequest);
        return pageResult.getContent();
    }
}
