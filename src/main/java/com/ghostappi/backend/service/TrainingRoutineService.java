package com.ghostappi.backend.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.ghostappi.backend.dto.TrainingRoutineDTO;
import com.ghostappi.backend.dto.TrainingRoutineExcerciseDTO;
import com.ghostappi.backend.model.Excercise;
import com.ghostappi.backend.model.TrainingRoutine;
import com.ghostappi.backend.model.TrainingRoutineExcercise;
import com.ghostappi.backend.repository.ExcerciseRepository;
import com.ghostappi.backend.repository.TrainingRoutineExcerciseRepository;
import com.ghostappi.backend.repository.TrainingRoutineRepository;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class TrainingRoutineService {

    @Autowired
    private TrainingRoutineRepository repository;

    @Autowired
    ExcerciseRepository excerciseRepository;

    @Autowired
    TrainingRoutineExcerciseRepository trainingRoutineExcerciseRepository;

    public void save(TrainingRoutineDTO trainingRoutineDTO) {
        TrainingRoutine trainingRoutine = convertToEntity(trainingRoutineDTO);
        repository.save(trainingRoutine);

        List<TrainingRoutineExcercise> trainingRoutineExcercises = trainingRoutineDTO.getTrainingRoutineExcercises()
                .stream().map(dto -> convertTrainingRoutineExcerciseDTOToEntity(dto, trainingRoutine))
                .collect(Collectors.toList());
        trainingRoutineExcerciseRepository.saveAll(trainingRoutineExcercises);

    }

    public TrainingRoutine getById(Integer id) {
        return repository.findById(id).get();
    }

    public List<TrainingRoutine> getAll(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        Page<TrainingRoutine> pageResult = repository.findAll(pageRequest);
        return pageResult.getContent();
    }

    public List<TrainingRoutine> getTrainingRoutinesByUserId(Integer idUser) {
        return repository.findByIdUser(idUser);
    }

    private TrainingRoutine convertToEntity(TrainingRoutineDTO trainingRoutineDTO) {

        TrainingRoutine trainingRoutine = new TrainingRoutine();
        trainingRoutine.setRoutineName(trainingRoutineDTO.getRoutineName());
        trainingRoutine.setRegistrationDate(trainingRoutineDTO.getRegistrationDate());
        trainingRoutine.setIdUser(trainingRoutineDTO.getIdUser());
        return trainingRoutine;
    }

    private TrainingRoutineExcercise convertTrainingRoutineExcerciseDTOToEntity(
            TrainingRoutineExcerciseDTO trainingRoutineExcerciseDTO,
            TrainingRoutine trainingRoutine) {

        Excercise excercise = excerciseRepository.findById(trainingRoutineExcerciseDTO.getIdExcercise()).get();

        TrainingRoutineExcercise trainingRoutineExcercise = new TrainingRoutineExcercise();
        trainingRoutineExcercise.setExcercise(excercise);
        trainingRoutineExcercise.setTrainingRoutine(trainingRoutine);
        trainingRoutineExcercise.setReps(trainingRoutineExcerciseDTO.getReps());
        trainingRoutineExcercise.setSets(trainingRoutineExcerciseDTO.getSets());

        return trainingRoutineExcercise;
    }

}
