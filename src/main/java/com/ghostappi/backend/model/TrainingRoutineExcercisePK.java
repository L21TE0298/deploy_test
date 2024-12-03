package com.ghostappi.backend.model;

import java.io.Serializable;
import java.util.Objects;


public class TrainingRoutineExcercisePK implements Serializable{

    private TrainingRoutine trainingRoutine;
    private Excercise excercise;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TrainingRoutineExcercisePK trainingRoutineExcercisePK)) return false;
        return trainingRoutine.getIdTrainingRoutine() == trainingRoutineExcercisePK.trainingRoutine.getIdTrainingRoutine() && Objects.equals(excercise, trainingRoutineExcercisePK.excercise);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trainingRoutine,excercise);
    }   

    public TrainingRoutine getTrainingRoutine() {
        return trainingRoutine;
    }

    public Excercise getExcercise() {
        return excercise;
    }

}
