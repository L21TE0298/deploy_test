package com.ghostappi.backend.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Schema;

import com.ghostappi.backend.service.TrainingRoutineExcerciseService;
import com.ghostappi.backend.model.TrainingRoutineExcercise;

@RestController
@RequestMapping("trainingroutineexcercises")
@CrossOrigin(origins = "*", methods = {
    RequestMethod.GET,
    RequestMethod.POST,
    RequestMethod.PUT,
    RequestMethod.DELETE })
@Tag(name = "TrainingRoutineExcercises", description = "Provides methods for managing TrainingRoutineExcercise relationship")
public class TrainingRoutineExcerciseController {

    @Autowired
    private TrainingRoutineExcerciseService service;

    @Operation(summary = "List all training routine excercises with pagination")
    @ApiResponse(responseCode = "200", description = "Found all training routine excercises", content = {
        @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = TrainingRoutineExcercise.class))) })
    @GetMapping(params = { "page", "size" })
    public List<TrainingRoutineExcercise> getAll(
            @RequestParam(value = "page", defaultValue = "0", required = false) int page,
            @RequestParam(value = "size", defaultValue = "5", required = false) int size) {
        List<TrainingRoutineExcercise> trainingRoutineExcercises = service.getAll(page, size);
        return trainingRoutineExcercises;
    }
}
