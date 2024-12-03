package com.ghostappi.backend.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;

import com.ghostappi.backend.service.TrainingRoutineService;
import com.ghostappi.backend.dto.TrainingRoutineDTO;
import com.ghostappi.backend.model.TrainingRoutine;

@RestController
@Validated
@RequestMapping("/trainingroutines")
@CrossOrigin(origins = "*", methods = {
                RequestMethod.GET,
                RequestMethod.POST,
                RequestMethod.DELETE,
                RequestMethod.PUT
})
@Tag(name = "TrainingRoutines", description = "Provides methods for managing training routines")
public class TrainingRoutineController {

        @Autowired
        private TrainingRoutineService service;

        @Operation(summary = "Get all training routines with pagination", description = "Return a list of all training routines with pagination")
        @ApiResponse(responseCode = "200", description = "Success", content = {
                        @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = TrainingRoutine.class)))
        })

        @GetMapping(params = { "page", "size" })
        public List<TrainingRoutine> getAll(
                        @RequestParam(value = "page", defaultValue = "0", required = false) int page,
                        @RequestParam(value = "size", defaultValue = "5", required = false) int size) {
                return service.getAll(page, size);
        }

        @Operation(summary = "Get a training routine by id", description = "Return a training routine by id")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Success", content = {
                                        @Content(mediaType = "application/json", schema = @Schema(implementation = TrainingRoutine.class))
                        }),
                        @ApiResponse(responseCode = "404", description = "Training routine not found", content = @Content)
        })

        @GetMapping("/{id}")
        public ResponseEntity<TrainingRoutine> getById(@PathVariable @Min(1) Integer id) {
                TrainingRoutine trainingRoutine = service.getById(id);
                return ResponseEntity.ok(trainingRoutine);
        }

        @Operation(summary = "Create a new training routine", description = "Create a new training routine")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "201", description = "Training routine sved successfully", content = @Content),
                        @ApiResponse(responseCode = "400", description = "Invalid input", content = @Content)
        })

        @PostMapping
        public ResponseEntity<?> save(@Valid @RequestBody TrainingRoutineDTO trainingRoutine) {
                service.save(trainingRoutine);
                return ResponseEntity.ok("Training routine sved successfully");
        }

        @Operation(summary = "Get training routines by user id", description = "Return a list of training routines by user id")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Success", content = {
                                        @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = TrainingRoutine.class))) }),
                        @ApiResponse(responseCode = "404", description = "Training routine not found", content = @Content)
        })
        @GetMapping("/user/{idUser}")
        public List<TrainingRoutine> getTrainingRoutinesByUserId(@PathVariable @Min(1) Integer idUser) {
                return service.getTrainingRoutinesByUserId(idUser);
        }        

}
