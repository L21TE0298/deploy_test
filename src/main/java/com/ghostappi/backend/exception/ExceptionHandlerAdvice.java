package com.ghostappi.backend.exception;

import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
//import org.springframework.security.access.AccessDeniedException; // Importa esta clase para el error 403
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;

@ControllerAdvice
public class ExceptionHandlerAdvice {
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<String> handleMissingServletRequestParameterException(
            MissingServletRequestParameterException ex) {
        String parameterName = ex.getParameterName();
        String message = String.format("The required request parameter '%s' is negative our missing.", parameterName);

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(message); // Devuelve un mensaje claro
    }
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ConstraintViolationException.class)
    public ModelAndView handleConstraintViolationExceptions(ConstraintViolationException ex) {
        Map<String, String> errors = new HashMap<>();
        Set<ConstraintViolation<?>> violations = ex.getConstraintViolations();

        for (ConstraintViolation<?> violation : violations) {
            String fieldName = violation.getPropertyPath().toString(); // Parámetro que falló
            String errorMessage = violation.getMessage(); // Mensaje asociado
            errors.put(fieldName, errorMessage);
        }

        ModelAndView mav = new ModelAndView();
        mav.addObject("exception", ex);
        mav.addObject("errors", errors);
        mav.setViewName("methodArgumentNotValid"); // Nombre de la vista HTML
        return mav;
    }
    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<String> handleNoSuchElementException(NoSuchElementException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("The requested resource was not registered.");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)

    public ModelAndView handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        ModelAndView mav = new ModelAndView();
        mav.addObject("exception", ex);
        mav.addObject("errors", errors);
        mav.setViewName("methodArgumentNotValid");
        return mav;
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<String> handleMethodArgumentTypeMismatchException(MethodArgumentTypeMismatchException ex) {
        String parameterName = ex.getName();
        String expectedType = ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown";
        String value = ex.getValue() != null ? ex.getValue().toString() : "null";

        String message = String.format(
                "Invalid value '%s' for parameter '%s'. Expected type: %s.",
                value, parameterName, expectedType);

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(message);
    }

    // @ExceptionHandler(AccessDeniedException.class)
    // public ResponseEntity<String>
    // handleAccessDeniedException(AccessDeniedException e) {
    // return ResponseEntity.status(HttpStatus.FORBIDDEN).body("You do not have
    // permission to access this resource.");
    // }
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<String> handleNoResourceFoundException(NoResourceFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Please insert the link correctly");
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleInvalidFormat(HttpMessageNotReadableException ex) {
        if (ex.getCause() instanceof com.fasterxml.jackson.databind.exc.InvalidFormatException) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid date format. Expected format: yyyy-MM-dd");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Malformed JSON request please check the request body and link");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        String message = "Invalid date format. Please ensure the date is in the correct format (e.g., yyyy-MM-dd HH:mm:ss)";

        // Verifica si el error específico está relacionado con un campo de fecha
        if (ex.getMessage().contains("Incorrect date value")) {
            message = "Invalid date value detected. Please check the date format or value. Please ensure the date is in the correct format (e.g., yyyy-MM-dd HH:mm:ss)";
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(message);
    }
}
