package com.ghostappi.backend.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.PutMapping;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

import com.ghostappi.backend.service.ProductService;
import com.ghostappi.backend.dto.ProductDTO;
import com.ghostappi.backend.model.Product;

@RestController
@Validated
@RequestMapping("/products")
@CrossOrigin(origins = "*", methods = {
                RequestMethod.GET,
                RequestMethod.POST,
                RequestMethod.DELETE,
                RequestMethod.PUT
})
@Tag(name = "Products", description = "Provides methods for managing products")
@SecurityRequirement(name = "bearerAuth")
public class ProductController {

        @Autowired
        private ProductService productService;

        @Operation(summary = "Get all products with pagination", description = "Return a list of products with pagination")
        @ApiResponse(responseCode = "200", description = "Success", content = {
                        @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = Product.class)))
        })

        @GetMapping(params = { "page", "size" })
        public List<Product> getAll(
                        @RequestParam(value = "page", defaultValue = "0", required = false) int page,
                        @RequestParam(value = "size", defaultValue = "5", required = false) int size) {
                List<Product> products = productService.getAll(page, size);
                return products;
        }

        @Operation(summary = "Get product by id", description = "Get product by id")

        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Success", content = {
                                        @Content(mediaType = "application/json", schema = @Schema(implementation = Product.class))
                        }),
                        @ApiResponse(responseCode = "400", description = "Invalid id supplied", content = @Content),
                        @ApiResponse(responseCode = "404", description = "Product not found", content = @Content)
        })
        @GetMapping("{idProduct}")
        public Product getById(@PathVariable Integer idProduct) {
                return productService.getById(idProduct);
        }

        @Operation(summary = "Create a new Product", description = "Create a new Product")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "201", description = "Product saved succesfully", content = {
                                        @Content(mediaType = "application/json", schema = @Schema(implementation = Product.class))
                        }),
                        @ApiResponse(responseCode = "400", description = "Invalid data", content = @Content)
        })
        @PostMapping
        public ResponseEntity<?> save(@Valid @RequestBody ProductDTO productDTO) {

                productService.save(productDTO);
                return new ResponseEntity<>("Product saved succesfully", HttpStatus.CREATED);
        }

        @Operation(summary = "Upload a image for product", description = "Upload a image for product")
        @ApiResponses(value = {
                        @ApiResponse(responseCode = "200", description = "Image uploaded successfully", content = @Content),
                        @ApiResponse(responseCode = "400", description = "Invalid file", content = @Content)
        })
        @PutMapping(value = "{idProduct}", consumes = "multipart/form-data")
        public String upload(@RequestParam MultipartFile multipartFile, @RequestParam Integer idProduct) {
                return productService.upload(multipartFile, idProduct);
        }
}
