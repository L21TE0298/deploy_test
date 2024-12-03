package com.ghostappi.backend.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.ghostappi.backend.repository.NutrientProductRepository;
import com.ghostappi.backend.repository.NutrientRepository;
import com.ghostappi.backend.repository.ProductRepository;
import com.ghostappi.backend.dto.NutrientProductDTO;
import com.ghostappi.backend.dto.ProductDTO;
import com.ghostappi.backend.model.Nutrient;
import com.ghostappi.backend.model.NutrientProduct;
import com.ghostappi.backend.model.Product;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.UUID;

import org.springframework.web.multipart.MultipartFile;

import com.google.auth.Credentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import jakarta.transaction.Transactional;

@Service
@Transactional
public class ProductService {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private NutrientRepository nutrientRepository;

    @Autowired
    private NutrientProductRepository nutrientProductRepository;

    public List<Product> getAll(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        Page<Product> pageResult = productRepository.findAll(pageRequest);
        return pageResult.getContent();
    }

    public void save(ProductDTO productDTO) {

        Product product = convertToEntity(productDTO);
        if(product.getImgProductPath().equals("") || product.getImgProductPath().equals("string"))
            product.setImgProductPath("https://firebasestorage.googleapis.com/v0/b/webservices-2024spring-17/o/Screenshot%202024-11-26%20072516.png?alt=media&token=8f40cfd8-bbb4-46eb-b114-21f7f8d4156f");
        productRepository.save(product);

        List<NutrientProduct> nutrientProducts = productDTO.getNutrientProducts().stream()
                .map(dto -> convertNutrientProductDTOToEntity(dto, product))
                .collect(Collectors.toList());

        nutrientProductRepository.saveAll(nutrientProducts);
    }

    public Product getById(Integer id) {
        return productRepository.findById(id).get();
    }

    public void delete(Integer id) {
        productRepository.deleteById(id);
    }

    private Product convertToEntity(ProductDTO productDTO) {
        Product product = new Product();
        product.setComercialName(productDTO.getComercialName());
        product.setPrice(productDTO.getPrice());
        product.setStock(productDTO.getStock());
        product.setServingSize(productDTO.getServingSize());
        product.setUnitServingSize(productDTO.getUnitServingSize());
        product.setServings(productDTO.getServings());
        product.setProductRecomendation(productDTO.getProductRecomendation());
        product.setImgProductPath(productDTO.getImgProductPath());
        product.setCaducity(productDTO.getCaducity());
        product.setLote(productDTO.getLote());
        product.setFlavor(productDTO.getFlavor());
        product.setNetContent(productDTO.getNetContent());
        product.setUnitNetContent(productDTO.getUnitNetContent());
        product.setPresentation(productDTO.getPresentation());
        product.setDescription(productDTO.getDescription());
        product.setIdBrand(productDTO.getIdBrand());
        product.setIdCategory(productDTO.getIdCategory());
        product.setIdAdministrationVia(productDTO.getIdAdministrationVia());

        return product;
    }

    private NutrientProduct convertNutrientProductDTOToEntity(NutrientProductDTO nutrientProductDTO, Product product) {

        Nutrient nutrient = nutrientRepository.findById(nutrientProductDTO.getIdNutrient()).orElse(null);

        NutrientProduct nutrientProduct = new NutrientProduct();
        nutrientProduct.setProduct(product);
        nutrientProduct.setNutrient(nutrient);
        nutrientProduct.setQuantity(nutrientProductDTO.getQuantity());
        nutrientProduct.setPercentage(nutrientProductDTO.getPercentage());
        return nutrientProduct;
    }

    public String upload(MultipartFile multipartFile, Integer idProduct) {
        try {
            Product product = productRepository.findById(idProduct).get();
            if(product==null){
                return "Product not found";
            }
            String fileName = multipartFile.getOriginalFilename();
            fileName = UUID.randomUUID().toString().concat(this.getExtension(fileName));
            File file = this.convertToFile(multipartFile, fileName);
            String URL = this.uploadFile(file, fileName);
            product.setImgProductPath(URL);
            productRepository.save(product);
            file.delete();
            return URL;
        } catch (Exception e) {
            e.printStackTrace();
            return "The image could not be uploaded";
        }
    }

    private String getExtension(String fileName) {
        return fileName.substring(fileName.lastIndexOf("."));
    }

    private File convertToFile(MultipartFile multipartFile, String fileName) throws IOException {
        File tempFile = new File(fileName);
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(multipartFile.getBytes());
            fos.close();
        }
        return tempFile;
    }

    private String uploadFile(File file, String fileName) throws IOException {
        BlobId blobId = BlobId.of("webservices-2024spring-17", fileName);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType("media").build();
        InputStream inputStream = ProductService.class.getClassLoader().getResourceAsStream("firebase-private-key.json");
        Credentials credentials = GoogleCredentials.fromStream(inputStream);
        Storage storage = StorageOptions.newBuilder().setCredentials(credentials).build().getService();
        storage.create(blobInfo, Files.readAllBytes(file.toPath()));

        String downloadURL = "https://firebasestorage.googleapis.com/v0/b/webservices-2024spring-17/o/%s?alt=media";
        return String.format(downloadURL, URLEncoder.encode(fileName, StandardCharsets.UTF_8));
    }
}
