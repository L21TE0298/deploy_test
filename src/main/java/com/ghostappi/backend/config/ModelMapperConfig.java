package com.ghostappi.backend.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration; // Correcto, esto importa singletonMap directamente

@Configuration
public class ModelMapperConfig {
  
        @Bean
        public ModelMapper modelMapper() {
            return new ModelMapper();
        }
    
}
