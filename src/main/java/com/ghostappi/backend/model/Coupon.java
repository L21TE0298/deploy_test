package com.ghostappi.backend.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "Coupon")
public class Coupon {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "idCoupon")
    @JsonProperty("idCoupon")
    @Positive(message = "The id must be a positive number")
    private Integer idCoupon;

    @NotBlank(message = "The code discount must no be null and containn at least one character")
    @Size(min = 1, max = 10, message = "The name must be almost 1 character and 10 characters at most")
    @Column(name = "codeDiscount")
    @JsonProperty("codeDiscount")
    private String codeDiscount;

    @NotBlank(message = "The description must no be null and containn at least one character")
    @Size(min = 1, max = 255, message = "The name must be almost 1 character and 255 characters at most")
    @Column(name = "description")
    @JsonProperty("description")
    private String description;

    @NotNull(message = "The init date can't be null")
    @Column(name = "initDate")
    @JsonProperty("initDate")
    @FutureOrPresent(message = "The init date must be in the future")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private Date initDate;

    @NotNull(message = "The expiration date can't be null")
    @Column(name = "expirationDate")
    @JsonProperty("expirationDate")
    @FutureOrPresent(message = "The expiration date must be in the future")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd")
    private Date expirationDate;

    @Positive(message = "Discount percentage must be a positive number")
    @NotNull(message = "The discount percentage must contain at least one digit")
    @Min(value = 1, message = "The min value of discount porcentaje is 1")
    @Max(value = 100, message = "The max value of discount porcentaje is 100")
    @Column(name = "discountPercentage")
    @JsonProperty("discountPercentage")
    private Integer discountPercentage;

    @NotNull(message = "The status can´t be null")
    @Column(name = "status")
    @JsonProperty("status")
    private Boolean status;

    @OneToOne
    @JoinColumn(name = "idCategory", referencedColumnName = "idCategory")
    @NotNull(message = "The category cannot be null")
    @JsonProperty("idCategory")
    private Category idCategory;

    public boolean isExpired() {
        Date now = new Date();
        return expirationDate != null && now.after(expirationDate);
    }

    public Boolean getStatus() {
        return !isExpired();
    }

    public void setStatus(Boolean status) {
        this.status = status;
    }

    public Integer getIdCoupon() {
        return idCoupon;
    }

    public void setIdCoupon(Integer idCoupon) {
        this.idCoupon = idCoupon;
    }

    public String getCodeDiscount() {
        return codeDiscount;
    }

    public void setCodeDiscount(String codeDiscount) {
        this.codeDiscount = codeDiscount;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Date getInitDate() {
        return initDate;
    }

    public void setInitDate(Date initDate) {
        this.initDate = initDate;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public Integer getDiscountPercentage() {
        return discountPercentage;
    }

    public void setDiscountPercentage(Integer discountPercentage) {
        this.discountPercentage = discountPercentage;
    }

    public Category getIdCategory() {
        return idCategory;
    }

    public void setIdCategory(Category idCategory) {
        this.idCategory = idCategory;
    }
}
