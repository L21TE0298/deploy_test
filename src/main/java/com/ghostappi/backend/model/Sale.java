package com.ghostappi.backend.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import java.math.BigDecimal;
import java.util.Date;

@Entity
@Table(name = "Sale")
public class Sale {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idSale;

    @Temporal(TemporalType.DATE)
    @NotNull(message = "The date cannot be null.")
    private Date date;

    @Column(nullable = false, precision = 10, scale = 2)
    @NotNull(message = "The total amount cannot be null.")
    @DecimalMin(value = "0.01", message = "The total must be at least 0.01.")
    @DecimalMax(value = "9999999999.99", message = "The total must not exceed 9,999,999,999.99.")
    private BigDecimal total;

    @Column(nullable = false, length = 25)
    @NotBlank(message = "Payment method must not be blank.")
    @Size(max = 25, message = "Payment method must be at most 25 characters.")
    private String paymentMethod;

    @Column(nullable = false)
    @NotNull(message = "Generated points cannot be null.")
    @Min(value = 0, message = "Generated points must be at least 0.")
    @Max(value = 2147483647, message = "Generated points must not exceed 2,147,483,647.")
    private Integer generatedPoints;

    @ManyToOne
    @JoinColumn(name = "idUser", nullable = false)
    @NotNull(message = "The user cannot be null.")
    private User user;

    // Uncomment if the coupon relationship is needed
    // @ManyToOne
    // @JoinColumn(name = "idCoupon", nullable = false)
    // @NotNull(message = "The coupon cannot be null.")
    // private Coupon coupon;

    // Getters and Setters

    public Integer getIdSale() {
        return idSale;
    }

    public void setIdSale(Integer idSale) {
        this.idSale = idSale;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    public BigDecimal getTotal() {
        return total;
    }

    public void setTotal(BigDecimal total) {
        this.total = total;
    }

    public String getPaymentMethod() {
        return paymentMethod;
    }

    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }

    public Integer getGeneratedPoints() {
        return generatedPoints;
    }

    public void setGeneratedPoints(Integer generatedPoints) {
        this.generatedPoints = generatedPoints;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    // Uncomment if the coupon relationship is needed
    // public Coupon getCoupon() {
    //     return coupon;
    // }

    // public void setCoupon(Coupon coupon) {
    //     this.coupon = coupon;
    // }
}
