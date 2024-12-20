package com.ghostappi.backend.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

@Entity
public class Wallet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer idWallet;
    @NotNull(message = "User ID cannot be null.")
    @Positive(message = "User ID must be a positive number.")
    @Min(value = 1, message = "The user ID must be at least 1.")
    @Max(value = 2147483647, message = "The user ID must not exceed 2,147,483,647.")
    @Column(name = "idUser", nullable = false)
    private Integer userId;

    @OneToMany(mappedBy = "wallet")
    @JsonBackReference
    private List<Card> cards = new ArrayList<>();

    public Wallet() {
    }

    public Integer getIdWallet() {
        return idWallet;
    }

    public void setIdWallet(Integer idWallet) {
        this.idWallet = idWallet;
    }

    @JsonProperty("idUser") 
    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public List<Card> getCards() {
        return cards;
    }

    public void setCards(List<Card> cards) {
        this.cards = cards;
    }

    @Override
    public String toString() {
        return "Wallet [idWallet=" + idWallet + ", userId=" + userId + ", cards=" + cards + "]";
    }

    
}