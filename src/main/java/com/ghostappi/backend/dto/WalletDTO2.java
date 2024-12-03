package com.ghostappi.backend.dto;

import java.util.ArrayList;
import java.util.List;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public class WalletDTO2 {
    @NotNull(message = "User ID cannot be null.")
    @Positive(message = "User ID must be a positive number.")
    @Min(value = 1, message = "The user ID must be at least 1.")
    @Max(value = 2147483647, message = "The user ID must not exceed 2,147,483,647.")
    private Integer idUser; 
    private Integer idWallet;
    private List<CardDTO> cards = new ArrayList<>();

    public Integer getIdUser() {
        return idUser;
    }
    public void setIdUser(Integer idUser) {
        this.idUser = idUser;
    }
    public Integer getIdWallet() {
        return idWallet;
    }
    public void setIdWallet(Integer idWallet) {
        this.idWallet = idWallet;
    }
    public List<CardDTO> getCards() {
        return cards;
    }
    public void setCards(List<CardDTO> cards) {
        this.cards = cards;
    }

}
