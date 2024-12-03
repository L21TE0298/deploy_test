package com.ghostappi.backend.dto;

import jakarta.validation.constraints.NotNull;

import java.util.ArrayList;
import java.util.List;

public class CardDTO2 {

    @NotNull(message = "User ID cannot be null")
    private Integer userId;

    @NotNull(message = "Cards list cannot be null")
    private List<CardDTO> cards = new ArrayList<>();

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public List<CardDTO> getCards() {
        return cards;
    }

    public void setCards(List<CardDTO> cards) {
        this.cards = cards;
    }
}
