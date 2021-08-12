package com.samuilolegovich;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AppleEncodeCardData {
    @NotBlank
    private String card;
    @NotBlank
    private String cardExpMonth;
    @NotBlank
    private String cardExpYear;
    @NotBlank
    private String tavv;

    private String phone;
    private String prepare;
    private String recurringByToken;
}
