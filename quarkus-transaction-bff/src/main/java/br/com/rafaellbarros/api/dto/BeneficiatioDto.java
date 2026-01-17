package br.com.rafaellbarros.api.dto;

import jakarta.validation.constraints.NotNull;
import org.eclipse.microprofile.openapi.annotations.media.Schema;


import java.io.Serializable;

public class BeneficiatioDto implements Serializable {

    private static final long serialVersionUID = 2806421543985360625L;

    @Schema(description = "CPF do Beneficiário")
    @NotNull(message = "Informar o CPF.")
    private Long CPF;
    @NotNull(message = "Informar o código do banco de destino.")
    @Schema(description = "Código do banco destino")
    private Long codigoBanco;
    @NotNull(message = "Informar a agência de destino.")
    @Schema(description = "Agência de destino")
    private String agencia;
    @NotNull(message = "Informar a conta de destino.")
    @Schema(description = "Conta de destino")
    private String conta;
    @NotNull(message = "Informar o nome do Favorecido.")
    @Schema(description = "Nome do Favorecido")
    private String nomeFavorecido;

    public BeneficiatioDto() {
    }


    public Long getCPF() {
        return CPF;
    }

    public void setCPF(Long CPF) {
        this.CPF = CPF;
    }

    public Long getCodigoBanco() {
        return codigoBanco;
    }

    public void setCodigoBanco(Long codigoBanco) {
        this.codigoBanco = codigoBanco;
    }

    public String getAgencia() {
        return agencia;
    }

    public void setAgencia(String agencia) {
        this.agencia = agencia;
    }

    public String getConta() {
        return conta;
    }

    public void setConta(String conta) {
        this.conta = conta;
    }

    public String getNomeFavorecido() {
        return nomeFavorecido;
    }

    public void setNomeFavorecido(String nomeFavorecido) {
        this.nomeFavorecido = nomeFavorecido;
    }

    @Override
    public String toString() {
        return "BeneficiatioDto{" +
                "CPF=" + CPF +
                ", codigoBanco=" + codigoBanco +
                ", agencia='" + agencia + '\'' +
                ", conta='" + conta + '\'' +
                ", nomeFavorecido='" + nomeFavorecido + '\'' +
                '}';
    }
}
