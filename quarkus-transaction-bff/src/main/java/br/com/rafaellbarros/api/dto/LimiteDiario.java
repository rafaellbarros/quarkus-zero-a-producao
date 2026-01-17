package br.com.rafaellbarros.api.dto;

import jakarta.validation.constraints.NotNull;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.math.BigDecimal;
import java.time.LocalDate;

public class LimiteDiario {

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    private Long id;
    @NotNull(message = "Informar o código da Agência.")
    @Schema(description = "Código da Agência")
    private Long agencia;
    @NotNull(message = "Informar o código da Conta.")
    @Schema(description = "Código da Conta")
    private Long conta;
    @Schema(description = "Data de Limite")
    @NotNull(message = "Data do Limite")
    private LocalDate data;
    @Schema(description = "Valor de Limite")
    @NotNull(message = "valor do limite.")
    private BigDecimal valor;

    public Long getAgencia() {
        return agencia;
    }

    public void setAgencia(Long codigoAgencia) {
        this.agencia = codigoAgencia;
    }

    public Long getConta() {
        return conta;
    }

    public void setConta(Long codigoConta) {
        this.conta = codigoConta;
    }

    public LocalDate getData() {
        return data;
    }

    public void setData(LocalDate data) {
        this.data = data;
    }

    public BigDecimal getValor() {
        return valor;
    }

    public void setValor(BigDecimal valor) {
        this.valor = valor;
    }

    @Override
    public String toString() {
        return "LimiteDiario{" +
                "agencia=" + agencia +
                ", conta=" + conta +
                ", data=" + data +
                ", valor=" + valor +
                ", id=" + id +
                '}';
    }
}
