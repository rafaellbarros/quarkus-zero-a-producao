package br.com.rafaellbarros.api.dto;


import br.com.rafaellbarros.domain.model.Conta;
import br.com.rafaellbarros.domain.model.SituacaoEnum;
import br.com.rafaellbarros.domain.model.TipoTransacaoEnum;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.eclipse.microprofile.openapi.annotations.media.Schema;


import java.io.Serializable;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Schema(description = "Objeto de transporte para o envio de uma promessa de transação")
public class TransactionDTO implements Serializable {

    private static final long serialVersionUID = 2806421523585360625L;
    @Schema(description = "Valor da transação")
    @NotNull(message = "Informar o valor da transação")
    private BigDecimal valor;
    @Schema(description = "Data/hora/minuto e segundo da transação")
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime data;
    @NotNull(message = "Informar a conta de origem da transação")
    @Schema(description = "Conta de origem da transação")
    @Valid
    private Conta conta;
    @NotNull(message = "Informar o beneficiário da transação")
    @Schema(description = "Beneficiário da transação")
    @Valid
    private BeneficiatioDTO beneficiario;
    @NotNull(message = "Informar o tipo da transação")
    @Schema(description = "Tipo de transação")
    private TipoTransacaoEnum tipoTransacaoEnum;
    @Schema(description = "Código de identificação da transação")
    private UUID uuid;
    @Schema(description = "Situação da transação")
    private SituacaoEnum situacao;

    public void naoAnalisada() {
        setSituacao(SituacaoEnum.NAO_ANALISADA);
    }


    public BigDecimal getValor() {
        return valor;
    }

    public void setValor(BigDecimal valor) {
        this.valor = valor;
    }

    public LocalDateTime getData() {
        return data;
    }

    public void setData(LocalDateTime data) {
        this.data = data;
    }

    public Conta getConta() {
        return conta;
    }

    public void setConta(Conta conta) {
        this.conta = conta;
    }

    public BeneficiatioDTO getBeneficiario() {
        return beneficiario;
    }

    public void setBeneficiario(BeneficiatioDTO beneficiario) {
        this.beneficiario = beneficiario;
    }

    public TipoTransacaoEnum getTipoTransacao() {
        return tipoTransacaoEnum;
    }

    public void setTipoTransacao(TipoTransacaoEnum tipoTransacaoEnum) {
        this.tipoTransacaoEnum = tipoTransacaoEnum;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public SituacaoEnum getSituacao() {
        return situacao;
    }

    public void setSituacao(SituacaoEnum situacao) {
        this.situacao = situacao;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionDTO that = (TransactionDTO) o;
        return Objects.equals(uuid, that.uuid);
    }

    public void analisada() {
        setSituacao(SituacaoEnum.ANALISADA);
    }

    public void suspeitaFraude() {
        setSituacao(SituacaoEnum.EM_SUSPEITA_FRAUDE);
    }

    public void analiseHumana() {
        setSituacao(SituacaoEnum.EM_ANALISE_HUMANA);
    }

    public void confirmadaUsuario() {
        setSituacao(SituacaoEnum.CONFIRMADA_USUARIO);
    }
    public void aceitaProcessamento() {
        setSituacao(SituacaoEnum.ACEITA_PROCESSAMENTO);
    }

    @Override
    public String toString() {
        return "TransactionDTO{" +
                "valor=" + valor +
                ", data=" + data +
                ", conta=" + conta +
                ", beneficiario=" + beneficiario +
                ", tipoTransacao=" + tipoTransacaoEnum +
                ", uuid=" + uuid +
                ", situacao=" + situacao +
                '}';
    }

    @Override
    public int hashCode() {
        return Objects.hash(uuid);
    }
}
