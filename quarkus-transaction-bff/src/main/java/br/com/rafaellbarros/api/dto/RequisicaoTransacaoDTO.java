package br.com.rafaellbarros.api.dto;


import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(description = "Objeto de transporte para o envio de uma promessa de transação")
public class RequisicaoTransacaoDTO extends TransactionDTO {

    public RequisicaoTransacaoDTO() {
    }

    @Override
    public String toString() {
        return "RequisicaoTransacaoDTO{" +
                "situacao=" + getSituacao() +
                ", data=" + getData() + "," +
                super.toString() +
                '}';
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    private String signature;
}
