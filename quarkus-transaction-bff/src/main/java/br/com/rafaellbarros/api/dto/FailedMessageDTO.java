package br.com.rafaellbarros.api.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class FailedMessageDTO {

    private RequisicaoTransacaoDTO transacao;
    private String error;
    private LocalDateTime timestamp;
    
    public FailedMessageDTO(RequisicaoTransacaoDTO transacao, String error) {
        this.transacao = transacao;
        this.error = error;
        this.timestamp = LocalDateTime.now();
    }

}