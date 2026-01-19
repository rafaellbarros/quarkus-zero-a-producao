package br.com.rafaellbarros.domain.model;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema
public enum SituacaoEnum {

    ACEITA_PROCESSAMENTO,
    LIMITE_EXCEDIDO,
    ANALISADA,
    APROVADA,
    NAO_ANALISADA,
    EM_ANALISE_HUMANA,
    EM_SUSPEITA_FRAUDE,
    RISCO_CONFIRMADO,
    CONFIRMADA_USUARIO;


}
