package br.com.rafaellbarros.api.controller;


import br.com.rafaellbarros.api.doc.TransactionApi;
import br.com.rafaellbarros.domain.model.Conta;
import br.com.rafaellbarros.api.dto.RequisicaoTransacaoDTO;
import br.com.rafaellbarros.domain.service.TransactionService;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.common.annotation.Blocking;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.jwt.Claim;
import org.jboss.logging.Logger;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

@Authenticated
@RequestScoped
@Blocking
public class TransactionController implements TransactionApi {

    private static final Logger LOG = Logger.getLogger(TransactionController.class);

    @Inject
    TransactionService transactionService;

    @Inject
    SecurityIdentity securityIdentity;

    @Claim("conta")
    String conta;

    @Claim("agencia")
    String agencia;

    @Override
    @RolesAllowed("coffeeandit-transaction")
    public Response save(@Context UriInfo uriInfo, RequisicaoTransacaoDTO requisicaoTransacaoDTO) {
        LOG.infof("Transação enviada pelo usuário %s - %s",
                securityIdentity.getPrincipal().getName(),
                requisicaoTransacaoDTO);

        Optional<RequisicaoTransacaoDTO> transacao =
                transactionService.save(introspectAccount(requisicaoTransacaoDTO));

        RequisicaoTransacaoDTO dto = transacao.orElseThrow(() ->
                new NotFoundException("Não foi possível processar a transação"));

        URI uri = uriInfo.getAbsolutePathBuilder()
                .path(TransactionController.class, "findById")
                .build(dto.getUuid().toString());

        return Response.created(uri)
                .header("x-signature", dto.getSignature())
                .build();
    }

    @Override
    @RolesAllowed("coffeeandit-transaction")
    public Response delete(String uuid) {
        LOG.infof("Deletando transação %s pelo usuário %s",
                uuid, securityIdentity.getPrincipal().getName());

        if (transactionService.delete(uuid)) {
            return Response.noContent().build();
        }
        throw new NotFoundException("Não encontrei o recurso " + uuid);
    }

    @Override
    @Blocking
    public RequisicaoTransacaoDTO findById(String uuid) {
        LOG.info("Procurando transação pelo uuid " + uuid);

        return transactionService.find(uuid)
                .orElseThrow(() ->
                        new NotFoundException("Não foi possível encontrar a transação"));
    }

    @Override
    @Blocking
    @RolesAllowed("coffeeandit-transaction")
    public RequisicaoTransacaoDTO aprovar(String uuid, String signature) {
        LOG.info("Aprovando transação pelo uuid " + uuid);

        RequisicaoTransacaoDTO dto = transactionService.find(uuid)
                .orElseThrow(() ->
                        new NotFoundException("Não foi possível encontrar a transação"));

        return transactionService.aprovarTransacao(dto, signature)
                .orElseThrow(() ->
                        new ServerErrorException(
                                "Não foi possível atualizar a transação",
                                Response.serverError().build()));
    }

    private RequisicaoTransacaoDTO introspectAccount(RequisicaoTransacaoDTO dto) {
        if (Objects.isNull(conta) || Objects.isNull(agencia)) {
            throw new NotAuthorizedException(
                    "O token não possui as claims obrigatórias de conta e/ou agencia");
        }

        dto.setConta(Conta.of(
                Long.parseLong(agencia),
                Long.parseLong(conta))
        );

        return dto;
    }
}