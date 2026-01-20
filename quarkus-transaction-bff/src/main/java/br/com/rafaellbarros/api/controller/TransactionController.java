package br.com.rafaellbarros.api.controller;


import br.com.rafaellbarros.api.doc.TransactionApi;
import br.com.rafaellbarros.api.dto.RequisicaoTransacaoDTO;
import br.com.rafaellbarros.domain.exception.BusinessException;
import br.com.rafaellbarros.domain.model.Conta;
import br.com.rafaellbarros.domain.service.TransactionService;
import io.smallrye.common.annotation.Blocking;
import io.smallrye.common.annotation.NonBlocking;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.jwt.Claim;
import org.jboss.logging.Logger;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;


// @Authenticated
@RequestScoped
public class TransactionController implements TransactionApi {

    private static final Logger LOG = Logger.getLogger(TransactionController.class);

    @Inject
    TransactionService transactionService;

    // @Inject
    // SecurityIdentity securityIdentity;

    @Claim("conta")
    String conta;

    @Claim("agencia")
    String agencia;

    @Override
    // @RolesAllowed("coffeeandit-transaction")
    @NonBlocking
    public Uni<Response> save(@Context UriInfo uriInfo, RequisicaoTransacaoDTO requisicaoTransacaoDTO) {

        // Validação inicial
        if (requisicaoTransacaoDTO.getValor() == null || requisicaoTransacaoDTO.getValor().intValue() <= 0) {
            return Uni.createFrom().item(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(Map.of("error", "Valor da transação inválido"))
                            .build()
            );
        }

        if (requisicaoTransacaoDTO.getTipoTransacao() == null) {
            return Uni.createFrom().item(
                    Response.status(Response.Status.BAD_REQUEST)
                            .entity(Map.of("error", "Tipo de transação não especificado"))
                            .build()
            );
        }

        // Processa transação
        return transactionService.save(requisicaoTransacaoDTO)
                .onItem().ifNotNull().transform(optionalTransacao -> {
                    return optionalTransacao.map(dto -> {
                        // Sucesso
                        return Response.status(Response.Status.CREATED)
                                .header("Location", buildLocation(uriInfo, dto.getUuid()))
                                .header("x-signature", dto.getSignature())
                                .entity(buildSuccessEntity(dto))
                                .build();
                    }).orElseGet(() -> {
                        // Processamento falhou
                        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                                .entity(Map.of("error", "Falha ao processar transação"))
                                .build();
                    });
                })
                .onFailure().recoverWithItem(this::handleError);
    }

    private String buildLocation(UriInfo uriInfo, UUID transactionId) {
        return uriInfo.getAbsolutePathBuilder()
                .path(transactionId.toString())
                .build()
                .toString();
    }

    private Map<String, Object> buildSuccessEntity(RequisicaoTransacaoDTO dto) {
        return Map.of(
                "id", dto.getUuid(),
                "status", "success",
                "processedAt", dto.getData(),
                "details", Map.of(
                        "amount", dto.getValor(),
                        "type", dto.getTipoTransacao().name()
                )
        );
    }

    private Response handleError(Throwable throwable) {
        LOG.error("Error processing transaction", throwable);

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(Map.of(
                        "error", "Internal server error",
                        "reference", UUID.randomUUID()
                ))
                .build();
    }

    @Override
    // @RolesAllowed("coffeeandit-transaction")
    @Blocking
    public Response delete(String uuid) {
        // LOG.infof("Deletando transação %s pelo usuário %s", uuid, securityIdentity.getPrincipal().getName());

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
    @NonBlocking
    @RolesAllowed("coffeeandit-transaction")
    public Response aprovar(String uuid, String signature) {
        LOG.info("Aprovando transação pelo uuid " + uuid);

        RequisicaoTransacaoDTO dto = transactionService.find(uuid)
                .orElseThrow(() -> new NotFoundException("Transação não encontrada: " + uuid));

        try {
            RequisicaoTransacaoDTO resultado = transactionService.aprovarTransacao(dto, signature)
                    .orElseThrow(() -> new BusinessException("Falha ao aprovar transação"));

            return Response.ok(resultado).build();

        } catch (NotAuthorizedException e) {
            return Response.status(401).entity("Assinatura inválida").build();
        }
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