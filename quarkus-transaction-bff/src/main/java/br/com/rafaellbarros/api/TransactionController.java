package br.com.rafaellbarros.api;


import br.com.rafaellbarros.api.dto.Conta;
import br.com.rafaellbarros.api.dto.RequisicaoTransacaoDTO;
import br.com.rafaellbarros.domain.TransactionService;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.common.annotation.Blocking;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.ParameterIn;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameters;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;


import java.net.URI;
import java.util.Objects;
import java.util.Optional;

@Path("/v1/transactions")
@Authenticated
@RequestScoped
@SecurityRequirement(name = "jwt", scopes = {"coffeeandit"})
@Tag(
        name = "/v1/transactions",
        description = "Grupo de APIs para manipulação de transações financeiras"
)
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class TransactionController {

    private static final Logger LOG = Logger.getLogger(TransactionController.class);

    @Inject
    TransactionService transactionService;

    @Inject
    SecurityIdentity securityIdentity;

    @Claim("conta")
    String conta;

    @Claim("agencia")
    String agencia;

    @Operation(description = "API responsável por criar uma transação financeira")
    @APIResponses({
            @APIResponse(responseCode = "201", description = "Transação criada com sucesso"),
            @APIResponse(responseCode = "401", description = "Erro de autenticação"),
            @APIResponse(responseCode = "403", description = "Erro de autorização"),
            @APIResponse(responseCode = "404", description = "Recurso não encontrado")
    })
    @POST
    @Blocking
    @RolesAllowed("coffeeandit-transaction")
    public Response save(@Context UriInfo uriInfo,
                         RequisicaoTransacaoDTO requisicaoTransacaoDTO) {

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

    @DELETE
    @Path("/{uuid}")
    @Blocking
    @RolesAllowed("coffeeandit-transaction")
    public Response delete(@PathParam("uuid") String uuid) {
        if (transactionService.delete(uuid)) {
            return Response.noContent().build();
        }
        throw new NotFoundException("Não encontrei o recurso " + uuid);
    }

    @Operation(description = "API responsável por procurar uma transação financeira")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Transação encontrada"),
            @APIResponse(responseCode = "401", description = "Erro de autenticação"),
            @APIResponse(responseCode = "403", description = "Erro de autorização"),
            @APIResponse(responseCode = "404", description = "Recurso não encontrado")
    })
    @GET
    @Path("/{uuid}")
    @Parameters(@Parameter(
            name = "uuid",
            in = ParameterIn.PATH,
            description = "UUID v4 da transação"
    ))
    @Blocking
    public RequisicaoTransacaoDTO findById(@PathParam("uuid") String uuid) {

        LOG.info("Procurando transação pelo uuid " + uuid);

        return transactionService.find(uuid)
                .orElseThrow(() ->
                        new NotFoundException("Não foi possível encontrar a transação"));
    }

    @Operation(description = "API responsável por aprovar uma transação financeira")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Transação aprovada"),
            @APIResponse(responseCode = "401", description = "Erro de autenticação"),
            @APIResponse(responseCode = "403", description = "Erro de autorização"),
            @APIResponse(responseCode = "404", description = "Recurso não encontrado")
    })
    @PATCH
    @Path("/{uuid}/aprovar")
    @Parameters({
            @Parameter(
                    name = "uuid",
                    in = ParameterIn.PATH,
                    description = "UUID v4 da transação"
            ),
            @Parameter(
                    name = "x-signature",
                    in = ParameterIn.HEADER,
                    description = "Assinatura da transação"
            )
    })
    @Blocking
    @RolesAllowed("coffeeandit-transaction")
    public RequisicaoTransacaoDTO aprovar(@PathParam("uuid") String uuid,
                                          @HeaderParam("x-signature") String signature) {

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