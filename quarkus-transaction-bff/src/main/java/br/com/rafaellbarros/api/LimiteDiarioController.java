package br.com.rafaellbarros.api;


import br.com.rafaellbarros.domain.LimiteService;
import io.quarkus.security.Authenticated;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.ParameterIn;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameters;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.eclipse.microprofile.rest.client.inject.RestClient;


import java.util.Objects;

@Path("/v1/limite")
@SecurityRequirement(name = "jwt", scopes = {"coffeeandit"})
@Tag(name = "/v1/limite", description = "Grupo de API's para limites financeiros")
@Authenticated
public class LimiteDiarioController {

    @Inject
    @RestClient
    private LimiteService limiteService;

    @Inject
    JsonWebToken accessToken;

    @Operation(description = "API responsável por recuperar um limite de uma agencia e conta")
    @APIResponses(value = {@APIResponse(responseCode = "200", description = "Retorno OK com o limite encontrado."),
            @APIResponse(responseCode = "401", description = "Erro de autenticação dessa API"),
            @APIResponse(responseCode = "403", description = "Erro de autorização dessa API"),
            @APIResponse(responseCode = "404", description = "Recurso não encontrado")})
    @Parameters({@Parameter(name = "agencia", in = ParameterIn.PATH, description = "Código da Agência"),
            @Parameter(name = "conta", in = ParameterIn.PATH, description = "Código da Conta")}
    )
    @GET
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RolesAllowed({"coffeeandit-transaction"})
    public Response findByAgenciaConta(@Context UriInfo uriInfo) {
        var conta = accessToken.getClaim("conta");
        var agencia = accessToken.getClaim("agencia");
        if (Objects.isNull(conta) || Objects.isNull(agencia)) {
            throw new NotAuthorizedException("O token de autenticação não possui as claims de conta e/ou agencia");
        }
        var entity = limiteService.findByAgenciaConta(Long.valueOf(agencia.toString())
                , Long.valueOf(conta.toString()));
        if (Objects.isNull(entity)) {
            throw new NotFoundException("Não foi possível encontrar o limite por esse id");
        }
        return Response.ok(entity).build();
    }


}
