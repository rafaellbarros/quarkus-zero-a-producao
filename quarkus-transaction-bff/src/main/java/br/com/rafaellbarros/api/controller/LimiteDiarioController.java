package br.com.rafaellbarros.api.controller;


import br.com.rafaellbarros.api.doc.LimiteDiarioApi;
import br.com.rafaellbarros.domain.service.LimiteService;
import io.quarkus.security.Authenticated;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import java.util.Objects;

@Authenticated
@RequestScoped
public class LimiteDiarioController implements LimiteDiarioApi {

    private static final Logger LOG = Logger.getLogger(LimiteDiarioController.class);

    @Inject
    @RestClient
    private LimiteService limiteService;

    @Inject
    JsonWebToken accessToken;

    @Override
    @RolesAllowed({"coffeeandit-transaction"})
    public Response findByAgenciaConta(@Context UriInfo uriInfo) {
        LOG.infof("Buscando limite diário para usuário: %s", accessToken.getName());

        var conta = accessToken.getClaim("conta");
        var agencia = accessToken.getClaim("agencia");

        if (Objects.isNull(conta) || Objects.isNull(agencia)) {
            throw new NotAuthorizedException("O token de autenticação não possui as claims de conta e/ou agencia");
        }

        var entity = limiteService.findByAgenciaConta(
                Long.valueOf(agencia.toString()),
                Long.valueOf(conta.toString())
        );

        if (Objects.isNull(entity)) {
            throw new NotFoundException("Não foi possível encontrar o limite por esse id");
        }

        return Response.ok(entity).build();
    }
}
