package br.com.rafaellbarros.domain.service;

import br.com.rafaellbarros.domain.model.LimiteDiario;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@Path("/v1/limite")
@RegisterRestClient
public interface LimiteService {

    @GET
    @Path("/{agencia}/{conta}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public LimiteDiario findByAgenciaConta(@PathParam("agencia") final Long agencia,
                                           @PathParam("conta") final Long conta);
}