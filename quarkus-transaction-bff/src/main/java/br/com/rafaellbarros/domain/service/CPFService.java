package br.com.rafaellbarros.domain.service;

import br.com.rafaellbarros.api.dto.CpfDTO;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@Path("/httpFunction")
@RegisterRestClient
public interface CPFService {

    @GET
    CpfDTO validarCPF(@QueryParam("cpf") final String cpf);
}