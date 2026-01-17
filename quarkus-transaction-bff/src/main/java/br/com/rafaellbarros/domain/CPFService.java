package br.com.rafaellbarros.domain;

import br.com.rafaellbarros.api.dto.CpfDto;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@Path("/httpFunction")
@RegisterRestClient
public interface CPFService {

    @GET
    CpfDto validarCPF(@QueryParam("cpf") final String cpf);
}