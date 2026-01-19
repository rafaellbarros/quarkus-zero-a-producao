package br.com.rafaellbarros.api.doc;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import static br.com.rafaellbarros.api.doc.DocApiConstants.*;

@Path(LIMITE_CONTROLLER_TAG)
@SecurityRequirement(name = "jwt", scopes = {"coffeeandit"})
@Tag(name = LIMITE_CONTROLLER_TAG, description = LIMITE_CONTROLLER_DESCRIPTION)
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface LimiteDiarioApi {

    @GET
    @Operation(description = FIND_LIMITE_DESCRIPTION)
    @APIResponses(value = {
        @APIResponse(responseCode = OK_CODE, description = OK_DESCRIPTION),
        @APIResponse(responseCode = UNAUTHORIZED_CODE, description = UNAUTHORIZED_DESCRIPTION),
        @APIResponse(responseCode = FORBIDDEN_CODE, description = FORBIDDEN_DESCRIPTION),
        @APIResponse(responseCode = NOT_FOUND_CODE, description = NOT_FOUND_DESCRIPTION)
    })
    Response findByAgenciaConta(@Context UriInfo uriInfo);
}