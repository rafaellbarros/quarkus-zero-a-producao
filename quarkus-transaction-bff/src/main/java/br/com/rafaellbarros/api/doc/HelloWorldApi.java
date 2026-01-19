package br.com.rafaellbarros.api.doc;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import static br.com.rafaellbarros.api.doc.DocApiConstants.*;

@Path(HELLO_CONTROLLER_PATH_TAG)
@Tag(name = HELLO_CONTROLLER_PATH_TAG, description = HELLO_CONTROLLER_DESCRIPTION)
public interface HelloWorldApi {

    @GET
    @Operation(description = HELLO_WORLD_DESCRIPTION)
    @APIResponses(value = {@APIResponse(description = OK_DESCRIPTION,
            responseCode = OK_CODE), @APIResponse(description = BAD_REQUEST_DESCRIPTION,
            responseCode = BAD_REQUEST_CODE), @APIResponse(description = INTERNAL_SERVER_ERROR_DESCRIPTION,
            responseCode = INTERNAL_SERVER_ERROR_CODE),
            @APIResponse(description = UNAUTHORIZED_DESCRIPTION,
                    responseCode = UNAUTHORIZED_CODE)
    })
    @Produces(MediaType.TEXT_HTML)
    @Consumes(MediaType.TEXT_HTML)
    String coffee();
}
